from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlparse

from .intel import domain_intelligence


class OsintError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    site: str
    url: str
    status: str
    tags: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    related_usernames: tuple[str, ...] = ()


@dataclass(frozen=True)
class Inspection:
    target: str
    addresses: tuple[str, ...]
    reverse_names: tuple[str, ...]
    http_status: str
    server: str
    content_type: str
    tls_subject: str
    ip_details: tuple[tuple[str, str], ...] = ()
    domain_details: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class HistoryEntry:
    timestamp: str
    kind: str
    target: str
    result: str


def _history_path() -> Path:
    path = Path(__file__).resolve().parent.parent / "data" / "history.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _read_history() -> list[dict[str, str]]:
    path = _history_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def load_history() -> list[HistoryEntry]:
    entries: list[HistoryEntry] = []
    for item in _read_history():
        if isinstance(item, dict) and {"timestamp", "kind", "target", "result"} <= item.keys():
            entries.append(HistoryEntry(**{key: str(item[key]) for key in item if key in HistoryEntry.__annotations__}))
    return entries


def save_history(entry: HistoryEntry) -> None:
    data = _read_history()
    data.insert(0, asdict(entry))
    _history_path().write_text(json.dumps(data[:100], indent=2), encoding="utf-8")


def _json_payloads(text: str) -> list[Any]:
    payloads: list[Any] = []
    stripped = text.strip()
    if stripped:
        try:
            payloads.append(json.loads(stripped))
        except json.JSONDecodeError:
            for line in stripped.splitlines():
                line = line.strip()
                if not line.startswith(("{", "[")):
                    continue
                try:
                    payloads.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return payloads


def _flatten_profiles(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        if "url_user" in value and ("username" in value or "status" in value):
            return [value]
        flattened: list[dict[str, Any]] = []
        for child in value.values():
            flattened.extend(_flatten_profiles(child))
        return flattened
    if isinstance(value, list):
        flattened = []
        for child in value:
            flattened.extend(_flatten_profiles(child))
        return flattened
    return []


def parse_maigret_output(text: str) -> list[Finding]:
    findings: dict[str, Finding] = {}
    ignored_hosts = {"discord.com", "scholar.google.com"}
    for payload in _json_payloads(text):
        for profile in _flatten_profiles(payload):
            url = str(profile.get("url_user") or profile.get("url") or profile.get("url_main") or "").strip()
            parsed = urlparse(url)
            if not url or not url.startswith(("http://", "https://")) or parsed.netloc in ignored_hosts:
                continue
            site_value = profile.get("site")
            status_value = profile.get("status")
            tags: tuple[str, ...] = ()
            details: tuple[str, ...] = ()
            related_usernames: tuple[str, ...] = ()
            if isinstance(status_value, dict):
                site = str(status_value.get("site_name") or site_value or parsed.netloc)
                status = str(status_value.get("status") or status_value.get("state") or "found")
                raw_tags = status_value.get("tags") or []
                tags = tuple(str(tag) for tag in raw_tags if isinstance(tag, (str, int)))
                raw_ids = status_value.get("ids") or {}
                if isinstance(raw_ids, dict):
                    details = tuple(
                        f"{key}: {str(value)[:300]}"
                        for key, value in raw_ids.items()
                        if key not in {"image", "_extractor"} and value not in (None, "")
                    )
            else:
                site = str(site_value if isinstance(site_value, str) else profile.get("name") or parsed.netloc)
                status = str(status_value or ("claimed" if profile.get("exists") else "found"))
            raw_related = profile.get("ids_usernames") or {}
            if isinstance(raw_related, dict):
                related_usernames = tuple(str(key) for key in raw_related if key)
            findings[url] = Finding(site=site, url=url, status=status, tags=tags, details=details, related_usernames=related_usernames)

    if findings:
        return sorted(findings.values(), key=lambda item: (item.site.lower(), item.url))

    url_pattern = re.compile(r"(https?://[^\s<>\"]+)")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("[+]"):
            continue
        match = url_pattern.search(stripped)
        if not match:
            continue
        url = match.group(0).rstrip(".,)")
        parsed = urlparse(url)
        if parsed.netloc in {"discord.com", "scholar.google.com"}:
            continue
        if not parsed.path.strip("/") and not parsed.query:
            continue
        label = stripped[3:].split(":", 1)[0].strip()
        site = label or parsed.netloc or url
        findings[url] = Finding(site=site, url=url, status="found")
    return sorted(findings.values(), key=lambda item: (item.site.lower(), item.url))


def smart_insights(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["No public profile matches were returned."]
    claimed = sum(1 for finding in findings if finding.status.lower() in {"claimed", "found"})
    tag_counts = Counter(tag for finding in findings for tag in finding.tags)
    enriched = [finding.site for finding in findings if finding.details]
    related = sorted({username for finding in findings for username in finding.related_usernames if username})
    insights = [f"Public profile matches: {claimed} across {len(findings)} indexed site result(s)."]
    if tag_counts:
        top_tags = ", ".join(f"{tag} ({count})" for tag, count in tag_counts.most_common(8))
        insights.append(f"Observed categories: {top_tags}.")
    if enriched:
        insights.append(f"Evidence-rich profiles: {', '.join(enriched[:8])}.")
    else:
        insights.append("No extracted profile fields were available; treat the matches as username-only leads.")
    if related:
        insights.append(f"Related handle values to pivot on: {', '.join(related[:12])}.")
    pivot_fields: list[str] = []
    wanted = {"username", "twitch_username", "tiktok_username", "chess_user_id", "tiktok_id", "payerid", "uid"}
    for finding in findings:
        for detail in finding.details:
            key = detail.split(":", 1)[0].strip().lower()
            if key in wanted and detail not in pivot_fields:
                pivot_fields.append(detail)
    if pivot_fields:
        insights.append(f"High-signal identifiers: {'; '.join(pivot_fields[:8])}.")
    insights.append("Next move: cross-check names, IDs, and timestamps across the evidence-rich profiles before drawing identity conclusions.")
    return insights


def find_maigret() -> str:
    from shutil import which

    executable = which("maigret")
    if not executable:
        raise OsintError("Maigret is not installed. Run: python -m pip install -e .")
    return executable


def run_maigret(
    username: str,
    scope: str = "top",
    timeout: int = 120,
    use_tor: bool = False,
    on_line: Callable[[str], None] | None = None,
) -> list[Finding]:
    username = username.strip()
    if not username or any(char.isspace() for char in username):
        raise OsintError("Enter a single username without spaces.")
    executable = find_maigret()
    command = [executable, username, "--json", "simple", "--no-color", "--no-progressbar", "--timeout", str(timeout)]
    if scope == "all":
        command.append("--all-sites")
    else:
        command.extend(["--top-sites", "500"])
    if use_tor:
        command.extend(["--tor-proxy", "socks5://127.0.0.1:9050"])
    started_at = time.time()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise OsintError(f"Could not start Maigret: {error}") from error
    timed_out = threading.Event()

    def kill_process() -> None:
        timed_out.set()
        process.kill()

    timer = threading.Timer(timeout, kill_process)
    timer.daemon = True
    timer.start()
    lines: list[str] = []
    try:
        if process.stdout is not None:
            for line in process.stdout:
                text = line.rstrip()
                lines.append(text)
                if on_line is not None:
                    on_line(text)
        return_code = process.wait()
    finally:
        timer.cancel()
    output = "\n".join(lines).strip()
    report_path = Path("reports") / f"report_{username}_simple.json"
    report_items: list[Finding] = []
    if report_path.exists() and report_path.stat().st_mtime >= started_at - 2:
        try:
            report_items = parse_maigret_output(report_path.read_text(encoding="utf-8"))
        except OSError:
            report_items = []
    if timed_out.is_set():
        if report_items:
            return report_items
        partial = parse_maigret_output(output)
        if partial:
            return partial
        raise OsintError(f"Maigret timed out after {timeout} seconds.")
    if return_code != 0:
        detail = output.splitlines()[-1] if output else "unknown Maigret error"
        raise OsintError(f"Maigret failed: {detail}")
    return report_items or parse_maigret_output(output)


def _resolve_target(target: str) -> tuple[str, list[str]]:
    target = target.strip()
    if not target:
        raise OsintError("Enter a domain, hostname, or IP address.")
    try:
        address = ipaddress.ip_address(target)
        return target, [str(address)]
    except ValueError:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(target, None)})
        except socket.gaierror as error:
            raise OsintError(f"DNS resolution failed for {target}.") from error
        if not addresses:
            raise OsintError(f"No addresses found for {target}.")
        return target, addresses


def _reverse_names(address: str) -> list[str]:
    try:
        name, _, _ = socket.gethostbyaddr(address)
        return [name] if name else []
    except (OSError, socket.herror):
        return []


def _http_metadata(target: str) -> tuple[str, str, str, str]:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "OSINT-Panel/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return str(response.status), response.headers.get("Server", "unknown"), response.headers.get("Content-Type", "unknown"), ""
    except urllib.error.HTTPError as error:
        return str(error.code), error.headers.get("Server", "unknown"), error.headers.get("Content-Type", "unknown"), ""
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
        return "no HTTP(S) response", "unknown", "unknown", ""


def _fetch_json(url: str, timeout: int = 8) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "OSINT-Panel/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("response was not a JSON object")
    return payload


def ip_intelligence(address: str) -> tuple[tuple[str, str], ...]:
    parsed_address = ipaddress.ip_address(address)
    address_type = "private" if parsed_address.is_private else "public"
    if parsed_address.is_loopback:
        address_type = "loopback"
    elif parsed_address.is_multicast:
        address_type = "multicast"
    elif parsed_address.is_reserved:
        address_type = "reserved"
    rows: list[tuple[str, str]] = [("IP version", f"IPv{parsed_address.version}"), ("Address type", address_type)]
    if not parsed_address.is_global:
        rows.append(("Public intelligence", "skipped for a non-public address"))
        return tuple(rows)
    try:
        payload = _fetch_json(f"https://ipwho.is/{quote(address)}")
        if payload.get("success") is False:
            raise ValueError(str(payload.get("message") or "lookup failed"))
        connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
        timezone_value = payload.get("timezone") or location.get("timezone") or "unknown"
        timezone = timezone_value.get("id") if isinstance(timezone_value, dict) else timezone_value
        rows.extend((
            ("Country", str(payload.get("country") or location.get("country") or "unknown")),
            ("Region", str(payload.get("region") or location.get("region") or "unknown")),
            ("City", str(payload.get("city") or location.get("city") or "unknown")),
            ("Coordinates", f"{payload.get('latitude', '?')}, {payload.get('longitude', '?')}"),
            ("Timezone", str(timezone)),
            ("ASN", str(connection.get("asn") or "unknown")),
            ("Organization", str(connection.get("org") or "unknown")),
            ("ISP", str(connection.get("isp") or "unknown")),
            ("Domain", str(connection.get("domain") or "unknown")),
        ))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, TimeoutError):
        rows.append(("Public intelligence", "ipwho.is unavailable"))
    try:
        rdap = _fetch_json(f"https://rdap.org/ip/{quote(address)}")
        network_name = str(rdap.get("name") or rdap.get("handle") or "unknown")
        cidr = "unknown"
        cidrs = rdap.get("cidr0_cidrs")
        if isinstance(cidrs, list) and cidrs and isinstance(cidrs[0], dict):
            entry = cidrs[0]
            prefix = str(entry.get("v4prefix") or entry.get("cidr") or "")
            length = entry.get("length")
            cidr = f"{prefix}/{length}" if prefix and length else prefix or cidr
        rows.extend((("RDAP network", network_name), ("Network CIDR", cidr)))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, TimeoutError):
        rows.append(("RDAP network", "unavailable"))
    return tuple(rows)


def _tls_subject(target: str) -> str:
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
        parts = certificate.get("subject", ())
        values = [value for part in parts for key, value in part if key == "commonName"]
        return ", ".join(values) or "unknown"
    except (OSError, ssl.SSLError, ValueError):
        return "unavailable"


def inspect_target(target: str) -> Inspection:
    resolved, addresses = _resolve_target(target)
    reverse = sorted({name for address in addresses for name in _reverse_names(address)})
    http_status, server, content_type, _ = _http_metadata(resolved)
    try:
        is_ip = ipaddress.ip_address(resolved)
    except ValueError:
        is_ip = None
    return Inspection(
        target=resolved,
        addresses=tuple(addresses),
        reverse_names=tuple(reverse),
        http_status=http_status,
        server=server,
        content_type=content_type,
        tls_subject=_tls_subject(resolved),
        ip_details=ip_intelligence(addresses[0]),
        domain_details=() if is_ip else domain_intelligence(resolved),
    )


def history_entry(kind: str, target: str, result: str) -> HistoryEntry:
    return HistoryEntry(
        timestamp=datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        kind=kind,
        target=target,
        result=result,
    )
