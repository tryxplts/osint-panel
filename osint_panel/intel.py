from __future__ import annotations

import html
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any


@dataclass(frozen=True)
class WebResult:
    title: str
    url: str
    snippet: str
    query: str


class _ResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.results: list[tuple[str, str]] = []
        self.current_href: str | None = None
        self.current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = attributes.get("class") or ""
        if tag == "a" and "result-link" in classes:
            self.current_href = attributes.get("href") or ""
            self.current_text = []

    def handle_data(self, data: str) -> None:
        if self.current_href is not None:
            self.current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self.current_href is not None:
            text = " ".join("".join(self.current_text).split())
            self.results.append((self.current_href, text))
            self.current_href = None
            self.current_text = []


def _fetch_text(url: str, timeout: int = 10) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 OSINT-Panel/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _clean_result_url(value: str) -> str:
    value = html.unescape(value)
    parsed = urllib.parse.urlparse(value)
    if parsed.path == "/l/" and parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        if "uddg" in params:
            return params["uddg"][0]
    return value


def _search_query(query: str, limit: int) -> list[WebResult]:
    url = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote_plus(query)}"
    try:
        document = _fetch_text(url)
    except (OSError, urllib.error.URLError, TimeoutError):
        return []
    parser = _ResultParser()
    parser.feed(document)
    results: list[WebResult] = []
    for href, title in parser.results:
        cleaned = _clean_result_url(href)
        if not cleaned.startswith(("http://", "https://")):
            continue
        results.append(WebResult(title=title or cleaned, url=cleaned, snippet="", query=query))
        if len(results) >= limit:
            break
    return results


def full_name_search(name: str, deep: bool = False, limit: int = 20) -> list[WebResult]:
    clean_name = " ".join(name.split())
    if not clean_name:
        return []
    queries = [f'"{clean_name}"']
    if deep:
        queries.extend((f'"{clean_name}" social profiles', f'"{clean_name}" username'))
    collected: dict[str, WebResult] = {}
    with ThreadPoolExecutor(max_workers=min(len(queries), 3)) as pool:
        futures = [pool.submit(_search_query, query, limit) for query in queries]
        for future in as_completed(futures):
            for result in future.result():
                collected.setdefault(result.url, result)
    return list(collected.values())[:limit]


def result_category(url: str) -> str:
    host = urllib.parse.urlparse(url).netloc.lower().removeprefix("www.")
    social_hosts = {"instagram.com", "facebook.com", "x.com", "twitter.com", "linkedin.com", "github.com", "tiktok.com", "youtube.com", "reddit.com", "t.me", "patreon.com"}
    if host in social_hosts:
        return "social"
    if host.endswith(".gov") or host.endswith(".edu"):
        return "institutional"
    if any(token in host for token in ("news", "press", "journal", "times")):
        return "news"
    return "web"


def summarize_web_results(results: list[WebResult]) -> list[str]:
    if not results:
        return ["No indexed web results were returned."]
    domains = sorted({urllib.parse.urlparse(result.url).netloc.lower().removeprefix("www.") for result in results})
    categories: dict[str, int] = {}
    for result in results:
        category = result_category(result.url)
        categories[category] = categories.get(category, 0) + 1
    summary = [f"Web results: {len(results)} unique links across {len(domains)} domains."]
    summary.append("Categories: " + ", ".join(f"{key} ({value})" for key, value in sorted(categories.items())) + ".")
    social = [result for result in results if result_category(result.url) == "social"]
    if social:
        summary.append("Social/profile candidates: " + ", ".join(result.url for result in social[:8]) + ".")
    summary.append("Next move: verify names, locations, and handles across independent sources before linking identities.")
    return summary


def _fetch_json(url: str, timeout: int = 8) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "OSINT-Panel/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("response was not a JSON object")
    return payload


def _dns_rows(domain: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    try:
        import dns.resolver
    except ImportError:
        return [("DNS records", "dnspython unavailable")]
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=3)
            values = [str(answer).strip('"') for answer in answers]
            rows.append((record_type, ", ".join(values[:12])))
        except Exception:
            continue
    return rows


def domain_intelligence(domain: str) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = [("Domain", domain)]
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
        rows.append(("DNS addresses", ", ".join(addresses)))
    except socket.gaierror:
        rows.append(("DNS addresses", "resolution failed"))
    rows.extend(_dns_rows(domain))
    try:
        rdap = _fetch_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
        registrar = "unknown"
        for entity in rdap.get("entities") or []:
            roles = entity.get("roles") or []
            if "registrar" in roles:
                vcard = entity.get("vcardArray") or []
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item and item[0] == "fn":
                            registrar = str(item[-1])
                break
        events = {str(event.get("eventAction")): str(event.get("eventDate")) for event in rdap.get("events") or [] if isinstance(event, dict)}
        nameservers = [str(item.get("ldhName") or item.get("unicodeName")) for item in rdap.get("nameservers") or [] if isinstance(item, dict)]
        rows.extend((
            ("Registrar", registrar),
            ("Domain status", ", ".join(str(item) for item in rdap.get("status") or [])),
            ("Created", events.get("registration", "unknown")),
            ("Updated", events.get("last changed", "unknown")),
            ("Expires", events.get("expiration", "unknown")),
            ("Nameservers", ", ".join(nameservers[:10]) or "unknown"),
        ))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, TimeoutError):
        rows.append(("RDAP", "unavailable"))
    return tuple(rows)
