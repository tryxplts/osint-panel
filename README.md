# osint-panel

Terminal OSINT dashboard. Username sweeps, full-name web search, and infrastructure
inspection (domain / IP) behind one plain CMD-style interface.

Built on top of [Maigret](https://github.com/soxoj/maigret) with its raw JSON
output parsed into structured evidence instead of being dumped as a wall of text.

```
OSINT PANEL 1.0
Maigret username search + target inspection

[1] Username search with Maigret
[2] Full-name web search
[3] Domain / IP inspection
[4] View history
[5] Exit
```

## Install

```bash
git clone https://github.com/tryxplts/osint-panel.git
cd osint-panel
pip install -e .
```

Python 3.10+. On Windows a `osint.cmd` shim gets dropped somewhere on your PATH so
you can just run `osint` from any shell.

## What it does

### Username search

Runs Maigret across its full site list with live progress and a configurable
timeout (30–3600s, defaults to 600s for the all-sites pass). Instead of Maigret's
raw output you get:

- one row per hit with site, URL, and status
- category counts derived from site tags
- extracted IDs, emails, and per-site detail lines
- related usernames found on the same profiles
- pivot suggestions for whatever the sweep turned up

The parser reads Maigret's structured `url_user` records, keeps extracted IDs and
tags, and drops the nested metadata block plus known false positives
(Discord/Scholar/sponsor/image avatars).

Export any sweep to CSV. History is kept locally so you can see what you ran
before.

### Full-name search

DuckDuckGo Lite, with a fast pass and a deep pass. Results are grouped by
category and the noise is filtered — anything with `news`, `press`, `journal`,
or `times` in the host gets treated as a news hit rather than a personal result.

### Domain / IP inspection

Feed it a domain and you get `A`, `AAAA`, `MX`, `NS`, `TXT`, and `CNAME` records
plus RDAP registration data (registrar, status, dates, nameservers).

Feed it an IP and you get ASN, ISP, organization, geolocation, and CIDR, resolved
through `ipwho.is` with a `rdap.org` fallback.

It also probes HTTP on 80/443, reads the TLS certificate subject, and attempts
reverse DNS. A closed port is reported as a result, not silently skipped.

### Correlation

Findings get cross-linked: usernames found during a sweep are offered as pivots,
and a target's addresses and reverse names feed back into the inspection view.

## Layout

```
osint_panel/
  app.py      CLI, Rich rendering, progress, export
  core.py     Maigret runner, JSON parser, target inspection, history
  intel.py    full-name search, DNS + RDAP domain intelligence
```

## Notes on accuracy

IP geolocation is approximate — it resolves to the ISP's registered location, not
the host's. Hostname, username, RAM, CPU, OS version, and MAC address cannot be
determined from a public IP and the tool does not pretend otherwise.

Scans make outbound requests: DNS, HTTP, RDAP, IP intelligence, web search, and
Maigret's site checks. History and reports stay local under `data/` and `reports/`,
which are gitignored.

## License

MIT
