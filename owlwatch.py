"""owlwatch - Detection-only web vulnerability scanner

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import threading
import time
from dataclasses import dataclass, asdict
from html import escape
from typing import Dict, List, Optional, Set, Tuple

try:  # optional deps
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - fallback
    BeautifulSoup = None  # type: ignore

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
except Exception:  # pragma: no cover - fallback
    Console = None  # type: ignore
    Table = None  # type: ignore
    box = None  # type: ignore

import requests
from requests.exceptions import RequestException
import urllib.parse
import urllib.robotparser

# ---------------------------------------------------------------------------
# Utilities & Constants
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0",
]

INTERNAL_IP_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
]

ASCII_OWL = r"""
   /\_/\
  ( o.o )  OwlWatch
   > ^ <
"""

DISCLAIMER = "Gunakan hanya untuk aset sendiri/berizin. Detection-only."

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single potential vulnerability finding."""

    vuln_type: str
    url: str
    param: str
    evidence_snippet: str
    confidence: float
    severity: str
    method: str
    payload_marker: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Scanner Core
# ---------------------------------------------------------------------------

class ScannerCore:
    """Core HTTP functionality with retries, delays and robots handling."""

    def __init__(
        self,
        *,
        timeout: int = 10,
        retries: int = 0,
        delay: float = 0.0,
        proxy: Optional[str] = None,
        random_agent: bool = False,
        respect_robots: bool = True,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.proxy = proxy
        self.random_agent = random_agent
        self.respect_robots = respect_robots
        self.session = requests.Session()
        self.lock = threading.Lock()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _user_agent(self) -> str:
        if self.random_agent:
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]

    def _allowed_by_robots(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parsed = urllib.parse.urlsplit(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        rp = urllib.robotparser.RobotFileParser()
        try:
            rp.set_url(urllib.parse.urljoin(base, "/robots.txt"))
            rp.read()
            return rp.can_fetch(self._user_agent(), url)
        except Exception:
            return True

    def request(
        self, method: str, url: str, *, params=None, data=None, headers=None
    ) -> Optional[requests.Response]:
        if not self._allowed_by_robots(url):
            return None
        time.sleep(self.delay)
        headers = headers or {}
        headers.setdefault("User-Agent", self._user_agent())
        for attempt in range(self.retries + 1):
            try:
                resp = self.session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=True,
                )
                return resp
            except RequestException:
                if attempt == self.retries:
                    return None
                time.sleep(0.5)
        return None


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class Crawler:
    """Simple crawler to gather URLs."""

    def __init__(
        self,
        core: ScannerCore,
        *,
        same_origin: bool = True,
        depth: int = 1,
        include: Optional[re.Pattern[str]] = None,
        exclude: Optional[re.Pattern[str]] = None,
    ) -> None:
        self.core = core
        self.same_origin = same_origin
        self.depth = depth
        self.include = include
        self.exclude = exclude
        self.visited: Set[str] = set()

    def crawl(self, start: str) -> List[str]:
        queue: List[Tuple[str, int]] = [(start, 0)]
        result: List[str] = []
        start_domain = urllib.parse.urlsplit(start).netloc
        while queue:
            url, d = queue.pop(0)
            if url in self.visited or d > self.depth:
                continue
            self.visited.add(url)
            result.append(url)
            if d == self.depth:
                continue
            resp = self.core.request("GET", url)
            if not resp or not resp.content:
                continue
            if BeautifulSoup is None:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = urllib.parse.urljoin(url, tag["href"])
                parsed = urllib.parse.urlsplit(href)
                if self.same_origin and parsed.netloc != start_domain:
                    continue
                if self.include and not self.include.search(href):
                    continue
                if self.exclude and self.exclude.search(href):
                    continue
                if href not in self.visited:
                    queue.append((href, d + 1))
        return result


# ---------------------------------------------------------------------------
# Vulnerability Checks
# ---------------------------------------------------------------------------

Marker = str


def generate_marker(rng: random.Random) -> Marker:
    return f"OWL{{{rng.randint(1000,9999)}}}"


def check_reflection(resp: requests.Response, marker: Marker) -> bool:
    try:
        return marker in resp.text
    except Exception:
        return False


def xss_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"x": [""]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = marker
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and check_reflection(resp, marker):
            findings.append(
                Finding(
                    vuln_type="XSS",
                    url=target,
                    param=key,
                    evidence_snippet=marker,
                    confidence=0.7,
                    severity="medium",
                    method="GET",
                    payload_marker=marker,
                )
            )
    return findings


SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-00933",
    "SQLite/JDBCException",
]


def sqli_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    payload = f"'\"{marker}"
    for key in params or {"id": ["1"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = payload
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and any(e.lower() in resp.text.lower() for e in SQL_ERRORS):
            findings.append(
                Finding(
                    vuln_type="SQLi",
                    url=target,
                    param=key,
                    evidence_snippet="SQL error",
                    confidence=0.6,
                    severity="high",
                    method="GET",
                    payload_marker=payload,
                )
            )
    return findings


def open_redirect_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = f"https://example.com/{generate_marker(rng)}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"next": ["/"], "url": ["/"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = marker
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and resp.is_redirect:
            loc = resp.headers.get("Location", "")
            if marker in loc:
                findings.append(
                    Finding(
                        vuln_type="Open Redirect",
                        url=target,
                        param=key,
                        evidence_snippet=loc,
                        confidence=0.7,
                        severity="medium",
                        method="GET",
                        payload_marker=marker,
                    )
                )
    return findings


def ssti_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    payload = f"{{{{{marker}}}}}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"name": ["test"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = payload
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and check_reflection(resp, payload):
            findings.append(
                Finding(
                    vuln_type="SSTI",
                    url=target,
                    param=key,
                    evidence_snippet=payload,
                    confidence=0.5,
                    severity="medium",
                    method="GET",
                    payload_marker=payload,
                )
            )
    return findings


def csti_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    payload = f"{{${marker}}}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"name": ["test"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = payload
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and check_reflection(resp, payload):
            findings.append(
                Finding(
                    vuln_type="CSTI",
                    url=target,
                    param=key,
                    evidence_snippet=payload,
                    confidence=0.5,
                    severity="medium",
                    method="GET",
                    payload_marker=payload,
                )
            )
    return findings


def lfi_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    payload = f"../../../../{marker}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"file": ["index.php"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = payload
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and marker in resp.text:
            findings.append(
                Finding(
                    vuln_type="LFI",
                    url=target,
                    param=key,
                    evidence_snippet=marker,
                    confidence=0.4,
                    severity="high",
                    method="GET",
                    payload_marker=payload,
                )
            )
    return findings


def rfi_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = f"https://example.com/{generate_marker(rng)}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"file": ["http://example.com"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = marker
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and marker in resp.text:
            findings.append(
                Finding(
                    vuln_type="RFI",
                    url=target,
                    param=key,
                    evidence_snippet=marker,
                    confidence=0.4,
                    severity="high",
                    method="GET",
                    payload_marker=marker,
                )
            )
    return findings


def cmdi_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    payload = f";{marker}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"cmd": ["ls"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = payload
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and marker in resp.text:
            findings.append(
                Finding(
                    vuln_type="CMDi",
                    url=target,
                    param=key,
                    evidence_snippet=marker,
                    confidence=0.5,
                    severity="high",
                    method="GET",
                    payload_marker=payload,
                )
            )
    return findings


def crlf_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    payload = f"%0d%0aX-Owl:{marker}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"header": ["test"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = payload
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        resp = core.request("GET", target)
        if resp and f"X-Owl: {marker}" in "\n".join(
            f"{k}: {v}" for k, v in resp.headers.items()
        ):
            findings.append(
                Finding(
                    vuln_type="CRLF",
                    url=target,
                    param=key,
                    evidence_snippet=f"header X-Owl: {marker}",
                    confidence=0.6,
                    severity="medium",
                    method="GET",
                    payload_marker=payload,
                )
            )
    return findings


def ssrf_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = f"http://example.com/{generate_marker(rng)}"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    for key in params or {"url": ["http://example.com"]}:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[key] = marker
        target = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        # check for internal address
        parsed_marker = urllib.parse.urlsplit(marker)
        if any(p.match(parsed_marker.hostname or "") for p in INTERNAL_IP_PATTERNS):
            continue
        resp = core.request("GET", target)
        if resp and marker in resp.text:
            findings.append(
                Finding(
                    vuln_type="SSRF",
                    url=target,
                    param=key,
                    evidence_snippet=marker,
                    confidence=0.3,
                    severity="high",
                    method="GET",
                    payload_marker=marker,
                )
            )
    return findings


def xxe_check(core: ScannerCore, url: str, rng: random.Random) -> List[Finding]:
    marker = generate_marker(rng)
    payload = f"<!DOCTYPE foo [<!ENTITY x SYSTEM 'http://example.com/{marker}'>]><foo>&x;</foo>"
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parsed.query)
    findings: List[Finding] = []
    headers = {"Content-Type": "application/xml"}
    if params:
        resp = core.request("POST", url, data=payload, headers=headers)
        if resp and marker in resp.text:
            findings.append(
                Finding(
                    vuln_type="XXE",
                    url=url,
                    param="",
                    evidence_snippet=marker,
                    confidence=0.4,
                    severity="high",
                    method="POST",
                    payload_marker=marker,
                )
            )
    return findings

# mapping of vulnerabilities to check functions
CHECKS = {
    "XSS": xss_check,
    "SQLi": sqli_check,
    "Open Redirect": open_redirect_check,
    "SSTI": ssti_check,
    "CSTI": csti_check,
    "LFI": lfi_check,
    "RFI": rfi_check,
    "CMDi": cmdi_check,
    "CRLF": crlf_check,
    "SSRF": ssrf_check,
    "XXE": xxe_check,
}

THREAT_MAP = {
    "low": ["XSS", "SQLi", "Open Redirect"],
    "medium": ["XSS", "SQLi", "Open Redirect", "SSTI", "CSTI", "LFI"],
    "high": list(CHECKS.keys()),
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class Reporter:
    """Handles console and HTML reporting."""

    def __init__(self, *, no_color: bool = False) -> None:
        self.no_color = no_color
        if Console and not no_color:
            self.console = Console()
        else:
            self.console = None

    def banner(self) -> None:
        if self.console:
            self.console.print(f"[bold cyan]{ASCII_OWL}[/bold cyan]")
            self.console.print(f"[bold yellow]{DISCLAIMER}[/bold yellow]")
        else:
            print(ASCII_OWL)
            print(DISCLAIMER)

    def print_findings(self, findings: List[Finding]) -> None:
        if not findings:
            if self.console:
                self.console.print("[green]No findings" )
            else:
                print("No findings")
            return
        if self.console and Table:
            table = Table(title="Findings", box=box.SIMPLE)
            table.add_column("Vuln")
            table.add_column("URL")
            table.add_column("Param")
            table.add_column("Confidence")
            table.add_column("Severity")
            for f in findings:
                table.add_row(
                    f.vuln_type,
                    f.url,
                    f.param,
                    f"{f.confidence:.2f}",
                    f.severity,
                )
            self.console.print(table)
        else:
            for f in findings:
                print(f"{f.vuln_type} {f.url} {f.param} {f.confidence} {f.severity}")

    def save_json(self, findings: List[Finding], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2)

    def save_html(self, findings: List[Finding], path: str) -> None:
        rows = "".join(
            f"<tr><td>{escape(f.vuln_type)}</td><td>{escape(f.url)}</td><td>{escape(f.param)}</td>"
            f"<td>{f.confidence:.2f}</td><td>{escape(f.severity)}</td>"
            f"<td>{escape(f.evidence_snippet)}</td></tr>" for f in findings
        )
        html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'/>
<title>OwlWatch Report</title>
<style>
body {{font-family: Arial, sans-serif; margin: 2em;}}
header {{display:flex; align-items:center;}}
pre {{margin-right:1em; animation:blink 2s infinite;}}
@keyframes blink {{0%{{opacity:1;}}50%{{opacity:0.2;}}100%{{opacity:1;}}}}
.badge {{padding:2px 4px; border-radius:4px; color:#fff;}}
.badge.low {{background:#2c7;}}
.badge.medium {{background:#e90;}}
.badge.high {{background:#e33;}}
</style>
</head>
<body>
<header><pre>{ASCII_OWL}</pre><h1>OwlWatch Report</h1></header>
<p>{DISCLAIMER}</p>
<table border='1' cellpadding='5' cellspacing='0'>
<tr><th>Vulnerability</th><th>URL</th><th>Param</th><th>Confidence</th><th>Severity</th><th>Evidence</th></tr>
{rows}
</table>
</body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def run_scanner(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    core = ScannerCore(
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        proxy=args.proxy,
        random_agent=args.random_agent,
        respect_robots=not args.ignore_robots,
    )
    reporter = Reporter(no_color=args.no_color)
    reporter.banner()
    targets: List[str] = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as fh:
                targets.extend(line.strip() for line in fh if line.strip())
        except FileNotFoundError:
            print(f"List file {args.list} not found", file=sys.stderr)
            return

    crawl_urls: List[str] = []
    if args.crawl:
        for t in targets:
            crawler = Crawler(
                core,
                same_origin=args.same_origin,
                depth=args.depth,
                include=re.compile(args.include) if args.include else None,
                exclude=re.compile(args.exclude) if args.exclude else None,
            )
            crawl_urls.extend(crawler.crawl(t))
    else:
        crawl_urls = targets

    checks = [CHECKS[c] for c in THREAT_MAP[args.threat]]
    findings: List[Finding] = []
    lock = threading.Lock()

    def worker(u: str) -> None:
        for check in checks:
            try:
                res = check(core, u, rng)
                if res:
                    with lock:
                        findings.extend(res)
            except Exception:
                continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as exc:
        futures = [exc.submit(worker, u) for u in crawl_urls]
        for _ in concurrent.futures.as_completed(futures):
            pass

    reporter.print_findings(findings)
    if args.json:
        reporter.save_json(findings, args.json)
        print(f"Saved JSON report to {args.json}")
    if args.html_report:
        reporter.save_html(findings, args.html_report)
        print(f"Saved HTML report to {args.html_report}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OwlWatch web vulnerability scanner")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-L", "--list", help="File with list of URLs")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth")
    parser.add_argument("--same-origin", action="store_true", default=True)
    parser.add_argument("--include", help="Regex of URLs to include")
    parser.add_argument("--exclude", help="Regex of URLs to exclude")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--random-agent", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--json", help="Output findings to JSON file")
    parser.add_argument("--html-report", help="Save HTML report")
    parser.add_argument("--no-color", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--respect-robots", action="store_true", default=True)
    group.add_argument("--ignore-robots", action="store_true")
    parser.add_argument("--allow-post", action="store_true")
    parser.add_argument(
        "--threat",
        choices=["low", "medium", "high"],
        default="low",
    )
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed")

    parser.epilog = (
        "Example: python3 owlwatch.py -u \"https://target.tld\" --crawl --depth 2 "
        "--random-agent --delay 0.5 --threads 8 --html-report report.html "
        "--threat medium -vv"
    )

    args = parser.parse_args()
    run_scanner(args)


if __name__ == "__main__":
    main()


# Unit test stub (for developers)
# def test_generate_marker():
#     rng = random.Random(1)
#     assert generate_marker(rng).startswith("OWL")
