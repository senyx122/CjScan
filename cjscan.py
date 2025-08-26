#!/usr/bin/env python3
"""
Smart Clickjacking Scanner (sensitive-aware) - improved JS endpoint extraction

Run ONLY against targets you own or have explicit permission to test.
Provides prioritized crawling, JS & JSON extraction, optional JS rendering (Playwright),
and flags vulnerabilities on sensitive pages as High-confidence (more likely accepted).

This version improves the JS endpoint extraction with multiple regex heuristics:
- collapses simple string concatenations like '/api/' + 'v1'
- extracts template-literal URLs (`...`)
- extracts fetch/axios endpoints
- finds REST-like paths (/api/, /v1/, /ajax/, /rest/) and relative 'api/...' patterns
- falls back to absolute http(s) matches
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
import time
import argparse
import csv
import logging
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import heapq
import json
from collections import defaultdict

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CJScanner")

# Small default wordlist for discovery
DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "wp-admin", "wp-login.php", "api", "user", "users",
    "account", "signup", "register", "search", "sitemap.xml", "robots.txt", "uploads",
    "download", "downloads", "assets", "static", "checkout", "cart", "order", "orders",
    "profile", "settings", "billing", "payment", "payments", "wallet", "transaction",
    "adminpanel", "manage", "panel", "console"
]

URL_REGEX = re.compile(r'(https?://[^\s"\'<>]+|\/[A-Za-z0-9_\-\/\.\?=&%]+)')
STRIP_PARAMS = {'utm_source','utm_medium','utm_campaign','utm_term','utm_content','sessionid','phpsessid','sid','fbclid'}

# --- Utility / Normalization ---
def normalize_url_raw(u):
    try:
        p = urlparse(u)
        # If scheme missing, assume https
        scheme = p.scheme or 'https'
        netloc = p.netloc or p.path  # if input was "/path"
        path = p.path if p.netloc else ''
        normalized = urlunparse((scheme, netloc, path, p.params, p.query, ''))
        return normalized
    except Exception:
        return u

def normalize_and_strip(u):
    try:
        p = urlparse(u)
        # default scheme
        scheme = p.scheme or 'https'
        netloc = p.netloc
        query_items = parse_qsl(p.query, keep_blank_values=True)
        qs = [(k,v) for (k,v) in query_items if k.lower() not in STRIP_PARAMS]
        # sort for stable canonical form
        qs_sorted = sorted(qs, key=lambda x: x[0])
        new_q = urlencode(qs_sorted)
        # remove fragment
        p = p._replace(scheme=scheme, netloc=netloc, query=new_q, fragment='')
        # remove default ports
        if p.netloc.endswith(':80') and p.scheme == 'http':
            p = p._replace(netloc=p.netloc.rsplit(':',1)[0])
        if p.netloc.endswith(':443') and p.scheme == 'https':
            p = p._replace(netloc=p.netloc.rsplit(':',1)[0])
        return urlunparse(p)
    except Exception:
        return u

# --- Priority queue for URLs ---
class URLPriorityQueue:
    def __init__(self):
        self.heap = []
        self.seen = set()
        self.counter = 0
    def push(self, url, priority=0):
        if url in self.seen:
            return
        heapq.heappush(self.heap, (-priority, self.counter, url))
        self.counter += 1
        self.seen.add(url)
    def pop(self):
        if not self.heap:
            return None
        return heapq.heappop(self.heap)[2]
    def empty(self):
        return len(self.heap) == 0
    def __len__(self):
        return len(self.heap)

# --- Sensitive detection & scoring ---
SENSITIVE_KEYWORDS = [
    r'login', r'wp\-admin', r'admin', r'dashboard', r'checkout', r'cart', r'payment',
    r'order', r'orders', r'account', r'profile', r'billing', r'wallet', r'transaction',
    r'withdraw', r'deposit', r'api', r'key', r'token', r'oauth'
]
SENSITIVE_RE = re.compile('|'.join(SENSITIVE_KEYWORDS), re.I)

def is_sensitive(url):
    parsed = urlparse(url)
    path = parsed.path or ''
    q = parsed.query or ''
    m = SENSITIVE_RE.search(path + "?" + q)
    if m:
        # return True and the matched keyword
        return True, m.group(0)
    return False, None

def score_url(url, from_sitemap=False, freq=0):
    score = 0
    if from_sitemap:
        score += 50
    sens, _ = is_sensitive(url)
    if sens:
        score += 40
    # short paths slightly preferred
    if url.count('/') <= 3:
        score += 5
    # frequency seen adds score
    score += min(freq, 20)
    return score

# --- Improved JS endpoint extraction heuristics ---
# We'll use multiple strategies: collapse simple concatenations, extract template literals,
# extract fetch/axios patterns, find REST-like paths (/api/, /v1/, /ajax/, /rest/), absolute http(s).
def extract_links_from_js_text(js_text, base_url):
    found = set()
    try:
        if not js_text:
            return []
        # 1) Collapse simple concatenations like '/api/' + 'v1' -> '/api/v1'
        collapsed = re.sub(r"(['\"])\s*\+\s*(['\"])", "", js_text)

        # 2) Extract template literals: `...`
        for m in re.findall(r'`([^`]+)`', collapsed):
            candidate = m.strip()
            if candidate.startswith('/') or candidate.startswith('http'):
                if candidate.startswith('/'):
                    candidate = urljoin(base_url, candidate)
                found.add(normalize_and_strip(candidate))

        # 3) fetch(...) calls
        for m in re.findall(r'fetch\(\s*[\'"]([^\'"]+)[\'"]', collapsed, re.I):
            cand = m.strip()
            if cand.startswith('/'):
                cand = urljoin(base_url, cand)
            found.add(normalize_and_strip(cand))

        # 4) axios.<method>('...') calls
        for m in re.findall(r'axios\.(?:get|post|put|delete|patch)\(\s*[\'"]([^\'"]+)[\'"]', collapsed, re.I):
            cand = m.strip()
            if cand.startswith('/'):
                cand = urljoin(base_url, cand)
            found.add(normalize_and_strip(cand))

        # 5) XMLHttpRequest open("GET", "...") patterns
        for m in re.findall(r'\.open\(\s*[\'"](?:GET|POST|PUT|DELETE|PATCH)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]', collapsed, re.I):
            cand = m.strip()
            if cand.startswith('/'):
                cand = urljoin(base_url, cand)
            found.add(normalize_and_strip(cand))

        # 6) Absolute http(s) matches
        for m in re.findall(r'(https?://[^\s\'"<>`,;]+)', collapsed):
            found.add(normalize_and_strip(m.strip().rstrip(') ,;')))

        # 7) REST-like absolute/relative paths: /api/... , /v1/... , /ajax/... , /rest/...
        for m in re.findall(r'(/(?:api|v\d+|ajax|rest|api2|backend)[^\s\'"<>]*)', collapsed, re.I):
            cand = m.split()[0].strip().strip('",\'();')
            cand = urljoin(base_url, cand)
            found.add(normalize_and_strip(cand))

        # 8) Relative patterns starting with api/ (no leading slash)
        for m in re.findall(r'(?<!/)(api\/[A-Za-z0-9_\-\/\.\?=&%]+)', collapsed, re.I):
            cand = urljoin(base_url, '/' + m.strip().strip('",\'();'))
            found.add(normalize_and_strip(cand))

        # 9) Generic quoted paths like '/path/to/endpoint' or "path/to/endpoint.php"
        for m in re.findall(r'["\'](\/[A-Za-z0-9_\-\/\.\?\=&%]+)["\']', collapsed):
            cand = m.strip()
            cand = urljoin(base_url, cand)
            found.add(normalize_and_strip(cand))

        # 10) As a fallback, scan for common endpoint-like tokens (api, upload, download, auth)
        # and capture a short window around them
        for token in ['api', 'upload', 'download', 'auth', 'token', 'login', 'checkout', 'order', 'payment']:
            for m in re.finditer(r'([\'"`]([^\'"`]{0,200}' + re.escape(token) + r'[^\'"`]{0,200})[\'"`])', collapsed, re.I):
                candidate = m.group(2)
                # attempt to extract first URL-like substring inside candidate
                u_match = re.search(r'(https?://[^\s\'"<>]+|\/[A-Za-z0-9_\-\/\.\?\=&%]+|api\/[A-Za-z0-9_\-\/\.\?=&%]+)', candidate, re.I)
                if u_match:
                    cand = u_match.group(0)
                    if cand.startswith('/'):
                        cand = urljoin(base_url, cand)
                    elif not cand.startswith('http'):
                        cand = urljoin(base_url, '/' + cand)
                    found.add(normalize_and_strip(cand))

    except Exception as e:
        logger.debug(f"extract_links_from_js_text error: {e}")
    return list(found)


def extract_links_from_json_text(txt, base_url):
    links = set()
    try:
        j = json.loads(txt)
    except Exception:
        return []
    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for it in o:
                walk(it)
        elif isinstance(o, str):
            if o.startswith('http') or o.startswith('/'):
                try:
                    cand = urljoin(base_url, o)
                    links.add(normalize_and_strip(cand))
                except:
                    pass
    walk(j)
    return list(links)

# Optional Playwright rendering
def try_render_with_playwright(url, timeout=10000):
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        logger.debug("Playwright not available or not installed.")
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent="Mozilla/5.0 (compatible; CJ-Scanner/1.0)")
            page.goto(url, timeout=timeout)
            # wait a bit for XHR/DOM changes
            page.wait_for_timeout(700)
            content = page.content()
            browser.close()
            return content
    except Exception as e:
        logger.debug(f"Playwright render failed for {url}: {e}")
        return None

# --- Main scanner class (unchanged except for the JS extractor usage) ---
class SmartClickjackingScanner:
    def __init__(self, base_url, max_threads=10, delay=0.2, max_urls=2000,
                 obey_robots=True, discover=False, wordlist=None, render=False):
        self.base_url = base_url.rstrip('/')
        self.parsed_base = urlparse(self.base_url)
        self.domain = self.parsed_base.netloc
        self.scheme = self.parsed_base.scheme or 'https'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; CJ-Scanner/1.0)'})
        self.max_threads = max_threads
        self.delay = delay
        self.max_urls = max_urls
        self.obey_robots = obey_robots
        self.discover = discover
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.render = render

        self.pq = URLPriorityQueue()
        self.pq.push(self.base_url, priority=100)
        self.visited = set()
        self.results = []
        self.freq = defaultdict(int)  # frequency counts for scoring

        # sitemap seeds
        self.sitemaps = set()

    def safe_get(self, url, method='get', **kwargs):
        try:
            if method == 'head':
                return self.session.head(url, timeout=8, allow_redirects=True, **kwargs)
            return self.session.get(url, timeout=10, allow_redirects=True, **kwargs)
        except Exception as e:
            logger.debug(f"safe_get error {url}: {e}")
            return None

    def fetch_robots_and_sitemaps(self):
        robots_url = urljoin(f"{self.scheme}://{self.domain}", "/robots.txt")
        logger.info(f"Fetching robots.txt: {robots_url}")
        r = self.safe_get(robots_url)
        if not r or r.status_code != 200:
            logger.debug("No robots or unreadable.")
            return []
        sitemaps = re.findall(r'(?i)Sitemap:\s*(\S+)', r.text)
        for s in sitemaps:
            if s:
                self.sitemaps.add(s.strip())
        return list(self.sitemaps)

    def parse_sitemap(self, sitemap_url):
        r = self.safe_get(sitemap_url)
        if not r or r.status_code != 200:
            logger.debug(f"Failed to fetch sitemap {sitemap_url}")
            return []
        urls = []
        try:
            root = ET.fromstring(r.content)
            for elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                if elem is not None and elem.text:
                    urls.append(elem.text.strip())
            if not urls:
                for elem in root.findall('.//loc'):
                    if elem is not None and elem.text:
                        urls.append(elem.text.strip())
        except ET.ParseError:
            # fallback regex
            urls = re.findall(r'<loc>([^<]+)</loc>', r.text)
        logger.info(f"Parsed {len(urls)} urls from sitemap {sitemap_url}")
        return urls

    def discover_common_paths(self):
        logger.info("Starting limited discovery of common paths (wordlist)...")
        candidates = []
        for w in self.wordlist:
            candidates.extend([
                urljoin(self.base_url, f"/{w}"),
                urljoin(self.base_url, f"/{w}/"),
                urljoin(self.base_url, f"/{w}.php"),
                urljoin(self.base_url, f"/{w}.html"),
            ])
        found = []
        with ThreadPoolExecutor(max_workers=min(self.max_threads, 20)) as ex:
            futures = {ex.submit(self.safe_get, u): u for u in candidates}
            for fut in as_completed(futures):
                url = futures[fut]
                r = fut.result()
                if r is not None and r.status_code in (200,301,302,303):
                    normalized = normalize_and_strip(r.url)
                    if self.domain in urlparse(normalized).netloc:
                        found.append(normalized)
                        logger.info(f"Discovered via wordlist: {normalized} [{r.status_code}]")
        for f in found:
            if f not in self.pq.seen:
                s = score_url(f, from_sitemap=False, freq=1)
                self.pq.push(f, priority=s)

    def extract_links_from_html(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        attrs = [
            ('a','href'), ('area','href'), ('link','href'),
            ('iframe','src'), ('frame','src'),
            ('script','src'), ('img','src'), ('source','src'),
            ('form','action')
        ]
        for tag, attr in attrs:
            for t in soup.find_all(tag):
                if t.has_attr(attr):
                    raw = t[attr]
                    if raw and not raw.lower().startswith(('mailto:','tel:','javascript:')):
                        full = urljoin(base_url, raw)
                        links.add(full)
        # meta refresh
        for m in soup.find_all('meta', attrs={'http-equiv': re.compile('refresh', re.I)}):
            content = m.get('content', '')
            m_url_match = re.search(r'url=(.+)', content, re.I)
            if m_url_match:
                candidate = m_url_match.group(1).strip().strip("'\"")
                links.add(urljoin(base_url, candidate))
        # regex-find in inline scripts/text
        for match in URL_REGEX.findall(html):
            candidate = match
            if candidate.startswith('/'):
                candidate = urljoin(base_url, candidate)
            links.add(candidate)
        # normalize & filter
        cleaned = set()
        for l in links:
            try:
                nl = normalize_and_strip(l)
                parsed = urlparse(nl)
                if parsed.netloc and (self.domain in parsed.netloc):
                    if not re.search(r'\.(css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|json|xml|pdf)(?:$|\?)', nl, re.I):
                        cleaned.add(nl)
            except Exception:
                continue
        return list(cleaned)

    def perform_clickjacking_check(self, url, response):
        if not response:
            return "Error: no response"
        headers = response.headers
        x_frame = headers.get('X-Frame-Options','').upper()
        csp = headers.get('Content-Security-Policy','').upper()
        permissions_policy = headers.get('Permissions-Policy','').upper()
        content_type = headers.get('Content-Type','').lower()

        csp_protected = False
        frame_ancestors_match = re.search(r'frame-ancestors\s+([^;]+)', csp, re.IGNORECASE)
        if frame_ancestors_match:
            fa = frame_ancestors_match.group(1).upper()
            if 'NONE' in fa or 'SELF' in fa or self.domain.upper() in fa:
                csp_protected = True

        js_protection = False
        if response.text and 'text/html' in content_type:
            body = response.text.lower()
            for pattern in [r"top\s*!==?\s*self", r"self\s*===\s*top", r"window\.top", r"parent\.frames"]:
                if re.search(pattern, body):
                    js_protection = True
                    break

        protection_methods = []
        if 'SAMEORIGIN' in x_frame or 'DENY' in x_frame:
            protection_methods.append('X-Frame-Options')
        if csp_protected:
            protection_methods.append('CSP(frame-ancestors)')
        if 'AUTOPLAY' in permissions_policy or 'FULLSCREEN' in permissions_policy:
            protection_methods.append('Permissions-Policy')
        if js_protection:
            protection_methods.append('JS')

        if protection_methods:
            return f"Protected ({', '.join(protection_methods)})"

        if not content_type.startswith('text/html'):
            return "Not HTML"

        # generate PoC file
        safe_part = re.sub(r'[^a-zA-Z0-9\-_.]', '_', urlparse(url).path.strip('/') or 'root')
        filename = f"cj_poc_{self.domain}_{safe_part[:60]}.html"
        poc_html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>PoC Clickjacking - {url}</title></head><body>
<h3>Clickjacking PoC for {url}</h3>
<iframe src="{url}" width="1000" height="700" style="border:4px solid red"></iframe>
<p>If you see the content inside the iframe, the page might be vulnerable to clickjacking.</p>
</body></html>"""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write(poc_html)
            return f"Potentially Vulnerable (PoC saved: {filename})"
        except Exception:
            return "Potentially Vulnerable (PoC not saved)"

    def process_url(self, url):
        """Check + extract links for a single URL. Returns tuple."""
        r = self.safe_get(url)
        status = self.perform_clickjacking_check(url, r) if r else "Error: no response"
        links = []
        # attempt extraction if html or json
        if r and r.status_code == 200:
            ctype = r.headers.get('Content-Type','').lower()
            if 'application/json' in ctype:
                links = extract_links_from_json_text(r.text, url)
            elif 'text/html' in ctype:
                try:
                    links = self.extract_links_from_html(r.text, url)
                except Exception as e:
                    logger.debug(f"HTML extract error for {url}: {e}")
                # extract from external JS
                try:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    for s in soup.find_all('script', src=True):
                        s_url = urljoin(url, s['src'])
                        jr = self.safe_get(s_url)
                        if jr and jr.status_code == 200 and jr.text:
                            jlinks = extract_links_from_js_text(jr.text, url)
                            links.extend(jlinks)
                    # inline scripts also
                    for s in soup.find_all('script', src=False):
                        tx = s.string or ''
                        if tx:
                            links.extend(extract_links_from_js_text(tx, url))
                except Exception as e:
                    logger.debug(f"JS extract error for {url}: {e}")
                # decide to render if few links and render enabled
                if self.render and len(links) < 6:
                    rendered = try_render_with_playwright(url)
                    if rendered:
                        try:
                            extra = self.extract_links_from_html(rendered, url)
                            links.extend(extra)
                        except:
                            pass
        # dedupe & normalize results
        norm = []
        for l in set(links):
            try:
                nl = normalize_and_strip(l)
                if self.domain in urlparse(nl).netloc:
                    norm.append(nl)
            except:
                continue
        return (url, status, norm)

    def crawl(self):
        # seed from robots/sitemaps
        if self.obey_robots:
            s = self.fetch_robots_and_sitemaps()
            for sitemap in s:
                for u in self.parse_sitemap(sitemap):
                    nn = normalize_and_strip(u)
                    if self.domain in urlparse(nn).netloc:
                        self.freq[nn] += 1
                        self.pq.push(nn, priority=score_url(nn, from_sitemap=True, freq=self.freq[nn]))

        if self.discover:
            self.discover_common_paths()

        logger.info("Starting crawl...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while len(self.pq) and len(self.results) < self.max_urls:
                # pop a batch
                batch = []
                while len(batch) < self.max_threads and not self.pq.empty() and len(self.results) < self.max_urls:
                    u = self.pq.pop()
                    if not u or u in self.visited:
                        continue
                    self.visited.add(u)
                    batch.append(u)
                if not batch:
                    break
                futures = {executor.submit(self.process_url, u): u for u in batch}
                for fut in as_completed(futures):
                    u = futures[fut]
                    try:
                        url, status, links = fut.result(timeout=30)
                    except Exception as e:
                        url = u
                        status = f"Error processing: {e}"
                        links = []
                    # sensitivity check
                    sensitive_flag, matched = is_sensitive(url)
                    severity = "Low"
                    if "Potentially Vulnerable" in status or "Vulnerable" in status:
                        severity = "Medium"
                    if ("Potentially Vulnerable" in status or "Vulnerable" in status) and sensitive_flag:
                        severity = "High"
                    poc = None
                    m = re.search(r'PoC saved:\s*([^)\s]+)', status)
                    if m:
                        poc = m.group(1)
                    self.results.append({
                        "url": url,
                        "status": status,
                        "sensitive": sensitive_flag,
                        "sensitive_match": matched,
                        "severity": severity,
                        "poc": poc
                    })
                    logger.info(f"{url:<80} {status} | Sensitive:{sensitive_flag} | Severity:{severity}")
                    # enqueue discovered links with scoring
                    for l in links:
                        self.freq[l] += 1
                        s = score_url(l, from_sitemap=False, freq=self.freq[l])
                        if l not in self.visited:
                            self.pq.push(l, priority=s)
                # polite delay
                time.sleep(self.delay)

    def generate_report(self, filename="clickjacking_report.csv"):
        with open(filename, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow(['URL','Status','Sensitive','Sensitive_Match','Severity','PoC'])
            for r in self.results:
                writer.writerow([r['url'], r['status'], r['sensitive'], r['sensitive_match'] or '', r['severity'], r['poc'] or ''])
        summary = {
            "Scanned Base": self.base_url,
            "Date": time.strftime('%Y-%m-%d %H:%M:%S'),
            "Total": len(self.results),
            "High": sum(1 for x in self.results if x['severity']=='High'),
            "Medium": sum(1 for x in self.results if x['severity']=='Medium'),
            "Low": sum(1 for x in self.results if x['severity']=='Low'),
        }
        logger.info("Scan summary:")
        for k,v in summary.items():
            logger.info(f"  {k}: {v}")
        with open("scan_summary.txt", 'w', encoding='utf-8') as fh:
            for k,v in summary.items():
                fh.write(f"{k}: {v}\n")
        logger.info(f"CSV saved to {filename}")

# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description='Smart Clickjacking Scanner (sensitive-aware)')
    parser.add_argument('url', help='Base URL to scan (e.g. https://example.com)')
    parser.add_argument('--threads', type=int, default=10, help='Concurrent threads (default: 10)')
    parser.add_argument('--delay', type=float, default=0.2, help='Delay between batches (default: 0.2s)')
    parser.add_argument('--max-urls', type=int, default=2000, help='Maximum pages to record/scan (default: 2000)')
    parser.add_argument('--no-robots', action='store_true', help='Do not read robots.txt / sitemaps')
    parser.add_argument('--discover', action='store_true', help='Enable wordlist discovery (be careful, many requests)')
    parser.add_argument('--wordlist', help='Custom wordlist file (one path per line)')
    parser.add_argument('--render', action='store_true', help='Enable Playwright-based JS rendering (optional & slow)')
    parser.add_argument('--output', default='clickjacking_report.csv', help='Output CSV filename')
    args = parser.parse_args()

    wl = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8') as fh:
                wl = [l.strip() for l in fh if l.strip()]
        except Exception as e:
            logger.warning(f"Cannot read wordlist {args.wordlist}: {e}")
            wl = DEFAULT_WORDLIST

    scanner = SmartClickjackingScanner(
        base_url=args.url,
        max_threads=args.threads,
        delay=args.delay,
        max_urls=args.max_urls,
        obey_robots=(not args.no_robots),
        discover=args.discover,
        wordlist=wl,
        render=args.render
    )

    logger.warning("Make sure you have written permission to test this target (bug bounty or owner).")
    scanner.crawl()
    scanner.generate_report(args.output)

if __name__ == '__main__':
    main()
