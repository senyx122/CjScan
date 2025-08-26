 CjScan — Repository (all files)

This document contains the complete set of starter files for the **CjScan** repository — Smart Clickjacking Scanner.

 Copy each file into your repo root (or use the provided `create_repo.sh` script) and push to GitHub.

---

````md
CjScan

Smart Clickjacking Scanner — sensitive-aware crawler and JS endpoint extractor for authorized security testing.

 Features

- Prioritized crawling using sitemaps and keyword scoring
- Extracts endpoints from HTML, JS (fetch/axios/template literals), and JSON
- Optional Playwright rendering for SPA/AJAX discovery
- Clickjacking detection via `X-Frame-Options`, `CSP(frame-ancestors)`, JS protections
- PoC iframe generator for potential vulnerable pages
- CSV report + scan summary

 Disclaimer / Legal

**Run only against targets you own or have explicit written permission to test.** Misuse may be illegal.

 Quickstart

 1. Create virtualenv & install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
````

`requirements.txt` example:

```
requests
beautifulsoup4
```

If you want Playwright-based rendering (optional):

```bash
pip install playwright
playwright install
```

### 2. Run scanner

```bash
python3 cj_scanner.py https://example.com --threads 8 --discover --output results.csv
```

 3. Outputs

* `results.csv` — detailed findings
* `scan_summary.txt` — summary
* `cj_poc_<domain>_...html` — PoC iframe pages (if generated)

Contributing

PRs welcome. Please follow `CODE_OF_CONDUCT.md` and `CONTRIBUTING.md`.

 License

MIT License — see `LICENSE` file.

```
LICENSE 

```text
MIT License

Copyright (c) 2025 <Senyx122>

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
```

---

