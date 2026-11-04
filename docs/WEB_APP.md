# Browser log analyzer

Public app: https://storage-log-analyzer.sureshemc12.chatgpt.site

## Use

1. Click **Upload logs** or drop files into the upload area.
2. Optionally set vendor, fallback timezone, year for yearless syslog, RPO target, and correlation window.
3. Click **Analyze logs**. Findings appear below the upload area with incident state, severity basis, evidence samples, and recommended actions.
4. Download a JSON or Markdown report. **Clear all** removes the selected files and displayed report; **Cancel analysis** terminates the worker.

Supported formats: `.log`, `.txt`, `.json`, `.jsonl`, `.csv`. Maximum 10 files and 20 MiB combined. A 3-minute timeout bounds each run. JSONL is strict by default. Naive timestamps default to UTC unless changed. Yearless syslog remains uncertain unless the year is provided.

## Processing and privacy

The static page downloads Pyodide 0.29.3 from jsDelivr, then runs the repository's Python engine, ijson's Python backend, and bundled timezone data in a dedicated Web Worker. No alternative JavaScript severity rules are used. P1-6/P1-7 chronology and impact policies apply. There are no upload endpoints, telemetry, account requirements, API keys, or external AI calls. Log contents and resulting reports stay in browser memory unless the visitor downloads a report. Downloads can contain sensitive evidence; handle them like the original logs.

Each run ends by terminating its worker, releasing its temporary in-memory files and Python state. Selected File objects and the displayed report remain until cleared or the tab closes. The application does not use persistent browser storage for logs. Runtime and static asset requests still reach the hosting provider/CDN; the site is not a fully offline application. Browser memory and WebAssembly limits differ from the CLI's native disk-backed operation, so use the CLI for large datasets. Detection coverage and missing source context limit conclusions; no finding is a guarantee of system health.

## Build and verify

```sh
python -m pip install -e '.[dev]'
python scripts/build_web.py
python -m http.server 8000 --directory dist/web
```

Open http://localhost:8000. The generated `engine.zip` contains the current source package, pure-Python ijson, tzdata, and license notices. It is rebuilt from source rather than committed as a stale binary.

```sh
python -m unittest discover -s tests -v
node --check web/app.js
node --check web/worker.js
npm install --no-save playwright@1.64.1
npx playwright install chromium
node scripts/check_web.cjs
```

Browser checks cover real WebAssembly analysis, same-device controller/path correlation, evidence treated as text, JSON downloads, malformed/empty/oversized inputs, responsive layouts, and absence of outbound upload requests. `PLAYWRIGHT_MODULE` optionally points to an existing Playwright installation. `AXE_PATH` enables accessibility checks using a local axe-core script; `WEB_SCREENSHOTS` sets an existing screenshot directory. CI builds and runs the browser checks in Chromium. Safari and Firefox are not yet verified.

The Sites deployment contains the generated `dist/web` assets. Site source is synchronized separately for hosting; canonical development files remain in this GitHub repository. Existing CLI release artifacts remain unchanged.
