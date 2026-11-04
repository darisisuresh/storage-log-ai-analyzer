/* The analyzer runs only in this isolated browser worker. */
let runtime;
async function initialize() {
  if (runtime) return runtime;
  runtime = (async () => {
    postMessage({type: 'status', text: 'Loading the analysis engine. The first run may take a moment…'});
    importScripts('https://cdn.jsdelivr.net/pyodide/v0.29.3/full/pyodide.js');
    const python = await loadPyodide({indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.29.3/full/'});
    await python.loadPackage('sqlite3');
    const response = await fetch('engine.zip');
    if (!response.ok) throw new Error('The analysis engine could not be downloaded. Please retry.');
    python.unpackArchive(await response.arrayBuffer(), 'zip', {extractDir: '/app'});
    await python.runPythonAsync("import os, sys\nos.environ['IJSON_BACKEND'] = 'python'\nsys.path.insert(0, '/app')");
    const adapter = await fetch('analysis.py');
    if (!adapter.ok) throw new Error('The analysis adapter could not be loaded.');
    await python.runPythonAsync(await adapter.text());
    return python;
  })();
  return runtime;
}
self.onmessage = async ({data}) => {
  try {
    const python = await initialize();
    postMessage({type: 'status', text: 'Analyzing your logs locally…'});
    const payload = python.toPy(data);
    python.globals.set('browser_payload', payload);
    try {
      const value = await python.runPythonAsync('analyze_browser(browser_payload)');
      postMessage({type: 'result', ...JSON.parse(value)});
    } finally {
      python.globals.delete('browser_payload');
      payload.destroy();
    }
  } catch (error) {
    // Never include raw log content or Python tracebacks in user-facing errors.
    const lastLine = String(error.message || error).trim().split('\n').filter(Boolean).pop();
    postMessage({type: 'error', message: lastLine?.replace(/^(ValueError|RuntimeError): /, '') || 'Analysis failed. Check your files and try again.'});
  }
};
