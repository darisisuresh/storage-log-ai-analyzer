'use strict';
const $ = id => document.getElementById(id);
const ALLOWED = /\.(log|txt|json|jsonl|csv)$/i;
const MAX_BYTES = 20 * 1024 * 1024;
let files = [], worker = null, timer = null, report = null, markdown = '', busy = false, runId = 0;
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function fail(message) { $('error').textContent = message; $('error').hidden = false; }
function clearResults() {
  report = null; markdown = '';
  $('results').hidden = true; $('empty-state').hidden = false;
  $('findings').replaceChildren(); $('diagnostics').replaceChildren();
}
function selectFiles(incoming) {
  if (busy) return;
  $('error').hidden = true;
  const combined = [...files];
  for (const file of incoming) {
    if (!ALLOWED.test(file.name)) return fail('Choose LOG, TXT, JSON, JSONL, or CSV files. Archives and other formats are not supported.');
    if (file.size === 0) return fail(`${file.name} is empty. Choose a nonempty log file.`);
    if (!combined.some(old => old.name === file.name && old.size === file.size && old.lastModified === file.lastModified)) combined.push(file);
  }
  if (combined.length > 10 || combined.reduce((total, file) => total + file.size, 0) > MAX_BYTES) return fail('Choose up to 10 files with a combined size of 20 MiB or less. Use the command-line tool for larger datasets.');
  files = combined; clearResults(); renderFiles();
  $('status').textContent = `${files.length} file${files.length === 1 ? '' : 's'} selected. Ready to analyze.`;
}
function renderFiles() {
  $('file-list').replaceChildren();
  files.forEach((file, index) => {
    const li = element('li'), label = element('span', file.name, 'filename');
    label.append(element('span', `${(file.size / 1024).toFixed(1)} KiB`, 'file-size'));
    const remove = element('button', 'Remove', 'text-button');
    remove.type = 'button'; remove.disabled = busy; remove.setAttribute('aria-label', `Remove ${file.name}`);
    remove.onclick = () => { files.splice(index, 1); clearResults(); renderFiles(); $('status').textContent = files.length ? 'Ready to analyze.' : 'Choose a file or try the sample to get started.'; };
    li.append(label, remove); $('file-list').append(li);
  });
  $('file-heading').hidden = files.length === 0;
  $('analyze').disabled = !files.length || busy;
}
function setBusy(value) {
  busy = value; document.body.classList.toggle('busy', value);
  $('analysis-form').setAttribute('aria-busy', String(value));
  for (const id of ['files', 'clear', 'sample', 'vendor', 'timezone', 'year', 'rpo', 'window', 'strict']) $(id).disabled = value;
  $('cancel').hidden = !value; renderFiles();
}
function finish() {
  runId += 1;
  clearTimeout(timer); timer = null;
  if (worker) worker.terminate(); worker = null;
  setBusy(false);
}
function badge(text, style) { return element('span', text, `badge ${style || ''}`); }
function renderReport(data) {
  report = data.report; markdown = data.markdown;
  $('results').hidden = false; $('empty-state').hidden = true;
  $('risk').textContent = `${report.risk} overall`; $('risk').className = `badge ${report.risk}`;
  $('analyzed-files').textContent = `Analyzed: ${report.files.join(', ')}`;
  const active = report.findings.filter(finding => finding.state !== 'RESOLVED').reduce((sum, finding) => sum + finding.incident_count, 0);
  $('metrics').replaceChildren(...[[report.event_count, 'Events processed'], [report.files.length, 'Files analyzed'], [active, 'Active / uncertain incidents'], [report.findings.length, 'Finding groups']].map(([value, label]) => {
    const box = element('div', undefined, 'metric'); box.append(element('strong', Number(value).toLocaleString()), element('span', label)); return box;
  }));
  $('findings').replaceChildren();
  if (!report.findings.length) $('findings').append(element('p', 'No known high-risk patterns were detected. This does not establish system health.', 'muted'));
  for (const finding of report.findings) {
    const card = element('article', undefined, 'finding'), head = element('div', undefined, 'finding-head');
    head.append(badge(finding.severity, finding.severity), badge(finding.state, finding.state === 'UNKNOWN' ? 'unknown' : ''), element('span', `${finding.finding_ref} · ${finding.rule_id}`));
    card.append(head, element('h4', finding.title));
    card.append(element('p', `${finding.incident_count} device/resource incident(s) · ${finding.unique_event_count} unique active-state event(s) · ${finding.duplicate_count} repeated`, 'muted'));
    card.append(element('p', `Severity basis: ${finding.severity_basis.replaceAll('_', ' ')}`));
    if (finding.first_seen || finding.last_seen) card.append(element('p', `UTC range: ${finding.first_seen || 'unknown'} → ${finding.last_seen || 'unknown'}`, 'muted'));
    if (finding.replication_gap_seconds !== null) card.append(element('p', `Replication lag: ${finding.replication_gap_seconds}s · Maximum observed: ${finding.max_replication_gap_seconds}s. This does not measure data loss.`));
    if (finding.duration_seconds !== null) card.append(element('p', `Observed current-cycle duration: ${finding.duration_seconds}s`));
    if (finding.business_risk_score !== null) card.append(element('p', `Supplied advisory index: ${finding.business_risk_score}/100. Uncalibrated; does not override severity.`));
    const actions = element('ul');
    const recommendations = finding.state === 'RESOLVED' ? ['Historical incident resolved; verify recovery evidence.'] : finding.recommendations;
    for (const action of recommendations) actions.append(element('li', action));
    card.append(actions);
    const details = element('details'); details.append(element('summary', `View evidence (${finding.evidence.length} samples)`));
    for (const line of finding.evidence) details.append(element('pre', line));
    card.append(details); $('findings').append(card);
  }
  $('diagnostics').replaceChildren();
  for (const [key, count] of Object.entries(report.diagnostics).sort()) {
    const row = element('div', undefined, 'diagnostic-row'); row.append(element('span', key.replaceAll('_', ' ')), element('strong', count)); $('diagnostics').append(row);
  }
  $('results-heading').focus({preventScroll: true}); $('results').scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start'});
}
$('files').addEventListener('change', event => { selectFiles([...event.target.files]); event.target.value = ''; });
$('clear').onclick = () => { files = []; clearResults(); renderFiles(); $('status').textContent = 'Choose a file or try the sample to get started.'; $('error').hidden = true; };
for (const type of ['dragenter', 'dragover']) $('dropzone').addEventListener(type, event => { event.preventDefault(); if (!busy) $('dropzone').classList.add('dragover'); });
for (const type of ['dragleave', 'drop']) $('dropzone').addEventListener(type, event => { event.preventDefault(); $('dropzone').classList.remove('dragover'); });
$('dropzone').addEventListener('drop', event => selectFiles([...event.dataTransfer.files]));
window.addEventListener('dragover', event => event.preventDefault()); window.addEventListener('drop', event => event.preventDefault());
$('sample').onclick = async () => {
  try {
    $('sample').disabled = true;
    const response = await fetch('sample.log');
    if (!response.ok) throw new Error('Sample could not be loaded. Please upload a log file.');
    selectFiles([new File([await response.arrayBuffer()], 'sample-storage.log', {type: 'text/plain', lastModified: 0})]);
  } catch (error) { fail(error.message); } finally { $('sample').disabled = busy; }
};
$('cancel').onclick = () => { finish(); $('status').textContent = 'Analysis cancelled. Files have been removed from the analysis worker.'; };
$('analysis-form').onsubmit = async event => {
  event.preventDefault(); if (busy || !files.length) return;
  $('error').hidden = true;
  if (!$('analysis-form').reportValidity()) return;
  clearResults(); setBusy(true);
  const currentRun = ++runId;
  $('status').textContent = 'Preparing your files…';
  try {
    const selected = await Promise.all(files.map(async file => ({name: file.name, data: new Uint8Array(await file.arrayBuffer())})));
    if (!busy || currentRun !== runId) return;
    worker = new Worker('worker.js');
    timer = setTimeout(() => { finish(); fail('Analysis reached the 3-minute browser limit. Try a smaller batch or use the command-line tool.'); $('status').textContent = 'Analysis stopped.'; }, 180000);
    worker.onmessage = ({data}) => {
      if (data.type === 'status') $('status').textContent = data.text;
      else if (data.type === 'error') { finish(); fail(data.message); $('status').textContent = 'Analysis stopped. Check the error above.'; }
      else if (data.type === 'result') { finish(); renderReport(data); $('status').textContent = 'Analysis complete. Your findings are displayed below.'; }
    };
    worker.onerror = () => { finish(); fail('The browser analysis engine could not start. Check your internet connection and WebAssembly support, then retry.'); $('status').textContent = 'Analysis stopped.'; };
    worker.postMessage({files: selected, options: {vendor: $('vendor').value, timezone: $('timezone').value.trim(), year: $('year').value ? Number($('year').value) : null, rpo: $('rpo').value ? Number($('rpo').value) : null, window: Number($('window').value), strict: $('strict').checked}}, selected.map(file => file.data.buffer));
  } catch (error) { finish(); fail(error.message); $('status').textContent = 'Analysis stopped.'; }
};
function download(contents, extension, type) {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([contents], {type}));
  const link = element('a'); link.href = url; link.download = `storage-log-analysis.${extension}`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('download-json').onclick = () => download(JSON.stringify(report, null, 2), 'json', 'application/json');
$('download-md').onclick = () => download(markdown, 'md', 'text/markdown;charset=utf-8');
