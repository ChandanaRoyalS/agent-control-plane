"""One file, no build step, no framework — task 63.

*"Minimal styling, no framework ceremony — it exists to be watched for thirty
seconds."*

Taken literally. No npm, no bundler, no CDN: a CDN import would make the console
fail on a laptop with no network, which is exactly the machine a demo runs on.

The one thing this page works hard at is the distinction between a **recorded**
event and an **observed** one, because that is the honest part and a console that
rendered them identically would quietly claim the breaker line is in the chain.
"""

from __future__ import annotations

from typing import Final

PAGE: Final = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ACP — live trace</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #0d1117; color: #c9d1d9;
         font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  header { padding: 10px 16px; border-bottom: 1px solid #30363d;
           display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  h1 { font-size: 14px; margin: 0; font-weight: 600; }
  input { background: #010409; color: #c9d1d9; border: 1px solid #30363d;
          padding: 4px 8px; font: inherit; width: 26ch; }
  button { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
           padding: 4px 12px; font: inherit; cursor: pointer; }
  #state { margin-left: auto; color: #8b949e; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 2px 8px; vertical-align: top; white-space: nowrap; }
  td.reason { white-space: normal; color: #8b949e; }
  td.id { cursor: help; }
  tr.observed { opacity: .72; }
  tr.observed td.mark { color: #d29922; }
  tr.recorded td.mark { color: #3fb950; }
  .denied { color: #f85149; }
  .held { color: #d29922; }
  .allowed, .completed { color: #3fb950; }
  .failed { color: #f85149; }
  .dim { color: #6e7681; }
  footer { padding: 8px 16px; border-top: 1px solid #30363d; color: #6e7681; }
  code { color: #79c0ff; }
</style>
</head>
<body>
<header>
  <h1>ACP live trace</h1>
  <input id="token" type="password" placeholder="operator token" autocomplete="off">
  <button id="go">watch</button>
  <span id="state">idle</span>
</header>
<table><tbody id="rows"></tbody></table>
<footer>
  <span style="color:#3fb950">&#9679;</span> recorded &mdash; in the hash chain,
  survives a restart, <code>acp audit verify</code> covers it &nbsp;&nbsp;
  <span style="color:#d29922">&#9675;</span> observed &mdash; live only, not in
  the chain, gone when this process is
</footer>
<script>
const rows = document.getElementById('rows');
const state = document.getElementById('state');
const MAX = 300;

function cell(row, text, cls) {
  const td = document.createElement('td');
  td.textContent = text === undefined || text === null ? '' : String(text);
  if (cls) td.className = cls;
  row.appendChild(td);
  return td;
}

// Identifiers are shortened for the column and kept whole in the tooltip.
//
// The audit record names a principal by the `sub` claim, which for Keycloak is
// a 36-character UUID. That is the RIGHT thing to record — it is the stable
// identifier, and a display name is neither stable nor unique — and it is the
// WRONG thing to fill a column with in a thing meant to be watched for thirty
// seconds. Truncating is a rendering decision, so it lives here rather than in
// the record.
const IDENT = 12;
function ident(row, text) {
  const value = text === undefined || text === null ? '' : String(text);
  const td = cell(row, value.length > IDENT ? value.slice(0, IDENT) + '\u2026' : value);
  if (value.length > IDENT) { td.className = 'id'; td.title = value; }
  return td;
}

function render(e) {
  const row = document.createElement('tr');
  row.className = e.source;
  cell(row, e.source === 'recorded' ? '\\u25CF' : '\\u25CB', 'mark');
  cell(row, e.seq === undefined ? '' : '#' + e.seq, 'dim');
  cell(row, new Date(e.at * 1000).toLocaleTimeString());
  cell(row, e.category, 'dim');
  cell(row, e.event);
  cell(row, e.outcome || '', e.outcome || '');
  ident(row, e.subject || '');
  ident(row, e.actor || '');
  cell(row, e.tool || e.upstream || '');
  cell(row, e.rule || '', 'dim');
  cell(row, e.reason || '', 'reason');
  // Newest first: a console watched for thirty seconds should not need
  // scrolling to find what just happened.
  rows.prepend(row);
  while (rows.children.length > MAX) rows.lastChild.remove();
}

// A hand-rolled SSE parser, because EventSource cannot set an Authorization
// header and the alternative is a credential in the query string — which lands
// in browser history, in referrers, and in every access log on the way.
async function watch(token) {
  state.textContent = 'connecting';
  let response;
  try {
    response = await fetch('/console/stream', {
      headers: { 'Authorization': 'Bearer ' + token },
    });
  } catch (err) {
    state.textContent = 'unreachable';
    return;
  }
  if (!response.ok) {
    state.textContent = response.status === 401 ? 'bad token' : 'error ' + response.status;
    return;
  }
  state.textContent = 'watching';

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    // SSE frames are separated by a blank line. Splitting on it and keeping
    // the tail is what makes a frame split across two TCP reads work — the
    // bug you only see under load, and only sometimes.
    const frames = buffer.split('\\n\\n');
    buffer = frames.pop();
    for (const frame of frames) {
      for (const line of frame.split('\\n')) {
        if (line.startsWith('data: ')) {
          try { render(JSON.parse(line.slice(6))); } catch (err) { /* keep going */ }
        }
      }
    }
  }
  state.textContent = 'disconnected';
}

document.getElementById('go').addEventListener('click', () => {
  const token = document.getElementById('token').value.trim();
  if (token) watch(token);
});
document.getElementById('token').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('go').click();
});
</script>
</body>
</html>
"""
