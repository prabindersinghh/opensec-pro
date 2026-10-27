import { readFile, writeFile } from 'node:fs/promises'

const [input, output] = process.argv.slice(2)
if (!input || !output) throw new Error('Usage: render-report.mjs findings.json report.html')
const findings = JSON.parse(await readFile(input, 'utf8'))
const rows = findings.map((f) => `<tr><td>${escapeHtml(f.severity)}</td><td>${escapeHtml(f.file)}:${f.line}</td><td>${escapeHtml(f.ruleName)}</td><td>${escapeHtml(f.description)}</td></tr>`).join('')
const html = `<!doctype html><meta charset="utf-8"><title>OpenSec CI report</title><style>body{font:16px system-ui;margin:2rem;background:#10131a;color:#eee}table{border-collapse:collapse;width:100%}td,th{border:1px solid #394150;padding:.6rem;text-align:left}th{background:#232938}</style><h1>OpenSec CI report</h1><p>${findings.length} deterministic findings</p><table><tr><th>Severity</th><th>Location</th><th>Rule</th><th>Evidence</th></tr>${rows}</table>`
await writeFile(output, html)

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}
