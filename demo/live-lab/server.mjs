import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const port = Number(process.env.PORT || 4173)
const root = fileURLToPath(new URL('../../', import.meta.url))
const target = join(root, 'demo', 'vulnerable-app')

const page = `<!doctype html><meta charset="utf-8"><title>OpenSec Live Lab</title><style>body{font:16px system-ui;max-width:900px;margin:3rem auto;background:#10131a;color:#eee}button{padding:.7rem 1rem;background:#00ff94;border:0}pre{background:#1d2330;padding:1rem;overflow:auto}</style><h1>OpenSec Live Lab</h1><p>Bundled vulnerable application. Scans run locally in a disposable target and never accept user-supplied paths.</p><button id="scan">Run deterministic scan</button><pre id="out">Ready.</pre><script>scan.onclick=async()=>{out.textContent='Scanning…';const r=await fetch('/api/scan',{method:'POST'});out.textContent=JSON.stringify(await r.json(),null,2)}</script>`

createServer(async (req, res) => {
  if (req.url === '/health') return json(res, 200, { status: 'ok', target: 'bundled-vulnerable-app' })
  if (req.method === 'GET' && req.url === '/') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(page) }
  if (req.method === 'POST' && req.url === '/api/scan') {
    const child = spawn(process.execPath, ['dist/bin/cmdr.js', 'scan', target, '--quick', '--output', 'json'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', (chunk) => { output += chunk })
    return child.on('close', () => { try { json(res, 200, { findings: JSON.parse(output), evidence: 'deterministic scan' }) } catch { json(res, 500, { error: 'scan failed' }) } })
  }
  json(res, 404, { error: 'not found' })
}).listen(port, '127.0.0.1', () => console.log(`OpenSec Live Lab listening on http://127.0.0.1:${port}`))

function json(res, status, value) { const body = JSON.stringify(value); res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }); res.end(body) }
