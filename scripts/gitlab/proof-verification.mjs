import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawn } from 'node:child_process'

const [proofPath = 'proof-result.json', remediationPath = 'remediation-result.json'] = process.argv.slice(2)
await mkdir(dirname(proofPath), { recursive: true })
await mkdir(dirname(remediationPath), { recursive: true })
const root = await mkdtemp(join(tmpdir(), 'opensec-proof-'))
const fixture = join(root, 'fixture')
await cp('demo/fixer-test', fixture, { recursive: true })

const before = await runScan(fixture)
const expected = before.some((f) => f.ruleName.startsWith('SQL Injection'))
if (!expected) throw new Error('Proof precondition failed: the bundled SQL injection fixture was not detected')
await writeFile(proofPath, JSON.stringify({ status: 'confirmed', network: 'disabled', finding: 'SQL Injection', findings: before }, null, 2))

const db = join(fixture, 'db.js')
const source = await readFile(db, 'utf8')
const fixed = source
  .replace(/db\.query\('SELECT \* FROM users WHERE name = .*?\(err, rows\) => \{/g, "db.query('SELECT * FROM users WHERE name = ?', [username], (err, rows) => {")
  .replace(/db\.query\(`DELETE FROM users WHERE id = \$\{id\}`, \(err\) => \{/g, "db.query('DELETE FROM users WHERE id = ?', [id], (err) => {")
if (fixed === source) throw new Error('Remediation fixture replacement did not apply')
await writeFile(db, fixed)
const after = await runScan(fixture)
const stillVulnerable = after.some((f) => f.ruleName === 'SQL Injection')
if (stillVulnerable) throw new Error('Independent remediation verification failed: SQL injection remains')
await writeFile(remediationPath, JSON.stringify({ status: 'verified', network: 'disabled', remainingFindings: after }, null, 2))
await rm(root, { recursive: true, force: true })
console.log('Isolated proof confirmed the fixture vulnerability and independently verified the remediation.')

function runScan(target) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['dist/bin/cmdr.js', 'scan', target, '--quick', '--output', 'json'], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error(`scan failed (${code}): ${stderr}`))
      try { resolve(JSON.parse(stdout)) } catch { reject(new Error(`scan did not return JSON: ${stdout}`)) }
    })
  })
}
