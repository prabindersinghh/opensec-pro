import { readFile } from 'node:fs/promises'

const file = '.gitlab/duo/flows/opensec-remediation.yml'
const source = await readFile(file, 'utf8')
const required = ['version: v1', 'environment: ambient', 'components:', 'routers:', 'flow:', 'entry_point:', 'prompts:']
for (const token of required) {
  if (!source.includes(token)) throw new Error(`Duo flow is missing required field: ${token}`)
}
for (const forbidden of ['\nname:', '\ndescription:', '\nproduct_group:']) {
  if (source.includes(forbidden)) throw new Error(`Custom flow contains unsupported top-level field: ${forbidden.trim()}`)
}
for (const tool of ['read_file', 'run_command', 'create_branch', 'create_merge_request']) {
  if (!source.includes(`      - ${tool}`)) throw new Error(`Duo flow does not grant required tool: ${tool}`)
}
console.log(`Validated ${file} against the checked-in GitLab custom-flow contract.`)
