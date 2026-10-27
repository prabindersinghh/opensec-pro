# OpenSec Remediation Flow guardrails

- Treat `demo/` and `tests/` vulnerable fixtures as disposable test targets, never as production deployables.
- Run `npm run build`, `npm run lint`, and `npm test` before proposing a remediation.
- Run deterministic OpenSec scanning before and after every security change. Preserve the JSON findings and proof output as evidence.
- Work only on an isolated branch. Never push directly to `main` or another protected branch.
- Never merge a remediation automatically. A merge request pipeline and an independent proof re-run must pass first.
- Execute exploit/proof code only against a temporary copy of a bundled fixture with network disabled and no production credentials.
- Do not weaken, delete, or suppress a finding merely to make CI green. Use `opensec-ignore` only with a documented, reviewed reason.
- Report unresolved findings, failed pipelines, unavailable credentials, and unavailable deployment targets honestly.
