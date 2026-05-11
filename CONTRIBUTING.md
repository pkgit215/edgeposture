# Contributing to RuleIQ

Thanks for digging in. This page covers the workflow conventions; the
hands-on setup (local dev commands, env vars, release / deploy notes)
lives in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## Run it locally

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md#local-development) for
the full backend + frontend setup. Quick start:

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
DEMO_MODE=true uvicorn main:app --reload --port 8001

# Frontend (separate terminal)
cd frontend
yarn install
yarn dev   # http://localhost:5173 by default
```

Demo mode reads the bundled WAF fixtures — no AWS creds required. For a
real-account run, set `OPENAI_API_KEY` and pass an `external_id` / role ARN
through the Connect flow.

## Tests

```bash
cd backend  && pytest -q       # all 178 backend tests
cd frontend && yarn test       # vitest suite, all 25 specs
```

The backend `pytest -q` runs in ~5s on a laptop. Frontend `yarn test` runs in
~4s. There's no excuse to skip them.

## Issues and PRs

- File bugs / features / security findings via the templates in
  `.github/ISSUE_TEMPLATE/`. Blank issues are disabled.
- Triage by `priority:` label (`p0` → `p3`) and `area:` label. See
  `.github/labels.yml` for the canonical set; seed locally with
  `bash scripts/seed-github-labels.sh`.
- Every PR should link the issue it closes with `Closes #N` in the body.

## Branch naming

- `phase/<N>-<short>` for phase rollups — e.g. `phase/5.3.2-impact-methodology`
- `fix/<issue-number>-<slug>` for one-off bug fixes — e.g. `fix/12-bypass-affected-rules`

## Commit message

Use the same format we use across the project:

```
Phase N.N.N: <short summary>

<optional body — what + why, not how>
```

For bug fixes outside a phase rollup:

```
Fix: <short summary> (#<issue>)
```

## What NOT to add in a PR

- No CLA / licensing boilerplate — out of scope.
- No new dependencies without a one-line justification in the PR description.
- No formatting-only churn mixed into a behaviour change.
