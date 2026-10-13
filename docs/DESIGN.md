# ODIN-GITHUB-AUTH-GATE-CANARY-05 — Native N1 synthetic implementation

Synthetic only. No model, no secrets, no paid API, no third-party Action (`uses:` is lint-forbidden).
Standard library Python 3; GitHub-hosted `ubuntu-24.04`; every job `timeout-minutes: 5`.

## Flow
`Owner merges authorization PR (authz/<pkg>.json + specs/<pkg>.md) into protected main`
→ `push` → **gate** (read) → **claim** (create-only tag) → **worker** (echo fixture, read) → **verify** (read) → **publish** (result branch + evidence tag).
Owner's routine action: one PR merge. Output is a branch `odin/<pkg>/r<N>`; nothing is merged or deployed.

## Enumerated triggers (checked by `python -m odin_gate.lint_workflows` + tests at review time; NOT executed at runtime — runtime enforcement is the gate's GATE_CHANGE rule)
| # | Trigger | Constraint |
|---|---|---|
| T1 | `push` | branches `[main]`, paths `authz/**`, `specs/**` |
| T2 | `workflow_dispatch` | inputs package_id + round; gate requires ref main, actor == repo owner, round >= 2 and <= record max_rounds, prior claim present |
Nothing else: no pull_request*, issue*, comment, label, workflow_run, schedule, fork-reachable path.

## Enumerated privileged paths
| Job | Token | Environment | What it can write |
|---|---|---|---|
| gate | contents:read, pull-requests:read | none | nothing |
| claim | contents:write | none | tag `odin/claim/<pkg>/r<N>` (create-only) |
| worker | contents:read | `synthetic-worker` (must be branch-restricted to main by Owner) | nothing; output is a job output |
| verify | contents:read | none | nothing |
| publish | contents:write | none | branch `odin/<pkg>/r<N>`, tag `odin/evidence/<pkg>/r<N>` (both create-only) |
Workflow-level `permissions: {}`. No `actions`, `id-token`, `workflows`, `packages` scopes anywhere. No job reads `secrets.*`.
Untrusted values never enter `run:` text (lint: no `${{` in `run:`); they pass through `env:` only.
Recursion: no job dispatches a workflow; `GITHUB_TOKEN` pushes do not trigger workflows; rounds bounded by the record.

## Authorization identity
`authz/<pkg>.json` (strict schema, unknown/duplicate keys rejected) pins: baseline_sha, spec_sha256, scope under `synthetic-out/<pkg>/`, max files/bytes/rounds, validity window (<= 7 days, upper bound exclusive), status.
Launch requires ALL of: repo/ref/event match; run_attempt <= 2 (second only while no claim exists); change set is exactly {A authz/<pkg>.json, A specs/<pkg>.md}; commit is the merge commit of a merged PR into main whose `merged_by` is the owner (API-derived, not actor-derived); baseline is an ancestor and baseline..launch touches only authz/specs files; spec bytes hash matches; record on main right now equals the launched blob (revocation/stale check).
Gate-code changes: any path outside authz/specs → `GATE_CHANGE`, never a launch. Modifications of an existing record: only a pure approved→revoked flip is accepted (recorded as NOOP); anything else → `AUTHZ_AMEND`.
Judge independence: every job runs `tools/` copied from the PRE-push tree (`github.event.before`; main tip for dispatch), so a commit cannot supply its own gate logic. This closes the mixed tools+authz commit. A tools-only commit triggers no run (paths filter), so each job also checks that the trusted copy's tree hash equals the pin `ODIN_TOOLS_TREE` in gate.yml; a silent tools change therefore fails every later run closed until the Owner deliberately re-pins. The extraction ignores tree attributes (`.git/info/attributes` forces `-export-ignore -export-subst -text -eol -ident -filter -working-tree-encoding`), and `tests/test_review_round1.py::CheckoutStepTests` executes the real workflow step against local repos (good pin, wrong pin, tools swapped in the pushed commit, tools swapped in the previous commit, hostile `.gitattributes`). Python runs with `-P` so a repo-root file cannot shadow a stdlib module (regression-tested with a control run showing the shadow works without `-P`). It does NOT close a commit that edits `.github/workflows/gate.yml` itself: GitHub runs the workflow file from the pushed commit, and a modified workflow can skip the gate. That case rests on Owner custody (what the Owner merges) and, if available on a personal repo, a push/path ruleset restricting `.github/**`; E3b observes it. Residual, stated, not claimed as mechanical.

## Verification
Verify re-derives everything from actual decoded bytes (declared size/hash only cross-checked): path normalization, forbidden prefixes, case-fold collisions, scope prefix match, file count, total bytes. Publish re-runs the same verification, re-checks revocation, requires the claim to exist, parent commit = approved baseline, create-only refs.

## Owner configuration gate (Phase C) — nothing here is assumed active
1. Settings > Rules > Rulesets: new branch ruleset on `main` — restrict deletions, block force pushes, require a pull request before merging (0 required approvals), no bypass actors (note Owner is repo admin: record whether admin bypass is selectable).
2. Rulesets: new tag ruleset for `odin/**` — restrict updates and deletions (do NOT restrict creation; GITHUB_TOKEN must create).
3. Settings > Actions > General: Workflow permissions = Read repository contents and packages permissions; untick "Allow GitHub Actions to create and approve pull requests"; Actions allowed = "Allow owner, and select non-owner, actions" (none needed); fork pull request workflows: require approval for all outside collaborators.
4. Settings > Environments > New `synthetic-worker`: Deployment branches = Selected branches → `main`; no secrets; no required reviewers.
5. Remove Claude GitHub App access to this repo (Settings > Applications > Claude > Repository access) and ensure ChatGPT/Codex GitHub connectors have no write access to it. Claude verifies loss of write independently; screenshots are Owner evidence only.
6. Billing: Settings > Billing and plans > Usage (or Plans and usage): record Actions minutes used, spending limit / budget = $0 with "stop usage", payment method as-is. Public repo + standard runners = no billing expected.
7. Confirm repo visibility Public and Actions enabled.

## Live experiment plan (Phase D; hard cap 30 runs including failed/cancelled)
| Exp | Method | Runs |
|---|---|---|
| E1 | observe actor/triggering_actor/initiator on push and dispatch runs (no Environment approver) | 0 extra |
| E2 | (note: 'Re-run failed jobs' does not re-run the gate, so run_attempt<=2 only bounds full re-runs; failed-job re-runs are bounded by create-only refs and publish resume) full re-run attempt 2 after claim → DUPLICATE; attempt 3 → RERUN; also 'Re-run failed jobs' behaviour (does the gate re-run?) | 2-3 |
| E3b | benign comment-only workflow edit bundled with an authz record — expected to LAUNCH (documents the residual above), BLOCK-class result | 1 |
| E3 | push launches for GATE_CHANGE, NO_AUTHZ(spec-only), AUTHZ_AMEND, SPEC_MISMATCH, BASELINE_DRIFT, EXPIRED; dispatch ROUND_GAP/ROUND_LIMIT/ACTOR n/a | ~8 |
| E4 | claim + evidence tags created by GITHUB_TOKEN; update/delete attempts refused by tag ruleset | 0 extra |
| E5 | direct push to main refused (no run); merges via squash / merge-commit / rebase record merged_by and merge_commit_sha behavior | 2 extra |
| E6 | fixtures out-of-scope, forbidden-path, oversize rejected by verify; max-size fixture passes end to end (job output/env size limits); job-level permission denial probes | 4 |
| E7 | two simultaneous dispatches of the same round → exactly one claim | 2 |
| E8 | environment branch policy: confirm the worker job ran under `synthetic-worker` restricted to main; no Action used | 0 extra |
| E9 | create issue / comment / label / PR-comment → run count unchanged | 0 |
| E10 | revoke record; dispatch → REVOKED; `slow` fixture revoked mid-flight stops at next check | 3 |
Expected ≈ 24 of 30 runs; reserve for re-tests. Each Owner action is a PR merge or UI click; the report lists them as batches.
NOT_TESTED by design: MERGER_MISMATCH (needs a second merging identity).

## Known limits
- `workflow_dispatch` on a non-main ref runs that ref's workflow file; gate rejects `REF_NOT_MAIN` but cannot prevent a writer from running arbitrary code on a branch (no secrets exist, but contents:write token exists in claim/publish for that branch's code). Mitigation is custody: no non-Owner writer.
- Job outputs (bundle) are visible in logs; synthetic data only.
- Owner admin can disable rulesets; evidence is tamper-evident to non-admins only.
