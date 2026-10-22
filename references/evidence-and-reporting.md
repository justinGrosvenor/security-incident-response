# Evidence and reporting contract

Create a restricted local incident directory. Separate the distributable summary from raw evidence. Exclude secret-bearing environment dumps, task definitions, registry tokens, customer records, and keys from reports/archives.

## Exposure ledger

| Field | Meaning |
| --- | --- |
| Finding | Advisory/incident identifier and component |
| Source | Primary URL, update date, checked-at timestamp |
| Asset | Repository/environment/deployment and account/region scope |
| Authorization | Per-project scan/patch decision; separate host/release permissions |
| Before | Exact installed/locked/running version or digest |
| Exposure | Confirmed affected, potentially affected, not affected within checked scope, unknown |
| Preconditions | Input, feature, configuration, execution window |
| Action | Patch/containment/mitigation and commit/artifact |
| Verification | Test, exit/result, positive control, evidence path, client actually tested |
| Delivery | Local, committed, pushed, PR, merged, staged, published, deployed, verified running |
| Remaining | Unchecked surfaces, compatibility, blocker, owner and next step |

A vulnerable version is not evidence of attacker execution. Negative findings must name the searched scope and time. Prefer "not found in inspected local environments" to "never used anywhere."

## Status vocabulary

- **Confirmed affected:** artifact/version/configuration matches exposure criteria; attacker execution is a separate finding.
- **Potentially affected:** prerequisites or artifact history remain unresolved.
- **Not affected within checked scope:** evidence excludes this issue for enumerated assets.
- **Unknown:** insufficient access, scope, metadata, or evidence.
- **Mitigated:** a tested control blocks the path, with limits stated.
- **Patched locally:** source/installed bytes updated and checked; no claim about remote users.
- **Staged / PR pending:** prepared for approval/merge, not published/deployed.
- **Verified running:** deployed process/artifact and relevant behavior checked after release.

## Final handoff

Lead with confirmed compromise if any, urgent remaining exposure, and required human actions. Then summarize verified fixes, negative findings/scope, validation, and unresolved work. Link PRs/releases and a restricted evidence index. Do not bury failed production verification under a passing test count.

```text
As of: <UTC timestamp and local time zone>
Scope: <machines, repositories, environments, accounts/regions>
Confirmed issues: <components and reachable impact>
Compromise evidence: <found / not found in stated scope / not assessed>
Completed: <local fixes / published artifacts / verified deployments separately>
Validation: <meaningful tests and precise outcomes>
Pending: <action, owner, blocker, compensating control>
Excluded: <historical environments, inaccessible services, other regions>
Evidence: <redacted index and primary sources>
```

## Shareable skill maintenance

Keep incident evidence in the user's own restricted audit record. Do not embed project names, organization identifiers, internal domains, deployment IDs, credential locations, or one user's approval waivers in this generic skill. Supply current incident data at invocation, with provenance and timestamps.

Distribute `SKILL.md`, `agents/`, `references/`, and `scripts/` together. Agents without Codex discovery can read `SKILL.md` directly. Inspect the entire archive for secrets and project/organization context before sharing; do not bundle local incident records.
