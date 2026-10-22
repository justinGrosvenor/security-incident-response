# Security Incident Response

A reusable agent skill targeting the October 19–22, 2026 cluster of security disclosures and supply-chain incidents.

It grew out of the certificate-authority compromise, which exposed a gap ordinary dependency audits cannot resolve: browsers, runtimes, SDKs and containers can use independent trust stores, so updating one does not prove the others are protected. The skill traces those less visible dependencies and trust paths across developer tooling, packages, builds and running deployments. Incident facts are refreshed at each use; the target dates do not freeze the affected-version criteria.

It asks permission before inspecting each project. Within approved scope, it traces declared, installed, cached, built, automated and running components; checks current primary incident reports; proposes or performs authorized remediation; and records evidence and remaining uncertainty.

## Use

Copy the `security-incident-response` folder into your agent's skill directory. In Codex, use `~/.codex/skills/`, or the configured skills location. Invoke:

```text
Use $security-incident-response to investigate these security incidents across
my development projects. Ask permission before each project. Start with scans;
do not publish, deploy, rotate credentials or stop services without approval.
```

Provide incident links if you have them. The skill also directs the agent to research current primary sources. An agent without skill discovery can read `SKILL.md` directly and follow the linked references. The workflow needs read/search tools appropriate to the approved scope; this package does not require a particular connector or account.

The agent will discover candidate identities from minimal metadata, then offer **scan only**, **scan and patch locally**, or **skip** for each project. Pending choices remain pending. Global/shared environments need separate scope approval. Source patches and tests are separate from publication and deployment.

The [PHP procedure](references/php-runtime-response.md) covers Composer dependencies and the engine independently, including CMS installations, FPM, Apache modules, embedded interpreters, vendor backports, container builds and verification of active workers. It is an investigation procedure; the bundled executable helper scans Python metadata only.

The [Node/Brotli procedure](references/node-brotli-response.md) traces inbound parsing, outbound response decompression, remote image/content fetching, direct decoder APIs and separately linked or embedded consumers. It requires actual build/patch evidence and verified activation; an inbound WAF is not treated as coverage for every path.

## Static Python helper

The helper uses the Python standard library and performs no network calls, subprocess execution, package imports, installations or remediation. Select a trusted interpreter; do not use a potentially compromised project interpreter for inspection.

```sh
/trusted/python3 -I -S scripts/inventory_python.py \
  --expected-root /approved/canonical/project \
  --exclude-root /approved/canonical/project/pending-child \
  /approved/canonical/project > metadata.json
```

Replace the example paths and complete boundary preflight in `references/scan-recipes.md`. Omit the exclusion only when no pending/denied descendant requires one. Supply additional verified indicator filenames using repeatable `--marker` arguments. Keep the source of those indicators in the incident record.

Read `errors`, `boundaries`, `exclusions`, `root_identities` and `limits`. Exit 2 means incomplete coverage. A successful inventory is not evidence that a machine is clean. Filename matches are investigation leads; metadata cannot establish artifact provenance or execution history by itself.

## Limits

This is an investigation workflow and static metadata helper. It does not automatically identify every malicious package, inspect running process memory, clear a host of compromise, or enforce human consent as a technical sandbox. Agents must preserve the approval ledger, canonical-root identity checks, exclusions and execution boundaries. Hostile concurrent filesystem changes require a suitable clean/offline investigation boundary.

No project inventory, organization identifiers, credential locations or fixed incident allowlist is included. Incident facts and affected versions must be refreshed at invocation. Keep generated audit records private unless explicitly approved for sharing.

## Verify the helper

```sh
/trusted/python3 -I -S tests/test_inventory_python.py scripts/inventory_python.py
```

Tests use temporary synthetic files, including inert startup-hook sentinels. They do not install packages, make network requests or scan your projects. Optional `--receipt <local-file>` writes detailed results that include local paths; keep them private. See `VALIDATION.md` for the release candidate's tested scope and limitations.

## License

MIT. See `LICENSE`.
