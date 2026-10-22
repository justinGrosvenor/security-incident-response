# Scan recipes for approved projects

These recipes identify where to look without importing or executing suspect packages. Start with the entrypoint's per-project approval checkpoint. Only inspect shared caches, global environments, running containers, remote CI or deployments when their scope is separately approved. Keep credentials out of output. Commands below use placeholders and must be adapted to the user's platform and package manager.

## Candidate discovery before project approval

Use user-supplied workspace roots or a shallow directory listing to identify likely projects, `.git` markers, and manifest **filenames**, without reading their contents. Use process executable paths/listening port ownership only if machine process discovery is authorized; omit environment variables and full argument strings because they can contain secrets. Do not recursively traverse a whole home directory as discovery.

Initial identity discovery uses static paths/markers, not native project Git commands, shell alias dumps or raw remote URLs. Git metadata commands can execute configured external programs, and URL/alias values can embed credentials. Assess tooling/configuration trust before invoking them; parse only approved metadata and redact before output when deeper identity is needed.

Present a specific project/path and independent choices: scan only, scan and patch locally, skip. If a service appears to share a global interpreter or volume, explain the cross-project boundary and ask for that shared scope. Pending/declined projects stay untouched and appear in exclusions.

Separate approval of named global/shared installations does not permit recursively inspecting every private project environment under a home directory. Respect both scopes when they overlap.

Record the canonical root and filesystem identity (device/inode where available) alongside each decision. Recheck them immediately before the scan; changed aliases, mounts or identity require renewed approval. Use the approved canonical path as `--expected-root`, never a newly resolved unapproved alias target. This check protects against accidental root retargeting; it is not an adversarial filesystem sandbox.

Before recursive content reads, inventory nested project marker **filenames** within the approved discovery scope. Independently configured descendant projects need their own decision. If uncertain whether a workspace component belongs to the approved project, ask; keep it excluded meanwhile. Supply every pending/denied descendant using `--exclude-root <canonical-path>`. Newly discovered boundaries remain pending. Dependency directories can also contain separate projects, so do not rely only on directory-name heuristics.

## Python

Use a verified clean interpreter and replace the paths:

```sh
/trusted/python3 -I -S /skill/scripts/inventory_python.py \
  --expected-root /approved/canonical/project \
  --exclude-root /approved/canonical/project/pending-child \
  /approved/canonical/project > metadata.json
```

Replace these paths; omit the exclusion only if there are no pending/denied descendants. For multiple independently approved roots, repeat `--expected-root` in roots order. Add global sites/external venvs only after approval. Read JSON `errors`, `boundaries`, `exclusions`, `root_identities`, and `limits`; exit 2 means incomplete coverage, even for intentional exclusions. A malformed exclusion fails closed before scanning. The helper skips candidate nested projects with common manifest/Git markers outside installed dependency trees unless supplied as explicit approved roots. This conservative heuristic does not determine actual consent or detect every possible project type. Keep the agent's explicit boundary preflight and exclusions authoritative.

The helper searches `target`, `node_modules`, build and bytecode directories rather than silently pruning them. It excludes Git internals as declared in `limits`. It lists plain, compiled, native and package-form Python startup customization candidates, not just `.py` files. It reports metadata identities, not execution history, provenance or malware attribution. `coverage_complete` describes its defined filesystem inventory only, not uninspected archives/remote assets or absence of compromise.

Supply additional exact indicator filenames from current verified reporting using repeatable `--marker <basename>` arguments. The scanner has no hardcoded incident-specific filename list. It identifies `.pth` hooks and Python customization modules as generic startup mechanisms; those are not automatically malicious. `matched_indicator` means only a filename matched the supplied list, not that its contents or execution were verified. Keep the source for that list in the incident profile.

Normalize distribution names using Python packaging rules (case folding and dash/underscore/dot equivalence). Match the current incident profile against metadata and exact artifact hashes. Use a trusted PEP 440 implementation when ranges matter; do not approximate with string comparison. Inspect lockfiles (`uv`, pip-tools, Poetry, Pipenv, requirements), wheel caches, pipx/tool environments and CI/container layers as separately authorized. Inspect legacy egg formats and manually installed modules if the metadata inventory is incomplete. Check explicit path overrides and running interpreter paths.

Do not run a suspect Python executable with `--version` merely because it looks read-only; normal startup still runs hooks. A clean trusted interpreter using `-I -S` can read suspect environment files, but does not make the suspect host clean. Do not add an entire suspect site directory to `sys.path` and import its utilities to aid inspection.

## JavaScript/TypeScript

Read approved manifest and exact npm/pnpm/Yarn/Bun lockfiles statically. Correlate requested ranges with installed `node_modules/<package>/package.json`, nested copies, workspace hoisting, aliases, optional dependencies, overrides, integrity entries, and bundled packages. Documentation references and optional peers are leads, not installation evidence.

Inspect runtime path/version and CI/Docker pins only after selecting trusted tooling. Audit commands may access the network and inspect configuration; run them only if the relevant scan scope permits it. Do not use `npx` or an auto-installing scanner to investigate a suspected package compromise. Avoid lifecycle scripts and project commands until package execution is considered safe. Account for preload hooks and custom package manager plugins.

Use a trusted semver implementation for npm ranges; prereleases, aliases and multiple installed copies matter. An audit finding's parent/meta-vulnerability record may represent the same root issue, but do not dismiss unrelated advisories. Preserve raw audit JSON plus precise dispositions. Inspect actual published tarballs and bundled native files if the project distributes them; source dependency changes alone do not establish what consumers received.

## PHP and Composer

Follow [the PHP runtime and package procedure](php-runtime-response.md). Statically compare manifests, lockfiles and installed JSON without loading PHP metadata, autoloaders, plugins or application commands. Inventory CLI, FPM/CGI, Apache modules, embedded interpreters, persistent workers and builder/final images separately. Composer audits and platform overrides do not establish engine safety; match actual builds or vendor backports and verify authorized worker replacement.

## Rust and other compiled runtimes

Read `Cargo.toml`/`Cargo.lock` and all resolved versions of relevant roots/verifiers/native libraries. Check feature selection and compatibility wrapper crates that re-export separately resolved dependencies. Match current RustSec/OSV ranges and maintained fixes. Only run build tooling after approval for execution; build scripts/procedural macros execute code.

For other ecosystems, apply the same installed/locked/built/running distinction using their authoritative package metadata and version rules. Runtime-embedded libraries may be absent from manifests. Check binary architecture, linked libraries, embedded trust, distro revision/backports, and build provenance. Rebuild/test actual artifacts, not just lockfiles, when patching is approved.

## Containers, running processes, and CI

Within approved scope, map a running process to its executable/environment and a container to its exact image digest/platform. Inspect metadata using fields selected to exclude environment secrets. Do not start a suspect image to query its version. Export/static-inspect relevant filesystem data without executing entrypoints, and safely handle untrusted archive paths/links and layer whiteouts.

Inspect all Docker stages and startup installers. Review CI actions, bots, agent/MCP servers, devcontainers, notebooks, release jobs and cache restoration. Capture actual observed action/image/dependency identities from run logs; immutable source refs can still load mutable image tags. Query incident-window history and report missing retention. Do not infer remote non-use from a clean local manifest.

Inspect token **scopes**, mounts and permissions without retrieving secret values. Any upload of private lockfiles or logs to an external scanning service requires appropriate authorization; prefer local matching or approved advisory endpoints. Read-only scan approval does not authorize disabling jobs, canceling workflows, changing policies, or revoking credentials.

## Decision sequence

For each incident/component and approved asset:

1. Is the component present in an installed, built, cached, remote or running layer? If only mentioned, label that distinction.
2. Does the exact version/artifact/digest match authoritative affected criteria? If unknown, preserve uncertainty.
3. Are required platform/features/input paths reachable? Separate confirmed applicability from observed exploitation.
4. For compromised artifacts, can provenance/file hashes/install history/execution evidence establish an artifact match and exposure window? An affected version is a lead; negative marker searches do not establish clearance.
5. What credentials/capabilities were reachable if execution occurred? Assess from clean tooling without exposing values.
6. What action is authorized for this project? Under scan-only, deliver findings and proposed changes, then ask before patching. Under local patch approval, repair/test locally; releases/deployments remain separate.
7. What meaningful verification proves the specific fix at the layer being claimed? Record positive controls, blockers, exclusions, and pending approvals.

Leave unapproved projects untouched. If another affected project is discovered while scanning an approved shared service, record its minimal identity, request permission, and continue only the independently approved work.
