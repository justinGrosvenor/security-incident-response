# Response workflow

Use the phases that match the incident. Confirmed compromise warrants containment before broad inventory; a rumor without exposure does not justify wiping machines or rotating an entire organization.

## 1. Establish a trustworthy investigation path

Record date/time zone and public incident scope. Discover project candidates using minimal filesystem identity and process metadata. Before opening project contents or environments, ask for its independent scan-only / scan-and-patch-locally / skip decision and wait. Read repository instructions only after project approval. Maintain an approval ledger: project/path, requested actions, decision, time, exclusions. Host-wide/global inspections need their own permission. A broad initial request does not waive this checkpoint. This per-project permission step is an explicit requirement of this skill.

Within approved scope identify active branches, CI, registries, cloud accounts/regions, deployments, and managed services. Obtain context from authorized connected services. Preserve dirty work and incident evidence. If repository identity and running process paths cannot be mapped without reading project files, report uncertain candidates and ask instead of silently expanding discovery.

Choose tools that do not run suspect project startup hooks. Do not begin a Python supply-chain investigation with `pip list`, `pip show`, a normal interpreter, a notebook kernel, a project CLI, or an agent importing the suspect environment. A `.pth` file may execute before a package is imported. Uninstalling via an affected interpreter can trigger it too.

If a credible clean inspection path is unavailable, report that scope as blocked and obtain a clean device/tooling path rather than executing suspect tools to prove themselves safe. Do not equate interpreter isolation flags with host integrity.

Use trusted shell/file utilities or a known-clean interpreter. Complete canonical-root and nested-boundary preflight from the scan recipes first. For metadata-only inspection:

```sh
/path/to/trusted/python3 -I -S /path/to/security-incident-response/scripts/inventory_python.py \
  --expected-root /approved/canonical/project /approved/canonical/project > python-metadata.json
```

Select and verify the interpreter; replace the example paths. `-I` ignores Python environment variables and the working directory; `-S` skips site initialization. These flags are not a sandbox and do not protect against a malicious interpreter, native library, shell, OS, or script. The scanner reports directory symlinks, nested project boundaries, exclusions and access/metadata errors. Exit 2 means incomplete coverage, including intentional exclusions. Add external environments only after separate approval. Its output contains local paths and is not a clearance certificate. It does not defend against hostile concurrent filesystem replacement; investigate a suspect live host from an appropriately clean/offline boundary.

Record artifact hashes, timestamps where useful, install logs, lockfiles, image digests, CI runs, and the exposure window. Keep evidence local with restricted permissions. Do not print `.env`, credentials, secret store values, or entire task definitions.

## 2. Verify what happened

Consult vendor releases, maintainer incident reports, registry advisories, RustSec/OSV, certificate root program incident trackers, and CISA KEV as applicable. Search the recent interval explicitly, including corrections and related disclosures. Use pagination correctly and deduplicate identifiers. A feed count describes that feed and interval, not the entire security landscape.

For each relevant announcement record the primary URL, publication/update/event dates and research timestamp; affected artifacts and exact version ranges/digests; published maintained fix or mitigation; attack prerequisites; whether exploitation is known or demonstrated; local evidence and its limits; and a verification plan.

Separate vendor statements from observed facts. Do not amplify "all of PyPI is compromised" from a package-specific incident. An upstream source tag can be clean while published wheels/images are malicious. An old vulnerable dependency does not prove execution or compromise.

## 3. Map the exposure surface

Correlate these layers:

| Layer | Useful evidence | Common blind spot |
| --- | --- | --- |
| Developer host | OS build, executable path/version, app signature, running process | Updated executable with old processes still running |
| Source | Manifests, exact locks, configuration, generated artifacts, feature use | Docs and optional peers mistaken for installed dependencies |
| Environments | Distribution metadata, user/global sites, venvs, tool environments, caches | One patched venv while another remains active |
| CI/build | Runner image, setup actions, runtime pins, cache provenance, logs | Patched final container with vulnerable builder |
| Packages | Version, exact tarball/hash, bundled/native assets, provenance | Engine field raised without updating consumers |
| Deployments | Digest, architecture, OS package revision, linked libs, task/process | Mutable tag or source lock treated as deployed proof |
| Managed services | Account use, provider notice, logs, credential reachability | Vendor breach conflated with an open-source vulnerability |
| Trust paths | Client settings, CA bundle, revocation, proxy, app TLS probe | Browser protection assumed to cover every client |

Useful bounded searches on selected roots:

```sh
rg --no-config --files --hidden -g '!**/.git/**' -g '!**/node_modules/**' -g '!**/target/**' \
  -g 'package.json' -g '*lock*' -g '*requirements*.txt' -g 'pyproject.toml' \
  -g 'Dockerfile*' -g '*.yml' -g '*.yaml' -g 'Cargo.toml'
```

Do not run every discovered project executable merely to inventory it. Read metadata first if the runtime may be suspect. Record permission errors and omitted roots. Deduplicate worktrees by repository while retaining different lock/build configurations. Distinguish active projects, historical copies, dormant deployments, and third-party fixtures.

Use static filesystem metadata for initial repository identity. Native Git metadata commands can execute configured programs: status may invoke a filesystem monitor, and log may invoke a signature verifier. Do not run project Git commands in the suspect-tooling preflight; assess configuration and execution trust first. Static worktree/ref/config inspection must stay within approved roots; a pointer into shared metadata outside them needs its own scope permission. Later authorized Git operations require reviewed execution/configuration settings rather than an assumption that a metadata command is harmless.

Remote URLs can contain credentials. Never print `git remote -v`, raw Git config, or unsanitized remote URL values. If remote identity is needed, capture and statically parse it inside trusted inspection code, removing credential-bearing components before any output. Shell alias/function listings can also contain inline credentials; inspect trusted executable paths without dumping definitions. Use the approved local path as identity when safe remote/tool identity cannot be obtained.

Match versions with ecosystem rules, never lexicographic comparison. npm semver and Python PEP 440 differ; distro backports may not change the upstream version. Check distro security changelogs/package revisions before declaring a distro binary fixed or vulnerable.

Do not infer cloud clearance from one region/account. Record accounts, regions, clusters, projects, and organizations actually checked. Inspect identifiers/runtime fields without dumping secrets. Include desired-zero services as rebuild/startup risks.

## 4. Choose the correct response

### Malicious artifact execution

If evidence indicates the compromised artifact was installed/executed, follow vendor guidance and the organization's incident response process. Isolate the affected machine/workload as authorized, stop sensitive work there, preserve evidence, and recover from a clean device. An agent on the suspect host cannot establish a clean recovery boundary by itself.

Record credentials reachable during exposure: cloud/registry tokens, GitHub/CI credentials, SSH keys/agents, application secrets, databases, browser sessions, and signing material as relevant. Revoke exposed credentials/sessions promptly from a clean device, then replace them through approved controls. Do not delay critical revocation solely to finish inventory. Rebuild affected hosts/environments from trusted sources; review locks/artifacts and audit logs/persistence. Removing package/marker files alone does not undo stolen credentials or establish eradication.

Avoid blanket rotations with no exposure basis. Do not request secrets in chat, destroy evidence first, or reuse suspect caches in a rebuild.

### Vulnerable dependency or runtime

Prioritize reachable production critical/high issues, public developer servers, and tools processing untrusted files. Patch within the current maintained major when possible; assess compatibility when the fix requires a major. Include transitive dependencies, runtime pins, CI, builders, final images, and native libraries. Do not force incompatible overrides merely to reach a zero audit count.

Inspect release metadata, provenance/signatures where available, hashes, yanked status, and source. A hash from the compromised release channel proves identity, not independent trust. A valid signature can belong to a compromised publisher. Do not install unreviewed scanners or pipe incident-related install scripts into a shell.

Use the existing package manager/lock format. Review unrelated changes and lifecycle scripts. Fresh environments can repair drift, but do not erase user environments without need. Check Python dependency compatibility; API/SDK families may require aligned versions. For Rust, update every affected resolved version; a compatibility wrapper may re-export an older locked trust store.

When no fix exists, record reachable impact, mitigation/isolation options, and a tracking item. Never call an unresolved audit clean. Development-only dependencies still matter when dev servers, CI parsers, or builds process untrusted input.

### Certificate compromise

Trace actual outbound verification. Update the applicable runtime, verifier, CA roots, revocation/block list, and deployed binary. Inspect trust overrides and relevant variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`) without printing other secrets. Verify precedence rather than assuming every client honors a variable.

Use the incident matching appendix's trust procedure and current primary research canaries or public chain fixtures. Root deletion may miss a cross-signed path; revoked intermediates do not help clients that skip revocation. Browser block lists do not rewrite Rust/gRPC bundles. Do not broadly remove roots without reviewing official remediation and legitimate-service impact.

Never fix trust with `curl -k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False`, disabled hostname checks, or equivalent settings.

### Vendor breach

Confirm actual service/account use, organizations, incident window, provider notices, and credential/data categories. Follow customer-specific guidance; separate unsupported claims. "No evidence of database access" is a bounded investigation result, not proof that no customer information was exposed.

## 5. Patch, validate, and land

Use a clean worktree from the intended remote target if the checkout is dirty or contains unrelated commits. Review the full PR diff. Do not hard-reset/stash user work without need. Preserve issue/review/CI requirements; waivers apply only to the stated scope.

Before deploying, establish the existing artifact's source/build provenance. A clean remote branch can be older than production when local commits or uncommitted files were previously built. Do not replace a running service with an older feature set merely to obtain a clean security diff. Reconstruct a reviewable matching baseline or report the provenance gap before dependent release work.

Run focused behavioral tests plus required checks. Prefer harmless upstream regressions. Avoid exploit execution against production. Check native ABI/FFI, startup, exports, generated artifacts, and integration behavior when affected. Compare broad-suite failures to a clean baseline where necessary and report both; do not relabel a failing check as passed.

Determine whether customers receive the affected implementation/trust store. Documentation/source floors alone may not require a package release; embedded code, native assets, or a changed runtime contract usually require a new artifact. Inspect/test the exact tarball/binary before authorized publication. Follow current staged approval, registry auth, or trusted publishing/OIDC; never bypass 2FA. A staging receipt is not publication. Verify registry bytes afterward.

For authorized deployment, rebuild with patched bases and reviewed integrity/version controls. Pull fresh bases and avoid suspect caches where relevant; pin the resulting digest. Source CI does not update a server. Record deployment/task revision and actual digest, wait for health, inspect running runtime/library versions, and repeat security probes. Keep rollback data protected; do not silently roll back to the vulnerable artifact. Respect production controls.

Use real transaction harnesses when authorized, with cost limits/idempotency. Report external blockers precisely. An API-credit rejection is neither a security regression nor a passed transaction. Do not retry paid traffic indefinitely.

## 6. Hand off

Use the reporting contract. Provide an ordered developer checklist: update/relaunch host tools, inspect their own environments, patch source+CI+artifacts, verify deployments, and record exceptions. Every developer needs an individual assessment; another machine's negative scan does not clear theirs.

Refresh the ledger as announcements change. This procedure alone does not authorize recurring monitoring, messages to coworkers, public publication, or access to new organizations.
