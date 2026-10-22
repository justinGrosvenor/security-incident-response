# Validation record

Candidate reviewed on 2026-10-22. This is evidence about the workflow and helper within exercised cases, not proof of exhaustive detection, host integrity or universal platform support.

## Independent evaluations

Three fresh agents separately evaluated consent boundaries, static scanner behavior, and incident/artifact reasoning. They used isolated fixtures and preserved reproducible commands, outputs, source hashes and audit logs outside the distributable package. They did not inspect developer projects, execute suspect packages or change live systems for these evaluations. The incident evaluator also consulted current public primary notices.

A fourth fresh agent reviewed all distribution files, ran the shipped suite independently and tested the documented metadata recipes. It reproduced credential leakage from raw remote URL listings and configured external-program execution during native Git metadata commands. Both were corrected by removing native Git commands and shell-definition listings from initial discovery, requiring static identity inspection until execution trust is assessed, and sanitizing remote identity before output. Its final review found no remaining material defect within its reviewed scope; it did not independently reproduce every prior evaluator's result.

A fifth fresh agent reviewed the MIT-licensed distribution and archive, confirmed byte equality, privacy and link checks, ran the suite on Python 3.9.6 and 3.14.6, and passed six additional isolated boundary/CLI probes. It found no material defect in the reviewed scope. Python 3.9.6 was a compatibility test, not a recommended inspection runtime. Separately, release inventory exposed a real registry-namespace identity mismatch; the incident profile guidance now explicitly separates a local package name from registry ownership and requires provenance/control checks before dependent install or publish actions.

Two additional fresh agents evaluated the PHP procedure. A primary-source reviewer checked engine/SAPI distinctions, distributor backports, static Composer inspection and activation safety. Its recommendations added effective Composer path selection, a conditional PHP persistence checklist, and audit-policy/source visibility; follow-up review confirmed all three resolved with no remaining finding in that scope.

The other agent assessed six approved synthetic PHP projects and left a seventh pending project unread. Cases covered a patched CLI with old FPM despite a clean Composer audit/platform override, an exact vendor backport that did not cover a different package revision, an embedded interpreter without host PHP, conflicting lock/installed metadata and a compromised download record, old live workers after an on-disk update, and unresolved mutable/development images. It preserved artifact-match versus execution distinctions and separate patch/activation approvals. No PHP, Composer, container or network execution occurred, no sentinel ran, and no real installation was assessed. Final reference hashes and private evaluation receipts identify the reviewed snapshot. These were behavioral procedure evaluations, not executable PHP scanning tests.

Two further fresh agents evaluated Node/Brotli coverage. A primary-source review checked inbound middleware, outbound automatic decompression, remote image fetching, direct decoder APIs and separately linked/embedded consumers. Corrections preserved already granted authorization and restricted malformed regression fixtures to isolated patched instances. Final review also checked the incident-cluster description and certificate-trust motivation without implying that the CA incident caused unrelated runtime vulnerabilities.

A separate behavioral evaluation assessed seven approved synthetic projects and left an eighth pending project unread. Cases included parsers before authentication, outbound decoding despite inbound controls and an identity request header, image-response encoding chains, offline aliases/converters, encoding-only negative paths, separate embedded/native consumers, a verified patch with an unchanged library version string, and an old running deployment despite a patched build. Final documents and an additional image-response evidence file were re-read after intentional maintainer revisions; original/final hashes preserve that change rather than claiming an immutable initial snapshot. No JavaScript, Node, package manager, container, exploit or network execution occurred and no sentinel ran. No material defect remained within the exercised procedure scope; this does not verify any real runtime, deployment or historical compromise.

A subsequent live catalogue reconciliation reproduced two feed blind spots: default GitHub queries omit unreviewed/malware categories, and some primary runtime notices remain absent across those categories. Fully paginated category queries and direct vendor-ID comparison supported a focused workflow correction. Published versus modified dates, source classification, CVE versus malware counts, and catalogue versus project-assessment status remain explicit. This was a read-only public-feed check, not a new project exposure assessment; the earlier fresh-agent evaluations predate this correction.

Initial reviews found material issues, which were fixed and retested:

- Recursion could cross a nested project boundary. The workflow now requires boundary preflight, explicit exclusions and independent approvals. The helper reports common nested markers and skips them pending explicit roots.
- Root aliases could resolve to a different target after approval. The workflow records/rechecks canonical identity; `--expected-root` rejects a changed canonical target before metadata reads. Same-path inode checks remain the agent's responsibility.
- Default filters silently skipped plausible installation targets. Those filters were removed; declared Git internals remain excluded, and directory symlinks/exclusions are reported.
- Startup discovery missed package-form and compiled customization modules. Source, bytecode, native-shaped and package forms are now included as leads.
- Empty/duplicate identity headers and missing metadata could appear successful. These now produce explicit incomplete-coverage errors. Legacy flat metadata is supported.

Retests found no remaining material defect in the exercised cases. Consent evaluation passed 13 checks, with audit logs checking that excluded descendant metadata was not opened. Incident evaluation covered ten approved synthetic projects plus pending/skipped cases, preserving distinctions among installed, locked, builder, historical, image and running-runtime evidence. Metadata alone remained insufficient for execution/provenance conclusions.

## Shipped regression suite

`tests/test_inventory_python.py` contains 12 tests and invokes the helper 15 times per complete run. Maintainer runs passed with zero failures/errors/skips on macOS arm64 using Python 3.10.21, 3.11.16, 3.12.14, 3.13.15 and 3.14.6. The suite covers supported metadata formats, installation layouts, startup forms, malformed metadata, special files, nested boundaries, explicit exclusions, root retargeting, missing roots and non-execution sentinels.

The same suite also passed on Linux arm64 in an official Python 3.14.9 image, pinned by digest, with no network, a read-only skill mount, no capabilities, an unprivileged user and temporary synthetic fixtures. These are six tested interpreter/platform combinations, not a claim of universal portability.

The evaluated helper SHA256 is:

```text
ec3a0958d8350a0d2f8ee4dab251f7c66e815b82407eb5343afe391e4edbcb15
```

Re-run the suite after changes. Local detailed receipts contain paths and are intentionally not bundled. The skill structure and local reference links are also checked separately.

## Important limits

- These tests do not establish Windows behavior, every package layout, or every filesystem race. Use a trusted maintained interpreter; tested version numbers are not security recommendations.
- Sentinel tests show that these exercised helper paths did not execute hooks. They do not validate a suspect interpreter, host, native library or operating system.
- Permission decisions, canonical inode checks and project identification remain agent workflow controls. The helper is not a sandbox or a proof that user consent exists. A directory-name heuristic cannot identify every independent project.
- The helper performs static Python metadata/startup discovery. Other ecosystems, archives, container layers, CI, process history, persistence, credentials and actual runtime behavior require the separate approved investigations described in the skill.
- A clean inventory or passing regression suite does not establish absence of compromise. Incident sources and indicators must be refreshed for each use.
