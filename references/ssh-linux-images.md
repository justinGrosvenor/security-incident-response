# SSH servers and Linux images

Use the main workflow's project and shared-service permissions. A Dockerfile change, a rebuilt image and a replaced running service are separate outcomes. An Alpine base is an inventory lead, not proof of an SSH exposure.

## Build the incident profile

Refresh the OpenSSH, C-library and distribution maintainers' advisories. Record the identifier, affected platforms, server builds, authentication prerequisites and fixed distribution revisions. An advisory can predate its CVE assignment. Distribution backports can fix an upstream version number that still looks old.

For the November 2026 OpenSSH/musl incident, consult the [OpenSSH release notes](https://www.openssh.org/releasenotes.html#10.6p2), [musl maintainer](https://www.openwall.com/lists/musl/2026/11/05/4), [Alpine advisory](https://www.alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/) and [current CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-123158). Fetch current values rather than treating this reference as a fixed version allowlist. This is an authentication defect; affected software alone does not establish attacker access.

## Trace the server and authentication path

- Inspect every relevant builder, final image, guest-image script, startup installer and deployed digest. Read package databases and image layers statically before considering execution. `openssh-client`, an SSH build mount and a private Git checkout do not by themselves install or start `sshd`. Dropbear is a separate implementation.
- Establish the actual server executable, libc, distribution revision, service startup and network reachability. `EXPOSE 22` is neither necessary nor sufficient: check alternative ports, host networking, forwards, security groups and private-network access. No public port 22 does not exclude internal exposure.
- Resolve authentication settings through includes and `Match` clauses. Missing included files or untested connection contexts leave effective policy unresolved. If the executable is trusted and execution is approved, validate configuration with `sshd -t`; inspect effective settings with `sshd -T` and representative connection contexts using `-C`. A global default does not clear a conditional override. A server built without PAM may omit the `UsePAM` setting entirely.
- Where the advisory requires account-state checks, report only account names and relevant field categories. Do not emit password hashes or full shadow files. Directory-service accounts can be absent from local shadow data; an incomplete account inventory leaves that prerequisite unknown. A user who normally logs in with a key can still have password authentication enabled on the server.
- Assess direct root login separately from a non-root account's escalation rights. Respect platform exclusions stated by maintainers; do not generalize a musl-specific OpenSSH defect to macOS, glibc or every program using musl.

## Refresh images and preserve access

Use the distribution's maintained correction for the existing branch where available. Compare exact APK revisions against the vendor's fixed revision, not an upstream-only version threshold. An emergency backport for an obsolete branch does not restore general support; track migration separately.

When preventive updates are requested, cover Alpine stages without SSH as well, while labeling them preventive. Preserve application versions, architecture, image variants, non-root execution and benchmark configuration unless a compatibility-reviewed change is needed. Confirm that inherited images actually provide APK and that the refresh runs with sufficient privileges. Avoid a cached pre-fix package layer; a new source line or mutable tag alone does not prove which packages were built. Never install a server just to test for its presence.

For live SSH changes, first verify working key access and a recovery channel; keep the current session open. Validate configuration before an authorized reload/restart. After replacement, confirm the active daemon/package and test a new legitimate key session. Do not test an authentication bypass against production. Host scan-only permission does not authorize changing authentication, restarting services or launching containers.

## Verify and investigate access

Inspect the exact rebuilt/deployed artifact's package database and server configuration, then confirm running replacement and health. Keep dormant images, unavailable engines, inaccessible logs and uninspected guests in the pending ledger.

State how runtime evidence was obtained and when. A supplied inventory snapshot can support a conclusion about that snapshot; it does not establish present live activation, a successful legitimate login or historical non-exploitation. Reserve a live-verification claim for the actual checks performed.

If the advisory recommends log review, correlate successful password logins with account state at the event time, escalation and key/user changes. Current account state alone cannot reconstruct historical state, and missing logs do not prove non-exploitation. Preserve evidence before cleanup. Credible unauthorized access requires the main workflow's containment, clean recovery and scoped credential response; upgrading a package does not undo a compromise.
