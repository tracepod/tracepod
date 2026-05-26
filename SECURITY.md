# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |
| older releases | Security fixes backported on request |

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report security issues via [GitHub private vulnerability disclosure](https://github.com/tracepod/tracepod/security/advisories/new).

Include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected versions (if known)

We aim to acknowledge reports within **2 business days** and provide an initial assessment
within **7 business days**.

## Security Considerations

Tracepod runs the sensor as a **privileged DaemonSet** (`privileged: true`, `hostPID: true`)
because it requires `CAP_BPF` and `CAP_SYS_ADMIN` to attach eBPF probes and read
`/proc/<pid>/cwd`. This is consistent with other eBPF-based observability tools (Tetragon,
Falco, Pixie).

Cluster administrators should:
- Restrict the sensor namespace to trusted operators via RBAC
- Review the ClusterRole in `helm/tracepod/templates/rbac.yaml` before deploying
- Treat sensor pod logs and manifests as potentially containing sensitive file paths

The hardener (`harden`) runs unprivileged on any machine with network access to your registry.
Manifests written by `tracepod profile get` contain full file-path lists and are written with
mode `0600` (owner-readable only).

## Licence

AGPL-3.0 — contributions to derived works must be released under the same licence.
