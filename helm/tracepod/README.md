# Tracepod Helm Chart

Deploys the Tracepod eBPF sensor as a Kubernetes DaemonSet. The sensor attaches kprobes
to `openat`, `execve`, and `mmap` and records every file a container touches at runtime,
producing a JSON manifest used by the `harden` CLI to build minimised OCI images.

> **Important:** Only containers started through Kubernetes (kubelet → containerd) are
> profiled. Containers started with `docker run`, `nerdctl run`, or `docker-compose` are
> silently ignored — they do not go through the NRI interface the sensor uses.

## Modes

| Mode | When | How profiles are stored |
|------|------|------------------------|
| **Standalone** | `sensor.controllerURL` is empty (default) | Written to each node's disk via hostPath at `sensor.profileHostPath` |
| **Controller** | `sensor.controllerURL` points to the Tracepod controller | POSTed to the controller API at container stop |

Standalone mode is the default. It requires no additional infrastructure — profiles land
at `/var/lib/tracepod/profiles/<container-id>/files.json` on each node.

## Before you install: verify NRI is enabled

**NRI is required.** Without it the sensor will start and show no errors, but no containers
will ever be profiled.

```bash
# Check NRI configuration on each node:
grep -E "^\s*disable\s*=" /etc/containerd/config.toml | grep nri
# Should return:  disable = false
# (or be absent — NRI is enabled by default in containerd 2.x)
```

If NRI is disabled or missing, add it:

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  disable_connections = false
  plugin_registration_timeout = "5s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
  state_dir = "/var/run/nri"
```

Restart containerd on each node:

```bash
sudo systemctl restart containerd
```

## Prerequisites

- Kubernetes ≥ 1.25
- Helm 3
- containerd runtime with NRI enabled (see above)
- cgroupv2 enabled on nodes (Ubuntu 22.04+ and most modern Kubernetes distributions default to cgroupv2)
- Cluster must allow `privileged: true` DaemonSet pods — see [Known constraints](#known-constraints)

## Install

```bash
helm install tracepod ./helm/tracepod \
  --namespace tracepod \
  --create-namespace
```

Wait for the DaemonSet to roll out:

```bash
kubectl -n tracepod rollout status daemonset/tracepod-sensor
```

Verify the sensor connected to NRI:

```bash
kubectl -n tracepod logs daemonset/tracepod-sensor | grep -E "NRI|tracking"
# Expected: "NRI connected" on startup, then "tracking  container=..." for each profiled container
```

## Values

| Value | Default | Description |
|-------|---------|-------------|
| `sensor.image.repository` | `ghcr.io/tracepod/tracepod-sensor` | Sensor container image |
| `sensor.image.tag` | `latest` | Image tag — pin to a release tag in production |
| `sensor.image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `sensor.controllerURL` | `""` | Tracepod controller URL; empty = standalone mode |
| `sensor.profileHostPath` | `/var/lib/tracepod/profiles` | Node-local path for profile output (standalone only) |
| `sensor.resources` | `{}` | Container resource requests/limits |
| `sensor.nodeSelector` | `{}` | Node selector for the DaemonSet |
| `sensor.tolerations` | `[]` | Tolerations — add entries to profile tainted nodes |
| `sensor.affinity` | `{}` | Affinity rules |

## Retrieving profiles (standalone mode)

After a container stops, the sensor writes its manifest to the node where the pod ran.

### Map container IDs to pod names

The sensor uses containerd's 64-character container ID as the directory name. Map it
to a pod name with:

```bash
kubectl get pods -A \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[*].containerID}{"\n"}{end}' \
  | sed 's|containerd://||g'
```

Or check the sensor logs — each tracked container is logged on start:

```bash
kubectl -n tracepod logs daemonset/tracepod-sensor | grep tracking
# sensor: tracking  container=abc123def456 cgroup=12345
```

### Copy the manifest

```bash
# Find the sensor pod on the node where your pod ran:
NODE=$(kubectl get pod <your-pod> -o jsonpath='{.spec.nodeName}')
SENSOR=$(kubectl -n tracepod get pod \
  -l app.kubernetes.io/name=tracepod-sensor \
  --field-selector spec.nodeName=$NODE \
  -o jsonpath='{.items[0].metadata.name}')

# List available profiles:
kubectl -n tracepod exec $SENSOR -- ls /profiles/

# Copy a profile to your local machine:
kubectl -n tracepod exec $SENSOR -- \
  cat /profiles/<container-id>/files.json > manifest.json
```

Profile paths inside the sensor pod use `/profiles/` (the `--profile-dir` mount).
The same data is on the node at `/var/lib/tracepod/profiles/<container-id>/files.json`.

### Build the hardened image

```bash
harden build \
  --manifest manifest.json \
  --source   <your-image-ref> \
  --output   /tmp/hardened

# Import into local Docker daemon:
skopeo copy oci:/tmp/hardened docker-daemon:myapp:hardened

# Or push directly to a registry during build:
harden build \
  --manifest manifest.json \
  --source   <your-image-ref> \
  --output   /tmp/hardened \
  --push     myregistry.com/myapp:hardened
```

## Troubleshooting

### Sensor starts but no profiles appear

1. **Check NRI is enabled** (most common cause):
   ```bash
   grep -E "^\s*disable\s*=" /etc/containerd/config.toml | grep nri
   # Must print: disable = false   (or be absent — enabled by default in containerd 2.x)
   ```

2. **Check the sensor connected to NRI:**
   ```bash
   kubectl -n tracepod logs daemonset/tracepod-sensor | head -20
   # Look for: NRI connected
   # Missing this line means NRI registration failed
   ```

3. **Were containers started via Kubernetes?**
   Only pods created by kubelet are profiled. `docker run` and `docker-compose` containers
   are not visible to the NRI interface.

4. **Did the container stop yet?**
   Profiles are written when the container stops, not while running.

5. **Is the sensor tracking the container?**
   ```bash
   kubectl -n tracepod logs daemonset/tracepod-sensor | grep tracking
   # If your container-id doesn't appear, the sensor missed the start event
   ```

## Upgrade

```bash
helm upgrade tracepod ./helm/tracepod --namespace tracepod
```

## Uninstall

```bash
helm uninstall tracepod --namespace tracepod
kubectl delete namespace tracepod
```

Profile data on node disks is **not** removed automatically. To clean up:

```bash
# On each node:
sudo rm -rf /var/lib/tracepod/profiles
```

## RBAC

The chart creates a ClusterRole and ClusterRoleBinding for the sensor's ServiceAccount
with the minimum permissions needed to resolve the pod → ReplicaSet → Deployment owner
chain (used when posting to the controller). In standalone mode these permissions are
present but unused.

| API group | Resource | Verbs |
|-----------|----------|-------|
| `""` (core) | `pods` | `get` |
| `apps` | `replicasets` | `get` |

## Known constraints

| Constraint | Detail |
|------------|--------|
| `privileged: true` required | Sensor pods need `CAP_SYS_ADMIN` for BPF kprobe attachment. Blocked by GKE Autopilot, Fargate, and PodSecurity `restricted` policy. |
| containerd + NRI only | The sensor integrates with containerd via NRI. CRI-O and standalone Docker are not supported. |
| cgroupv2 required | The BPF helper `bpf_get_current_cgroup_id()` returns cgroupv2 inodes. Ubuntu 22.04+ and most modern Kubernetes distributions default to cgroupv2. |
| CRI containers only | NRI hooks fire only for containers started through the Kubernetes CRI (kubelet → containerd). Containers started with `docker run` or `nerdctl run` are not profiled. |
| Profile data per-node | In standalone mode, profiles land on the node where the pod ran. Cross-node aggregation requires the controller. |

See [docs/KNOWN-LIMITATIONS.md](../../docs/KNOWN-LIMITATIONS.md) for the full sensor gap analysis.
