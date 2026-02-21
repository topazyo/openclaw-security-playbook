---
title: Runtime Sandboxing Guide
layer: 3
estimated_time: 45 minutes
difficulty: Intermediate
---

# Runtime Sandboxing Guide

**Layer 3 of 7-Layer Defense-in-Depth Model**

**Estimated Time:** 45 minutes  
**Difficulty:** Intermediate  
**Prerequisites:** Docker experience, Linux container knowledge

This guide covers container-based sandboxing to limit the blast radius of compromised AI agents.

## Table of Contents

1. [Why Runtime Sandboxing](#why-runtime-sandboxing)
2. [Docker Security Hardening](#docker-security-hardening)
3. [Capability Dropping](#capability-dropping)
4. [Filesystem Restrictions](#filesystem-restrictions)
5. [Resource Limits](#resource-limits)
6. [Seccomp and AppArmor](#seccomp-and-apparmor)
7. [Rootless Containers](#rootless-containers)
8. [Testing and Verification](#testing-and-verification)

---

## Why Runtime Sandboxing

### Threat Model

Even with credential isolation and network segmentation, assume breach:
- **Prompt injection succeeds** → Agent executes malicious code
- **Dependency vulnerability** → Arbitrary code execution
- **Supply chain attack** → Malicious skill installed

**Goal:** Limit damage through containment

### Container Security Principles

```
┌────────────────────────────────────┐
│     Host System (Unrestricted)      │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   Container (Sandboxed)       │  │
│  │                               │  │
│  │  ✅ Can: Read allowed files   │  │
│  │  ✅ Can: Network localhost    │  │
│  │  ❌ Cannot: Write filesystem  │  │
│  │  ❌ Cannot: Access /proc      │  │
│  │  ❌ Cannot: Load kernel mods  │  │
│  │  ❌ Cannot: Raw network       │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
```

---

## Docker Security Hardening

### Production-Ready Docker Run Command

```bash
docker run -d \
  --name clawdbot-production \
  \
  # Capabilities (DROP ALL, add only necessary)
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  \
  # Filesystem (read-only root, tmpfs for temp files)
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /var/run:rw,noexec,nosuid,size=10m \
  \
  # Volume mounts (minimum required, read-only where possible)
  -v ~/.openclaw/config:/app/config:ro \
  -v ~/.openclaw/skills:/app/skills:ro \
  -v ~/.openclaw/logs:/app/logs:rw \
  \
  # Network (localhost only)
  --network=none \  # No network access
  # OR for localhost access:
  # -p 127.0.0.1:18789:18789 \
  \
  # Security options
  --security-opt no-new-privileges \
  --security-opt seccomp=openclaw-seccomp.json \
  --security-opt apparmor=openclaw-apparmor \
  \
  # Resource limits
  --memory=2g \
  --memory-swap=2g \
  --cpus=2.0 \
  --pids-limit=100 \
  \
  # User (non-root)
  --user 1000:1000 \
  \
  # Other security
  --log-driver=json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  \
  anthropic/clawdbot:latest
```

**Each option explained below...**

---

## Capability Dropping

### Linux Capabilities Overview

Linux capabilities split root privileges into discrete units:

| Capability | Allows | Needed by ClawdBot? |
|------------|--------|---------------------|
| CAP_NET_BIND_SERVICE | Bind ports < 1024 | Maybe (if port < 1024) |
| CAP_NET_ADMIN | Network configuration | ❌ No |
| CAP_SYS_ADMIN | Mount, kernel modules | ❌ No |
| CAP_SYS_PTRACE | Debug other processes | ❌ No |
| CAP_DAC_OVERRIDE | Bypass file permissions | ❌ No |
| CAP_SETUID | Change UID | ❌ No |
| CAP_SETGID | Change GID | ❌ No |

### Drop All Capabilities

```bash
# Default (insecure)
docker run --cap-add ALL ...  # ❌ DANGEROUS

# Secure baseline
docker run --cap-drop ALL ...  # ✅ SECURE

# Add only if needed (port 80/443)
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE ...
```

### Verify Dropped Capabilities

```bash
# Inside container
docker exec clawdbot-production capsh --print

# Expected output:
# Current: =
# Bounding set =cap_net_bind_service
```

---

## Filesystem Restrictions

### Read-Only Root Filesystem

**Problem:** Writable filesystem allows:
- Downloading malicious binaries
- Modifying application code
- Persisting backdoors

**Solution:** Make root filesystem read-only

```bash
docker run --read-only ...
```

**Required writable areas:**
- `/tmp` — Temporary files
- `/var/run` — PID files, sockets
- `/app/logs` — Application logs

**Solution:** Use tmpfs (memory-only, no persistence)

```bash
--tmpfs /tmp:rw,noexec,nosuid,size=100m \
--tmpfs /var/run:rw,noexec,nosuid,size=10m
```

**tmpfs Options:**
- `rw` — Read-write
- `noexec` — Cannot execute binaries (prevents downloading exploits)
- `nosuid` — Cannot use SUID binaries
- `size=100m` — Limit to 100MB (prevents memory exhaustion)

### Volume Mount Security

**Insecure volume mounts:**
```bash
# ❌ DANGEROUS: Full home directory access
-v ~:/home/user:rw

# ❌ DANGEROUS: Docker socket access (container escape)
-v /var/run/docker.sock:/var/run/docker.sock
```

**Secure volume mounts:**
```bash
# ✅ SECURE: Specific directory, read-only
-v ~/.openclaw/config:/app/config:ro

# ✅ SECURE: Skills directory, read-only
-v ~/.openclaw/skills:/app/skills:ro

# ✅ SECURE: Logs only, writable
-v ~/.openclaw/logs:/app/logs:rw,nosuid,nodev

# ✅ SECURE: Credentials via OS keychain (no volume)
# (Use keychain integration instead of mounting secrets)
```

### Test Filesystem Restrictions

```bash
# Try to write to root (should FAIL)
docker exec clawdbot-production touch /test.txt
# Expected: touch: cannot touch '/test.txt': Read-only file system

# Try to write to tmpfs (should SUCCEED)
docker exec clawdbot-production touch /tmp/test.txt
# Expected: Success (no output)

# Try to execute from tmpfs (should FAIL due to noexec)
docker exec clawdbot-production sh -c 'echo "#!/bin/sh\necho pwned" > /tmp/exploit.sh && chmod +x /tmp/exploit.sh && /tmp/exploit.sh'
# Expected: Permission denied
```

---

## Resource Limits

### Prevent Resource Exhaustion

**Attacks prevented:**
- Fork bombs (unlimited process creation)
- Memory exhaustion (OOM crashes host)
- CPU exhaustion (denial of service)

### Memory Limits

```bash
# Limit memory to 2GB
--memory=2g \
--memory-swap=2g \       # Same as memory = no swap
--memory-reservation=1g    # Soft limit
```

**Test memory limit:**
```bash
# Inside container (should FAIL at 2GB)
docker exec clawdbot-production stress --vm 1 --vm-bytes 3G
```

### CPU Limits

```bash
# Limit to 2 CPU cores
--cpus=2.0 \

# OR limit CPU shares (relative)
--cpu-shares=512  # 50% of default (1024)
```

### Process Limits

```bash
# Limit to 100 processes (prevents fork bombs)
--pids-limit=100
```

**Test process limit:**
```bash
# Fork bomb (should be blocked at 100 processes)
docker exec clawdbot-production bash -c ':(){ :|:& };:'
# Container should remain stable
```

### Disk I/O Limits

```bash
# Limit read/write operations
--device-read-bps /dev/sda:10mb \
--device-write-bps /dev/sda:10mb
```

---

## Seccomp and AppArmor

### Seccomp (System Call Filtering)

**What is Seccomp?**
Secure Computing Mode filters system calls at kernel level.

**Create custom seccomp profile:**

```json
// openclaw-seccomp.json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        // File operations
        "read", "write", "open", "openat", "close", "stat",
        "fstat", "lstat", "lseek", "access", "dup", "dup2",

        // Networking (minimal)
        "socket", "connect", "sendto", "recvfrom", "bind",
        "listen", "accept", "getsockname", "getpeername",

        // Process management
        "execve", "fork", "clone", "wait4", "exit", "exit_group",

        // Memory
        "mmap", "munmap", "mprotect", "brk",

        // Time
        "clock_gettime", "gettimeofday"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      // Block dangerous syscalls
      "names": [
        "mount", "umount", "pivot_root",  // Filesystem manipulation
        "reboot", "swapon", "swapoff",    // System control
        "create_module", "init_module"     // Kernel modules
      ],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

**Apply seccomp profile:**
```bash
docker run \
  --security-opt seccomp=openclaw-seccomp.json \
  ...
```

### AppArmor Profile

**Create AppArmor profile:**

```bash
# /etc/apparmor.d/openclaw-profile

#include <tunables/global>

profile openclaw flags=(attach_disconnected, mediate_deleted) {
  #include <abstractions/base>

  # Allow reading config
  /app/config/** r,
  /app/skills/** r,

  # Allow writing logs
  /app/logs/** rw,

  # Allow network (localhost only)
  network inet stream,
  network inet6 stream,

  # Deny dangerous operations
  deny /proc/sys/** w,
  deny /sys/** w,
  deny /dev/** w,
  deny /boot/** rw,

  # Deny execution from temp
  deny /tmp/** x,
  deny /var/tmp/** x,
}
```

**Load and apply:**
```bash
# Load profile
sudo apparmor_parser -r /etc/apparmor.d/openclaw-profile

# Apply to container
docker run \
  --security-opt apparmor=openclaw-profile \
  ...
```

---

## Rootless Containers

### Why Rootless?

**Problem with root-in-container:**
- Root inside container = root on host (if escape)
- Privilege escalation vectors
- Kernel vulnerabilities affect both

**Solution:** Run as non-root user

### Configure Non-Root User in Dockerfile

```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r openclaw && useradd -r -g openclaw openclaw

# Create directories owned by openclaw user
RUN mkdir -p /app/config /app/skills /app/logs && \
    chown -R openclaw:openclaw /app

# Install dependencies as root
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application as openclaw user
COPY --chown=openclaw:openclaw . /app/

# Switch to non-root user
USER openclaw

# Run application
WORKDIR /app
CMD ["python", "clawdbot.py"]
```

### Run Container as Specific UID

```bash
# Run as specific user (UID 1000)
docker run --user 1000:1000 ...

# OR use username from container
docker run --user openclaw:openclaw ...
```

### Rootless Docker (Advanced)

**Install rootless Docker:**

```bash
# Install rootless Docker
curl -fsSL https://get.docker.com/rootless | sh

# Configure systemd service
systemctl --user enable docker
systemctl --user start docker

# Set environment
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock

# Test
docker run --rm hello-world
```

**Benefits:**
- Docker daemon runs as non-root
- Containers cannot access host root resources
- Improved security isolation

---

## Testing and Verification

### Baseline Hardening Verification

```bash
docker inspect clawdbot-production \
  --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} PidsLimit={{.HostConfig.PidsLimit}}'
```

**Verify:** Expected output:
```text
User=1000:1000 ReadOnly=true CapDrop=[ALL] PidsLimit=100
```

### Security Test Suite

```bash
#!/bin/bash
# test_sandbox_security.sh

echo "=== Docker Security Test Suite ==="

# Test 1: Root filesystem write
echo "[Test 1] Root filesystem write (should FAIL)"
docker exec clawdbot-production touch /test.txt && echo "❌ FAIL: Can write to root" || echo "✅ PASS: Root is read-only"

# Test 2: Execute from tmpfs
echo "[Test 2] Execute from tmpfs (should FAIL)"
docker exec clawdbot-production sh -c 'echo "#!/bin/sh" > /tmp/test.sh && chmod +x /tmp/test.sh && /tmp/test.sh' && echo "❌ FAIL: Can execute from tmpfs" || echo "✅ PASS: tmpfs is noexec"

# Test 3: Capability check
echo "[Test 3] Capabilities (should show minimal)"
docker exec clawdbot-production capsh --print | grep "Current: ="

# Test 4: Process limit
echo "[Test 4] Process limit"
docker exec clawdbot-production sh -c 'for i in {1..150}; do sleep 1000 & done; wait' && echo "❌ FAIL: No process limit" || echo "✅ PASS: Process limit enforced"

# Test 5: Memory limit
echo "[Test 5] Memory limit (2GB)"
docker exec clawdbot-production stress --vm 1 --vm-bytes 3G --timeout 5s && echo "❌ FAIL: No memory limit" || echo "✅ PASS: Memory limit enforced"

# Test 6: Network isolation
echo "[Test 6] Network access"
docker exec clawdbot-production curl -s http://example.com && echo "⚠ WARN: Has internet access" || echo "✅ PASS: Network isolated"

# Test 7: User check
echo "[Test 7] User (should be non-root)"
USER_ID=$(docker exec clawdbot-production id -u)
if [ "$USER_ID" -eq 0 ]; then
  echo "❌ FAIL: Running as root"
else
  echo "✅ PASS: Running as UID $USER_ID"
fi

echo "=== Test Complete ==="
```

---

## Docker Compose Configuration

For multi-container deployments:

```yaml
# docker-compose.yml

version: '3.8'

services:
  clawdbot:
    image: anthropic/clawdbot:latest
    container_name: clawdbot-production

    # User
    user: "1000:1000"

    # Capabilities
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

    # Security options
    security_opt:
      - no-new-privileges:true
      - seccomp:./openclaw-seccomp.json
      - apparmor:openclaw-profile

    # Filesystem
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=100m
      - /var/run:rw,noexec,nosuid,size=10m

    # Volumes
    volumes:
      - ./config:/app/config:ro
      - ./skills:/app/skills:ro
      - ./logs:/app/logs:rw

    # Network
    ports:
      - "127.0.0.1:18789:18789"

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
          pids: 100
        reservations:
          cpus: '1.0'
          memory: 1G

    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:18789/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

    # Logging
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

    # Restart policy
    restart: unless-stopped
```

---

## Best Practices

1. **Always drop all capabilities first**
   - Start with `--cap-drop ALL`
   - Add back only what's needed

2. **Read-only root filesystem**
   - Use `--read-only`
   - tmpfs for writable areas

3. **Run as non-root**
   - Create dedicated user in Dockerfile
   - Use `--user` flag

4. **Resource limits**
   - Memory, CPU, process limits
   - Prevents DoS attacks

5. **Regular security audits**
   - Run test suite weekly
   - Update base images monthly
   - Review seccomp/AppArmor profiles

---

## Related Guides

- **Quick Start:** [01-quick-start.md](01-quick-start.md)
- **Network Segmentation:** [03-network-segmentation.md](03-network-segmentation.md)
- **Supply Chain Security:** [05-supply-chain-security.md](05-supply-chain-security.md)
- **Community Tools (openclaw-shield):** [07-community-tools-integration.md](07-community-tools-integration.md)

---

**Last Updated:** February 14, 2026  
**Tested On:** Docker 24.0+, Ubuntu 22.04+, AppArmor 3.0+
