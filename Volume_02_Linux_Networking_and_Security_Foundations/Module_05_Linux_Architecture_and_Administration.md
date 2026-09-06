# Volume 02: Linux, Networking & Security Foundations
# Module 05: Linux Architecture, System Administration & Security Auditing

---

## 1. Learning Objectives

By completing this module, security practitioners, systems engineers, and penetration testers will be able to:
1. Deconstruct the Linux kernel architecture: detail the boundary between User Space (Ring 3) and Kernel Space (Ring 0), the System Call Interface (SCI), and Virtual File System (VFS) operations.
2. Audit Discretionary Access Control (DAC) models: evaluate standard octal permissions, special bits (SUID, SGID, Sticky bit), Access Control Lists (POSIX ACLs), and umask inheritance.
3. Analyze and configure Linux Extended Capabilities (`capabilities(7)`): deconstruct thread capability sets (Permitted, Effective, Inheritable, Bounding, Ambient) to decommission monolithic root privileges.
4. Interrogate runtime kernel state directly through the `/proc` and `/sys` pseudo-filesystems (memory mappings, file descriptor tables, kernel security toggles).
5. Audit system services and scheduled tasks: inspect `systemd` service unit security sandboxing (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`) and detect cron privilege-escalation vectors.
6. Assess authentication frameworks: deconstruct Pluggable Authentication Modules (PAM), `/etc/passwd`, `/etc/shadow` hash storage, and secure sudoer delegation policies.
7. Construct automated Bash and AWK auditing pipelines for continuous host hardening and forensic log interrogation.

---

## 2. Prerequisites & Technical Foundations

Before starting this module, students should understand:
* **Operating System Primitives**: CPU execution rings, page-based virtual memory, and process lifecycle states (covered in [Module 01](../Volume_01_Computer_and_Programming_Foundations/Module_01_Computer_Hardware_OS_and_Productivity.md)).
* **OS Lineage & Command-Line Foundations**: Unix/Linux historical evolution, FHS directory tree taxonomy, and Top 50 essential Linux commands (covered in [Windows & Linux OS Foundations, Directory Structures & Command Mastery](../Volume_01_Computer_and_Programming_Foundations/Windows_and_Linux_OS_Foundations_and_Command_Mastery.md)).
* **Basic Command-Line Proficiency**: Navigation (`cd`, `ls`), file inspection (`cat`, `less`), and basic standard input/output redirection (`|`, `>`, `<`).

---

## 3. What Is It?

**Linux System Architecture and Security Auditing** is the practice of evaluating, configuring, and verifying the security controls of the Linux operating system. Linux powers the vast majority of cloud infrastructure, internet routers, container platforms, and security toolsets.

Unlike Windows' centralized registry and object-centric architecture, Linux adheres to the Unix philosophy: **"Everything is a file"** and systems are composed of small, modular programs interacting via text streams and standard system calls.

A secure Linux posture is not achieved merely by applying vendor updates. It requires auditing the underlying kernel interfaces, file permissions, process execution boundaries, user privileges, and authentication chains to prevent privilege escalation and unauthorized access.

---

## 4. Deep Technical Architecture & Internals

### 4.1 Kernel and User Space Traversal

```
+-------------------------------------------------------------------------+
| USER SPACE (Ring 3)                                                     |
|                                                                         |
|   [ Application / Shell: /bin/bash ]                                    |
|             |                                                           |
|             v                                                           |
|   [ C Standard Library: glibc (open, read, write) ]                     |
+-------------|-----------------------------------------------------------+
              | Assembly Instruction: syscall (x86_64) / int 0x80 (x86)
              v
+-------------------------------------------------------------------------+
| KERNEL SPACE (Ring 0)                                                   |
|                                                                         |
|   [ System Call Interface (SCI) & Syscall Dispatch Table: sys_call_table] |
|             |                                                           |
|             v                                                           |
|   [ Virtual File System (VFS) Layer ] <-----> [ Security Modules (LSM) ]|
|      - Inode Cache                               - SELinux / AppArmor   |
|      - Directory Entry Cache (dentry)            - Capabilities Check   |
|             |                                                           |
|             v                                                           |
|   [ Concrete File System Drivers: ext4 / xfs / btrfs ]                  |
|             |                                                           |
|             v                                                           |
|   [ Block Device Layer & Storage Controller Drivers ]                    |
+-------------------------------------------------------------------------+
```

1. **System Call Interface (SCI)**:
   * When an unprivileged program in User Space requires hardware access, file I/O, or network communication, it cannot execute these instructions directly.
   * It populates CPU registers with the system call number (stored in `RAX` on x86_64) and arguments (`RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`), then triggers the `syscall` CPU instruction.
   * The CPU switches execution mode to Ring 0 (Kernel Mode) and jumps to the kernel's architecture-specific entry point (`entry_SYSCALL_64`).
   * The kernel indexes into the `sys_call_table` array, verifies user pointer validity, checks permissions, executes the kernel function (e.g., `sys_openat`), writes the return code to `RAX`, and executes `sysretq` to return to Ring 3.
2. **Virtual File System (VFS)**:
   * Provides an abstraction layer above concrete filesystem implementations (`ext4`, `xfs`, `nfs`, pseudo-filesystems like `procfs`).
   * Core VFS objects:
     * **Superblock**: Stores filesystem metadata (block size, total blocks, mount flags).
     * **Inode (Index Node)**: Represents a specific filesystem object. Stores file size, owner UID, group GID, permission mode bits, timestamps (ctime, mtime, atime), and pointers to data blocks. *Inodes do not store the filename.*
     * **Dentry (Directory Entry)**: Links a human-readable pathname string to a specific Inode number. Cached in RAM (`dcache`) for high-speed resolution.
     * **File Object**: Represents an open file instance within a process; tracks current file offset and access mode (`O_RDONLY`, `O_WRONLY`).

### 4.2 Linux Process Isolation: Namespaces and Cgroups

Modern Linux isolation (foundational to Docker and LXC containers) relies on two kernel subsystems:
* **Linux Namespaces (`namespaces(7)`)**: Virtualize system resources so that a process perceives its own isolated instance of global operating system resources:
  * `PID`: Process IDs (PID 1 inside namespace is distinct from host PID).
  * `NET`: Network stacks, routing tables, firewall rules, and virtual interfaces.
  * `MNT`: Mount tables and filesystem views.
  * `IPC`: System V IPC and POSIX message queues.
  * `UTS`: Hostname and domain name.
  * `USER`: User and Group ID mappings (unprivileged user on host can map to root inside namespace).
  * `CGROUP`: Isolated view of the control group hierarchy.
* **Control Groups (`cgroups(7)`)**: Restrict, track, and throttle physical hardware resource utilization (CPU cycles, memory allocation, block I/O bandwidth, network bandwidth) per process group.

### 4.3 Pseudo-Filesystems: `/proc` and `/sys`

* **`procfs` (`/proc`)**: Kernel-resident virtual filesystem exposing live process tables and kernel parameters:
  * `/proc/[PID]/maps`: Virtual memory layout of the process (loaded binaries, shared libraries, heap, stack).
  * `/proc/[PID]/cmdline`: Exact command-line invocation parameters passed at process initialization.
  * `/proc/[PID]/environ`: Environment variables available to the process (often exposing leaked API tokens or credentials).
  * `/proc/[PID]/fd/`: Symlinks to all open file descriptors (files, sockets, pipes).
  * `/proc/sys/`: Live kernel tuning knobs (e.g., `/proc/sys/kernel/randomize_va_space` controlling ASLR).
* **`sysfs` (`/sys`)**: Hardware, driver, and kernel subsystem hierarchy structured by bus topology and device classes.

---

## 5. How It Works: Permissions & Authentication Chains

### 5.1 Discretionary Access Control (DAC) & Special Permission Bits

File permissions are stored in a 16-bit integer within the inode:

```
+-------------------------------------------------------------+
| Inode Permission Bitmask Layout:                            |
|                                                             |
| [ 4-bit File Type ] [ 3-bit Special ] [ Owner ] [ Group ] [ Others ] |
|  e.g., Regular (-),    SUID (4)         rwx       r-x       r-x      |
|  Directory (d),        SGID (2)        (7)       (5)       (5)       |
|  Symlink (l)           Sticky (1)                                    |
+-------------------------------------------------------------+
```

* **SUID (Set User ID - Octal 4000 / Symbol `u+s`)**:
  * When set on an executable binary, any unprivileged user executing the file temporarily inherits the effective user ID (**EUID**) of the file owner (typically `root`).
  * *Essential for utilities like `/usr/bin/passwd` to write to `/etc/shadow`, but a severe privilege-escalation vulnerability if placed on interpreters (`bash`, `python`) or file editors (`vim`).*
* **SGID (Set Group ID - Octal 2000 / Symbol `g+s`)**:
  * On an executable: Executes with the Effective Group ID (EGID) of the file.
  * On a directory: Any new file or subdirectory created within automatically inherits the parent directory's group ownership rather than the primary group of the creating user. Critical for shared collaborative directories.
* **Sticky Bit (Octal 1000 / Symbol `+t`)**:
  * When applied to a world-writable directory (e.g., `/tmp`), users can only delete or rename files that they personally own, preventing unprivileged users from deleting each other's temporary lockfiles or sockets.

### 5.2 Linux Capabilities (`capabilities(7)`)

To eliminate the security risks of monolithic SUID root binaries, Linux partitions root's superpowers into discrete, granular flags:

```
+-----------------------------------------------------------------------------+
| Process Capability Sets:                                                    |
|                                                                             |
| 1. Permitted:   Maximum superset of capabilities the process may acquire.    |
| 2. Effective:   Active capabilities evaluated by the kernel during syscalls. |
| 3. Inheritable: Capabilities preserved across an execve() system call.      |
| 4. Bounding:    System-wide ceiling; masks capabilities across execve().     |
| 5. Ambient:     Automatically inherited across unprivileged execve().       |
+-----------------------------------------------------------------------------+
```

* **Critical Capabilities to Audit**:
  * `CAP_SETUID`: Allows arbitrary manipulation of process UIDs. Equivalent to full root access.
  * `CAP_DAC_OVERRIDE`: Bypasses all read, write, and execute permission checks on files.
  * `CAP_NET_RAW`: Permits creation of raw network sockets (packet sniffing, ARP spoofing).
  * `CAP_SYS_ADMIN`: The "new root"—grants mount, namespace configuration, IPC control, device driver debugging.
  * `CAP_SYS_PTRACE`: Permits tracing arbitrary processes via `ptrace(2)` (enables memory injection and credential scraping).

### 5.3 Pluggable Authentication Modules (PAM)

When a user authenticates (via SSH, local console, or `sudo`), Linux invokes PAM rather than hardcoding authentication routines into individual applications:

```
[ Application: /usr/bin/sudo ]
              |
              v
[ Loads: /etc/pam.d/sudo ]
              |
              +---> [ auth ]      --> pam_unix.so (Verifies /etc/shadow password)
              |                   --> pam_faillock.so (Locks account after 3 failures)
              |
              +---> [ account ]   --> pam_time.so (Checks login time restrictions)
              |
              +---> [ session ]   --> pam_limits.so (Enforces ulimits)
              |                   --> pam_systemd.so (Registers session with logind)
              |
              +---> [ password ]  --> pam_pwquality.so (Enforces password entropy)
```

* **PAM Control Flags**:
  * `required`: Failure causes overall authentication to fail, but PAM continues down the module stack (prevents timing analysis).
  * `requisite`: Immediate failure terminates authentication stack execution.
  * `sufficient`: If this module passes and no prior required module failed, authentication succeeds immediately.
  * `optional`: Module result is only factored in if no other modules provide a conclusive result.

---

## 6. Security Perspective & Threat Surface

### 6.1 Attack Surface of Misconfigured Linux Hosts

1. **SUID / SGID Weaponization**:
   * Misconfigured administrators or developers frequently place SUID bits on binaries capable of executing shell escapes or reading arbitrary files (documented extensively on GTFOBins).
   * Example: `/usr/bin/find` with SUID permits immediate root shell generation via `find . -exec /bin/sh -p \; -quit`.
2. **Wildcard Injection in Cron Tasks**:
   * Scheduled tasks running scripts like `tar -czf backup.tar.gz /var/www/html/*` can be exploited if an attacker creates files named `--checkpoint=1` and `--checkpoint-action=exec=sh exploit.sh` inside the directory, as `tar` interprets filenames starting with dashes as command-line options.
3. **Insecure `sudoers` Delegations**:
   * Allowing unprivileged users to execute utilities like `less`, `more`, `vi`, or `nmap` via sudo without password credentials (`NOPASSWD`) permits instant privilege escalation via interactive shell breakout commands (`!/bin/sh`).
4. **World-Writable Configuration Files**:
   * Writable `/etc/passwd` allows an attacker to append a root-level account (`toor:x:0:0::/root:/bin/bash`) directly.
   * Writable `/etc/cron*` directories allow direct injection of scheduled reverse shells.

---

## 7. Auditing Methodology: Host Hardening Verification

```
[ Step 1: User & Credential Auditing ]
  - Verify /etc/shadow permissions are 0640 or 0600, owned by root:shadow.
  - Identify non-root accounts with UID 0: awk -F: '($3 == 0) {print $1}' /etc/passwd
  - Audit /etc/sudoers and /etc/sudoers.d/* for NOPASSWD and wildcard abuses.
       |
[ Step 2: Filesystem Permission Audit ]
  - Locate all SUID/SGID binaries: find / -perm /6000 -type f 2>/dev/null
  - Compare discovered SUID binaries against default distribution manifests.
  - Inspect world-writable directories lacking the Sticky Bit (+t).
       |
[ Step 3: Capability & Process Execution Audit ]
  - Enumerate assigned file capabilities across all system binaries: getcap -r / 2>/dev/null
  - Audit running process privileges, listening network daemons, and orphaned processes.
       |
[ Step 4: Systemd Service & Cron Inspection ]
  - Inspect systemd timer units and cron directories (/etc/cron*, /var/spool/cron/).
  - Verify script ownership and path definitions (check for relative PATH execution).
       |
[ Step 5: Kernel Security Parameter Verification ]
  - Confirm ASLR is fully enabled: cat /proc/sys/kernel/randomize_va_space (must equal 2).
  - Verify dmesg restriction: sysctl kernel.dmesg_restrict (must equal 1).
  - Verify ptrace scope restriction: sysctl kernel.yama.ptrace_scope (must be >= 1).
```

---

## 8. Tooling Deep-Dive

### 8.1 Linux Native Diagnostic & Auditing Commands

```bash
# 1. Enumerate all SUID binaries on the filesystem (suppressing permission errors)
find / -perm -4000 -type f -exec ls -la {} + 2>/dev/null

# 2. Recursively find all binaries with extended capabilities assigned
getcap -r / 2>/dev/null

# 3. Inspect the active capabilities of a running process (by PID)
grep Cap /proc/$$/status
# Decode hex capability mask to human-readable strings
capsh --decode=00000000000004c0

# 4. Display process tree with security contexts, UIDs, and PIDs
ps auxZ --forest
```

### 8.2 High-Performance Log Parsing with AWK and Sed

```bash
# Extract failed SSH authentication attempts from auth.log, count and sort by attacking IP
sudo awk '/Failed password/ {for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' /var/log/auth.log \
  | sort | uniq -c | sort -nr | head -n 10

# Audit sudo invocations: extract user, timestamp, and target command executed
sudo grep "COMMAND=" /var/log/auth.log \
  | awk '{print $1, $2, $3, "User:", $5, "Command:", substr($0, index($0, "COMMAND="))}'
```

---

## 9. Practical Lab Setup: Automated Host Hardening Audit Script

Deploy this standalone, production-ready auditing script to automatically evaluate Linux DAC, capabilities, and configuration hygiene:

Save as `linux_security_audit.sh`:

```bash
#!/usr/bin/env bash
# ==============================================================================
# SCRIPT: linux_security_audit.sh
# PURPOSE: Automated Local Security Posture & Privilege Escalation Audit
# COMPLIANCE: Aligned with CIS Linux Benchmark v2.0
# ==============================================================================

set -o pipefail

echo "========================================================================"
echo "          AUTOMATED LINUX HOST SECURITY POSTURE AUDITOR                "
echo "========================================================================"

# Check 1: Audit Accounts with UID 0 (Root Equivalent)
echo -e "\n[*] [CHECK 1] Scanning for Unauthorized UID 0 Accounts..."
UID_ZERO=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
for acct in ${UID_ZERO}; do
    if [ "${acct}" == "root" ]; then
        echo "    [+] Baseline Root Account: ${acct}"
    else
        echo "    [!] ALERT: Rogue UID 0 Account Detected: ${acct}"
    fi
done

# Check 2: Audit Critical Filesystem Permissions
echo -e "\n[*] [CHECK 2] Verifying Critical Configuration File Permissions..."
declare -A CRITICAL_FILES=(
    ["/etc/passwd"]="644"
    ["/etc/shadow"]="640"
    ["/etc/group"]="644"
    ["/etc/gshadow"]="640"
)

for file in "${!CRITICAL_FILES[@]}"; do
    if [ -f "${file}" ]; then
        PERM=$(stat -c "%a" "${file}")
        OWNER=$(stat -c "%U:%G" "${file}")
        EXPECTED="${CRITICAL_FILES[$file]}"
        if [ "${PERM}" -le "${EXPECTED}" ]; then
            echo "    [+] ${file}: PERMISSIONS OK (${PERM}, Owner: ${OWNER})"
        else
            echo "    [!] ALERT: Insecure Permissions on ${file}: ${PERM} (Expected <= ${EXPECTED})"
        fi
    fi
done

# Check 3: Audit SUID Binaries against Known High-Risk List
echo -e "\n[*] [CHECK 3] Auditing SUID Binaries for Dangerous Living-off-the-Land (LotL) Executables..."
DANGEROUS_SUID=("bash" "sh" "python" "python3" "perl" "ruby" "vim" "vi" "nano" "find" "nmap" "cp" "mv" "tar")

SUID_LIST=$(find / -perm -4000 -type f 2>/dev/null)
for suid_path in ${SUID_LIST}; do
    bin_name=$(basename "${suid_path}")
    for dangerous in "${DANGEROUS_SUID[@]}"; do
        if [ "${bin_name}" == "${dangerous}" ]; then
            echo "    [!] CRITICAL WARNING: High-Risk SUID Binary Detected: ${suid_path}"
        fi
    done
done

# Check 4: Audit Extended Linux Capabilities
echo -e "\n[*] [CHECK 4] Scanning for Dangerous Extended File Capabilities..."
CAP_OUTPUT=$(getcap -r / 2>/dev/null)
if [ -z "${CAP_OUTPUT}" ]; then
    echo "    [+] No custom file capabilities detected."
else
    echo "${CAP_OUTPUT}" | while read -r line; do
        echo "    [i] Capability Found: ${line}"
    done
fi

# Check 5: Kernel Hardening Parameter Check
echo -e "\n[*] [CHECK 5] Checking Kernel ASLR & Memory Protections..."
ASLR_VAL=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
if [ "${ASLR_VAL}" -eq 2 ]; then
    echo "    [+] Full ASLR Enabled (randomize_va_space = 2)"
else
    echo "    [!] WARNING: ASLR is disabled or incomplete (val = ${ASLR_VAL})"
fi

echo -e "\n========================================================================"
echo "          AUDIT COMPLETE: REVIEW WARNINGS FOR REMEDIATION               "
echo "========================================================================"
```

---

## 10. Evidence & Verification: Verifying Capability Isolation

### Benign Capability Verification Protocol

Demonstrate how granting `cap_net_bind_service` allows a non-root application to bind to privileged low ports (e.g., port 80) without requiring full root execution:

```bash
# 1. Compile a minimal benign listening probe in C or Python
# 2. Assign capability to a non-privileged Python executable copy
sudo cp /usr/bin/python3 /tmp/python3_test
sudo setcap 'cap_net_bind_service=+ep' /tmp/python3_test

# 3. Verify capability assignment
getcap /tmp/python3_test
# Expected output: /tmp/python3_test cap_net_bind_service=ep

# 4. Execute non-root script binding port 80
sudo -u nobody /tmp/python3_test -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 80))
print('[+] Successfully bound privileged port 80 as unprivileged user!')
s.close()
"

# 5. Clean up temporary test binary
rm -f /tmp/python3_test
```

---

## 11. Telemetry, Detection & Log Signatures

### 11.1 Auditd Configuration for SUID and Privilege Execution (`/etc/audit/rules.d/privilege.rules`)

```ini
# Monitor successful and unsuccessful invocations of the setuid and setgid system calls
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

# Track changes to the sudoers configuration
-w /etc/sudoers -p wa -k sudoers_tampering
-w /etc/sudoers.d/ -p wa -k sudoers_tampering

# Monitor execution of capabilities assignment tool
-w /sbin/setcap -p x -k capability_tampering
```

### 11.2 Host EDR / Sigma Rule: SUID Execution by Low-Privilege User

```yaml
title: High-Risk SUID Binary Executed by Non-Root User
id: 5a7e1124-34df-419b-b981-d1c9817e9420
status: production
description: Detects execution of known GTFOBins binaries containing SUID flags by unprivileged service accounts.
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/find'
            - '/vim'
            - '/nano'
            - '/python'
            - '/python3'
            - '/bash'
        User|contains:
            - 'www-data'
            - 'nobody'
            - 'nginx'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.001
```

---

## 12. Mitigation & Remediation: Securing Linux Permissions & Services

### 12.1 Sudoers Principle of Least Privilege (`/etc/sudoers.d/web_admin`)

Avoid wildcard `ALL=(ALL) ALL` grants. Delegate explicit binaries with strict argument validation:

```sudoers
# Production Sudoers Policy
# User webadmin may ONLY restart nginx and view its status; NO shell escapes permitted
User_Alias WEB_OPS = webadmin
Cmnd_Alias NGINX_CMDS = /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx, /usr/sbin/nginx -t

WEB_OPS ALL=(root) NOPASSWD: NGINX_CMDS
```

### 12.2 Hardening Systemd Unit Files (`/etc/systemd/system/app.service`)

Modern systemd provides built-in kernel namespace and capability confinement:

```ini
[Unit]
Description=Production Internal API Service
After=network.target

[Service]
Type=simple
User=appuser
Group=appuser
ExecStart=/usr/local/bin/api_server

# Systemd Security Hardening Directives:
NoNewPrivileges=true            # Disables acquiring new privileges (SUID execution blocked)
ProtectSystem=strict            # Mounts /usr, /boot, /etc as read-only
ProtectHome=true                # Makes /root, /home inaccessible to service
PrivateTmp=true                 # Gives service an isolated, private /tmp mount
PrivateDevices=true             # Strips access to physical /dev devices
CapabilityBoundingSet=CAP_NET_BIND_SERVICE # Restricts all capabilities except binding port
MemoryDenyWriteExecute=true     # Blocks W^X memory violations (stops shellcode injection)
```

---

## 13. System & Protocol Hardening (CIS Benchmark Alignment)

| Security Control | Implementation Command / Configuration | Benchmark Reference |
| :--- | :--- | :--- |
| **Enforce Strict Umask** | Set `umask 027` in `/etc/profile` and `/etc/bash.bashrc` (new files created 640, dirs 750). | CIS Linux Benchmark 5.4.4 |
| **Secure Shadow Passwords** | Verify `/etc/shadow` uses SHA-512 (`$6$`) or Yescrypt (`$y$`) with salt rounds >= 5000. | CIS Linux Benchmark 5.3.1 |
| **Disable Core Dumps** | Set `* hard core 0` in `/etc/security/limits.conf` and `fs.suid_dumpable = 0` via sysctl. | CIS Linux Benchmark 1.5.1 |
| **Restrict Kernel DMESG** | Set `kernel.dmesg_restrict = 1` via `/etc/sysctl.d/99-security.conf` (stops kernel memory leak). | CIS Linux Benchmark 1.5.2 |
| **Restrict PTRACE Tracing** | Set `kernel.yama.ptrace_scope = 2` (prevents cross-process memory debugging). | CIS Linux Benchmark 1.5.3 |
| **Mount `/tmp` Securely** | Mount `/tmp` as a separate partition with `nodev,nosuid,noexec` flags in `/etc/fstab`. | CIS Linux Benchmark 1.1.2 - 1.1.4 |

---

## 14. Documented Real-World Case Studies

### Case Study 1: PwnKit (CVE-2021-4034 - Polkit `pkexec` Memory Corruption)
* **Vulnerability Class**: CWE-787 (Out-of-bounds Write).
* **Component**: Polkit's `pkexec` utility (installed default SUID-root across all major Linux distributions for over a decade).
* **Root Cause**: `pkexec` failed to handle the argument count `argc=0` properly. When invoked via `execve()` with an empty argument list, `argc` became 0, and the program read past the end of the argument array into the environment pointer array `envp`. By carefully placing an environmental variable payload (`GCONV_PATH`), an unprivileged attacker could force `pkexec` to load and execute an arbitrary shared library as `root`.
* **Impact**: Instant, 100% reliable local privilege escalation from any low-privileged user account to root on Ubuntu, Debian, Fedora, CentOS.
* **Remediation**: Patched polkit code to validate `argc > 0`; immediate workaround involved stripping SUID permissions: `chmod 0755 /usr/bin/pkexec`.

### Case Study 2: Baron Samedit (CVE-2021-3156 - Sudo Heap Overflow)
* **Component**: `/usr/bin/sudo` (SUID root).
* **Mechanism**: Sudo unescaped backslashes in command arguments when running in shell mode (`-s` or `-e`). When arguments terminated in a trailing backslash without following characters, sudo read past the terminating null byte, overflowing a heap-allocated buffer.
* **Impact**: Complete privilege escalation to root without requiring password authentication or sudo privileges.

---

## 15. Common Mistakes & Anti-Patterns

```
❌ ANTI-PATTERN 1: Giving SUID Permissions to Interpreted Binaries
   Setting SUID on bash, python, or perl scripts. Interpreted languages do not drop privileges
   cleanly, allowing environmental variable poisoning (PYTHONPATH, PERL5LIB) to hijack code flow.
   ✔ CORRECT: Use Linux capabilities (setcap) or strictly audited, compiled C wrappers with dropped privileges.

❌ ANTI-PATTERN 2: Using Sudo NOPASSWD with Shell-Escapable Utilities
   Granting a user sudo access to `less /var/log/syslog` without password. Inside `less`, the user
   types `!/bin/sh` to immediately drop into an interactive root shell.
   ✔ CORRECT: Restrict commands to non-interactive wrappers or use sudo's `NOEXEC:` tag.

❌ ANTI-PATTERN 3: Relative Path Definitions in Privileged Scripts
   Writing cron scripts that call `backup.sh` or `service restart` without fully qualified paths
   (`/usr/bin/service`). If PATH begins with `.` or an attacker controls a directory in PATH, code execution occurs.
   ✔ CORRECT: Always hardcode absolute paths (/usr/bin/tar, /bin/rm) and define explicit PATH=/usr/bin:/bin.
```

---

## 16. Professional vs. Naive Methodology

| Security Review Phase | Naive / Untrained Approach | Professional Security Auditor Approach |
| :--- | :--- | :--- |
| **SUID Auditing** | Runs a noisy automated script and ignores output; looks only for `bash`. | Compares full filesystem SUID inventory against OS package manager database (`dpkg -V` / `rpm -V`) to identify unauthorized drift. |
| **Capability Review** | Unaware of Linux capabilities; assumes non-SUID binaries are safe. | Audits extended attributes with `getcap` and inspects `/proc/[pid]/status` capability sets on all daemon processes. |
| **Cron Auditing** | Checks only the primary `/etc/crontab` file. | Interrogates `/etc/cron.*`, `/var/spool/cron/crontabs`, `/etc/anacrontab`, and systemd timer units (`systemctl list-timers`). |
| **Service Confinement** | Runs services as dedicated user without sandboxing. | Hardens systemd units with `ProtectSystem=strict`, `NoNewPrivileges=true`, and drops all unneeded capabilities from bounding set. |

---

## 17. Graded Knowledge Check & Interview Questions

### Beginner Level
1. **Question**: What occurs when an executable binary with the SUID bit set is launched by a standard user?
   * *Answer*: The operating system sets the process's Effective User ID (EUID) to match the User ID of the file's owner (typically root/UID 0) rather than the Real User ID (RUID) of the executing user, allowing it to perform operations permitted only to the owner.
2. **Question**: Why is the Sticky Bit set on the `/tmp` directory?
   * *Answer*: `/tmp` is world-writable (`rwxrwxrwt`). The sticky bit (`t`) ensures that only the file's owner or the root user can delete, rename, or modify files within that directory, preventing users from sabotaging each other's temporary files.

### Intermediate Level
3. **Question**: If an attacker finds a copy of `tar` with the SUID bit owned by root, explain the exact GTFOBins command to spawn a root shell.
   * *Answer*: `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh -p`. The `-p` flag preserves the SUID effective user privileges in bash/sh, preventing it from dropping privileges back to the real UID.
4. **Question**: What is the difference between a process's Permitted and Effective capability sets?
   * *Answer*: The *Permitted* set defines the maximum capabilities the process is authorized to use; it acts as a limiting boundary. The *Effective* set contains the capabilities that are currently active and being evaluated by the kernel when the process invokes system calls.

### Advanced / Scenario-Based
5. **Question**: You are auditing a custom Go service that binds to port 443 and writes logs to `/var/log/audit/`. The developer requests root privileges. How do you re-architect the service to eliminate the need for root execution?
   * *Answer*: (1) Create a dedicated unprivileged user and group (`audit-svc`); (2) Grant the binary the specific capability to bind low ports: `setcap 'cap_net_bind_service=+ep' /usr/local/bin/go_audit`; (3) Create `/var/log/audit/` owned by `audit-svc:audit-svc` with permissions `0750`; (4) Enforce `NoNewPrivileges=true` and `ProtectSystem=strict` in its systemd unit file.

---

## 18. Progressive Hands-on Exercises

### Level 1: Basic DAC Auditing (Beginner)
* Locate all world-writable files outside of `/proc`, `/sys`, and `/dev` on a Linux system. Identify which ones lack the sticky bit.

### Level 2: SUID vs Capability Comparison (Intermediate)
* Copy `/bin/ping` to a temporary directory. Strip its capabilities (`setcap -r`). Attempt to ping localhost as an unprivileged user and observe the raw socket permission error. Then assign `cap_net_raw=+ep` and observe successful pinging without SUID.

### Level 3: PAM Configuration Hardening (Advanced)
* Configure `/etc/pam.d/common-auth` to enforce account lockouts after 5 consecutive failed authentication attempts using `pam_faillock`. Verify lockout behavior and unlock the test account using `faillock --user <username> --reset`.

---

## 19. Key Takeaways

1. **Monolithic Root Is Obsolete**: Use Linux Extended Capabilities (`capabilities(7)`) to break root privileges into isolated, least-privilege primitives.
2. **Audit SUID Meticulously**: Every SUID binary is an execution bridge to elevated privileges. Regularly reconcile SUID lists against distribution package databases.
3. **The Power of Pseudo-Filesystems**: `/proc` and `/sys` provide unmatched visibility into live memory mappings, kernel configuration state, and open handles.
4. **Systemd Sandboxing**: Always configure `NoNewPrivileges=true`, `PrivateTmp=true`, and `ProtectSystem=strict` on custom service units.
5. **Defense in Depth**: Combine DAC permissions, POSIX ACLs, kernel sysctl parameters (ASLR=2, yama ptrace restriction), and PAM security modules.

---

## 20. Authoritative References

* **Linux Man-Pages**: `capabilities(7)`, `namespaces(7)`, `cgroups(7)`, `proc(5)`, `sudoers(5)`.
* **Kerrisk, M. (2010)**: *The Linux Programming Interface: A Linux and UNIX System Programming Handbook*. No Starch Press.
* **NIST SP 800-145**: *Guide to General Server Security (Linux Configurations)*.
* **CIS Benchmarks**: *CIS Distribution Independent Linux Benchmark v2.0.0*.
* **Qualys Security Advisory**: *CVE-2021-4034 (PwnKit: Local Privilege Escalation in polkit's pkexec)*.
* **Qualys Security Advisory**: *CVE-2021-3156 (Baron Samedit: Heap-based buffer overflow in Sudo)*.
