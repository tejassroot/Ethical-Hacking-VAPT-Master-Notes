# Volume 01: Computer & Programming Foundations
# Windows & Linux Operating System Foundations, Directory Structures & Command Mastery
## An Exhaustive First-Principles Architecture, Comparative Analysis, and Dual-Platform Command Guide for Security Engineers

---

## 1. Executive Overview & Learning Objectives

Operating systems represent the primary abstraction layer between raw microprocessor hardware and executable application software. In offensive and defensive cybersecurity engineering, every network packet intercepted, every exploit executed, every payload delivered, and every defensive detection rule engineered ultimately interacts directly with operating system primitives: processes, threads, virtual memory, system calls, file descriptors, object handles, and security descriptors.

By completing this master guide, security practitioners, systems administrators, and penetration testers will be able to:
1. **Trace the Historical Lineage of Modern Computing**: Understand how Bell Labs Unix, the GNU Project, and the Linux kernel shaped open-source computing, and how MS-DOS, DEC VMS, and Windows NT architected the modern enterprise corporate environment.
2. **Deconstruct Kernel & User-Space Architectures**: Contrast the monolithic kernel model of Linux against the hybrid executive architecture of Windows NT, analyzing privilege rings (Ring 0 vs. Ring 3), system call dispatching, and hardware abstraction.
3. **Master Filesystem Directory Hierarchies**: Navigate and audit every directory of the Linux Filesystem Hierarchy Standard (FHS) and Windows NTFS volume trees, identifying sensitive files, configuration files, and privilege-escalation sinks.
4. **Compare Operating System Security Models**: Evaluate the security differences between POSIX Discretionary Access Control (UID/GID, `rwx`, SUID/SGID, Capabilities) and Windows Security Reference Monitor architecture (SIDs, Access Tokens, DACLs, SACLs, Integrity Levels).
5. **Execute the Top 50 Essential Linux Commands**: Utilize core command-line tools for systems reconnaissance, file manipulation, permission auditing, text processing, process inspection, and network socket interrogation.
6. **Execute the Top 50 Essential Windows Commands**: Leverage Command Prompt (`cmd.exe`) and PowerShell (`powershell.exe`) to audit system configurations, service accounts, registry keys, scheduled tasks, network sockets, and security policies.
7. **Translate Fluent Knowledge Across Platforms**: Utilize the Dual-Platform Command Rosetta Stone to immediately translate administrative and assessment tasks between Linux and Windows environments.

---

## 2. Historical Lineage & Evolution of Operating Systems

### 2.1 The History of Unix & The Rise of Linux

The genealogy of modern computing can be traced directly to research laboratories in the late 1960s attempting to solve the problem of multi-user interactive computing:

```
[ 1964: MULTICS Project (MIT / GE / Bell Labs) ]
                     │ (Complexity & Resource Overhead)
                     ▼
[ 1969: AT&T Bell Labs - Ken Thompson & Dennis Ritchie ]
                     │ (PDP-7 / PDP-11: Unix is Born)
                     ▼
[ 1972: Dennis Ritchie invents C Language ] ──> [ 1973: Unix Re-written in C ]
                     │
        ┌────────────┴──────────────────────────┐
        ▼                                       ▼
[ Commercial AT&T System V ]          [ Academic BSD Unix (UC Berkeley) ]
        │ (Licensing Restrictions)              │ (TCP/IP Networking, Sockets)
        ▼                                       ▼
[ 1983: Richard Stallman announces GNU ]       [ SunOS / Solaris / NeXTSTEP ]
   - Goal: 100% Free Unix Clone                         │
   - Tools: GCC, Bash, Coreutils, GPL                   ▼
        │                                      [ macOS / Darwin / iOS ]
        ▼
[ 1991: Linus Torvalds invents Linux Kernel (v0.01) ]
        │
        ▼
[ GNU Userland + Linux Kernel = GNU/Linux Operating System ]
        │
   ┌────┴───────────────────────────────┬───────────────────────────────┐
   ▼                                    ▼                               ▼
[ Debian Lineage ]             [ Red Hat Lineage ]             [ Independent Lineage ]
   ├── Ubuntu                     ├── RHEL                        ├── Slackware
   ├── Kali Linux (Offensive)     ├── CentOS / Rocky / Alma       ├── Arch Linux
   └── Parrot OS                  └── Fedora                      └── Alpine Linux (Containers)
```

#### 1. The Multics Genesis & Bell Labs (1964–1969)
In the mid-1960s, MIT, General Electric, and AT&T Bell Laboratories partnered to develop **Multics** (Multiplexed Information and Computing Service). Multics was ambitious, aiming to deliver continuous, utility-like computing to hundreds of simultaneous users. However, it was excessively complex and resource-heavy. In 1969, Bell Labs withdrew from the project.

Frustrated by the loss of their interactive computing environment, Bell Labs researchers **Ken Thompson**, **Dennis Ritchie**, **Douglas McIlroy**, and **Joe Ossanna** began designing a much simpler, lightweight operating system on a discarded Digital Equipment Corporation (DEC) PDP-7 computer. They named it **UNIX** (originally *UNICS*, a pun on Multics).

#### 2. The C Language Revolution (1971–1973)
Initially, Unix was written in PDP assembly language, making it bound to DEC hardware. In 1972, Dennis Ritchie created the **C programming language**. In 1973, Thompson and Ritchie rewrote the entire Unix kernel in C. This was an unprecedented architectural leap: **an operating system could now be ported to entirely different hardware architectures simply by compiling the source code with an architecture-specific C compiler.**

#### 3. The Unix Philosophy
Unix introduced architectural design tenets that govern operating systems to this day:
* **"Everything is a file"**: Disks, keyboard inputs, screens, network interfaces, and running processes are abstracted as streams of bytes accessed through standard file operations (`open()`, `read()`, `write()`, `close()`).
* **Modularity & Simplicity**: Write programs that do one specific thing and do it well.
* **Composability**: Programs communicate via standard text streams (`stdin`, `stdout`, `stderr`), connected together using the **pipeline (`|`)** operator invented by Douglas McIlroy.

#### 4. The Unix Wars & The GNU Movement (1977–1983)
AT&T was initially prohibited by antitrust regulations from selling computer software commercially, so they distributed Unix source code to universities for a nominal media fee. The University of California, Berkeley added virtual memory and the first reference implementation of the **TCP/IP protocol stack**, giving birth to **BSD (Berkeley Software Distribution)**.

When AT&T was broken up in 1982, it commercialized Unix (System III and System V) and began aggressively enforcing copyright claims against universities and vendors. Seeing the freedom of software developers under threat, **Richard Stallman** founded the **GNU Project** (GNU's Not Unix) at MIT in 1983 and established the **Free Software Foundation (FSF)**. Stallman wrote the **GNU General Public License (GPL)** and developed the essential user-space components of an operating system: the GNU C Compiler (`gcc`), the GNU core utilities (`coreutils`), `make`, and the Bourne Again Shell (`bash`). However, the GNU kernel project (**GNU Hurd**) struggled with technical complexity and remained unfinished.

#### 5. Linus Torvalds & The Birth of Linux (1991)
In August 1991, a 21-year-old Finnish computer science student at the University of Helsinki named **Linus Torvalds** grew frustrated by the licensing limitations of MINIX (an educational operating system created by Andrew Tanenbaum). Torvalds posted his famous announcement to the `comp.os.minix` newsgroup:

> *"I'm doing a (free) operating system (just a hobby, won't be big and professional like gnu) for 386(486) AT clones..."*

Torvalds developed a monolithic kernel designed specifically to leverage the 32-bit protected-mode paging and hardware task-switching capabilities of the Intel 80386 processor. He released **Linux kernel version 0.01** in September 1991 and re-licensed it under the GNU GPL in 1992.

By combining the free **Linux kernel** with the existing **GNU user-space operating environment**, developers finally had a complete, fully functional, free and open-source operating system: **GNU/Linux**.

#### 6. Modern Evolution & Dominance
Today, Linux is the bedrock of global enterprise technology:
* **Enterprise Cloud & Supercomputing**: Powers over 90% of all public cloud workloads (AWS, Microsoft Azure, Google Cloud) and 100% of the world's top 500 supercomputers.
* **Mobile Devices**: Android, which runs on over 3 billion active devices, is built upon a modified Linux kernel.
* **Cybersecurity & VAPT**: Offensive security distributions such as **Kali Linux** and **Parrot Security OS** package thousands of specialized VAPT tools on top of standard Debian Linux backbones.

---

### 2.2 The History of Microsoft Windows

Microsoft's operating system evolution followed an entirely different trajectory, transitioning from a single-user, 16-bit command interpreter into an enterprise-grade, object-oriented, multi-user operating system:

```
[ 1980: Tim Paterson (Seattle Computer Products) creates QDOS / 86-DOS ]
                                 │
                                 ▼
[ 1981: Microsoft buys 86-DOS & licenses it as MS-DOS 1.0 to IBM PC ]
                                 │ (16-bit Real Mode, Single-Tasking CLI)
                                 ▼
[ 1985-1992: Windows 1.0, 2.0, 3.0, 3.1 ]
   - Graphical Shell operating on top of MS-DOS
   - Cooperative Multitasking, Segmented 16-bit Memory
                                 │
     ┌───────────────────────────┴───────────────────────────┐
     ▼ (Consumer Branch: DOS-Based)                          ▼ (Enterprise Branch: Modern NT Kernel)
[ 1995: Windows 95 ]                                    [ 1988: Dave Cutler leaves DEC for Microsoft ]
   - 32-bit Win32 API support                              - Architect of DEC VMS hired to design NT
   - Integrated with MS-DOS 7.0                            - Built from scratch: Preemptive, HAL, Objects
     │                                                       │
[ 1998: Windows 98 ]                                    [ 1993: Windows NT 3.1 ]
[ 2000: Windows ME (Millennium) ]                       [ 1996: Windows NT 4.0 (Win32 GUI in Kernel) ]
     │                                                  [ 2000: Windows 2000 (NT 5.0) ]
     │ (Consumer branch abandoned due to instability)      - Active Directory, Kerberos, NTFS 3.0
     └───────────────────────────┬───────────────────────────┘
                                 ▼
[ 2001: The Unification Era - Windows XP (NT 5.1) ]
   - Consumer & Enterprise lines united under the pure Windows NT Kernel
                                 │
                                 ▼
[ 2006: Windows Vista (NT 6.0) & Windows Server 2008 ]
   - Architectural Hardening: User Account Control (UAC), Mandatory Integrity Control,
     BitLocker, Windows Service Hardening, ASLR, Audio/Graphics moved out of Kernel
                                 │
                                 ▼
[ 2009-2015: Windows 7 (NT 6.1), Windows 8/8.1 (NT 6.2/6.3) ]
                                 │
                                 ▼
[ 2015: Windows 10 (NT 10.0) & Windows Server 2016-2022 ]
   - Windows Subsystem for Linux (WSL1/WSL2)
   - Windows Defender Exploit Guard, AMSI, Virtualization-Based Security (VBS)
                                 │
                                 ▼
[ 2021-Present: Windows 11 & Windows Server 2025 ]
   - Hardware-enforced TPM 2.0, Secure Boot, HVCI default, Cloud Identity (Entra ID)
```

#### 1. The MS-DOS Foundation (1981–1990)
In 1980, IBM was secretly developing its first mass-market personal computer (the IBM 5150) and contracted Microsoft to provide an operating system. Microsoft purchased the rights to **86-DOS** (Quick and Dirty Operating System) from Tim Paterson at Seattle Computer Products for $50,000, modified it, and delivered it to IBM as **PC-DOS 1.0**, while retaining the rights to sell it to other hardware manufacturers as **MS-DOS**.

MS-DOS was fundamentally primitive:
* **Single-tasking**: Only one program could execute at any given moment.
* **Real Mode Memory**: CPU operated in 16-bit real mode with no memory protection. Any program could write directly to physical memory addresses, overwriting the operating system itself.
* **Command-Line Only**: Interaction occurred strictly via the `COMMAND.COM` command shell.

#### 2. The Early Windows GUI Shells (1985–1992)
To counter the graphical user interface popularized by Apple's Macintosh, Microsoft released **Windows 1.0** (1985), **Windows 2.0** (1987), and **Windows 3.0/3.1** (1990–1992). 
Critically, early Windows was **not an operating system**. It was a 16-bit graphical desktop shell running on top of MS-DOS. It utilized **cooperative multitasking**: if one application hung or refused to yield control of the processor, the entire operating system froze.

#### 3. The Windows NT Revolution & Dave Cutler (1988–1993)
Recognizing that the DOS architecture was a dead end incapable of supporting enterprise computing, Microsoft Chairman Bill Gates made one of the most critical decisions in software history in 1988: he hired **Dave Cutler**, the legendary lead systems architect of Digital Equipment Corporation (DEC) who had designed **VMS** (Virtual Memory System) for the VAX computer architecture.

Cutler and his team of DEC engineers were tasked with designing an enterprise-grade, portable, highly secure, preemptive multitasking operating system completely from scratch. The project was named **Windows NT (New Technology)**.

Cutler’s team engineered Windows NT with revolutionary architectural principles:
* **Hardware Abstraction Layer (HAL)**: Isolated the kernel from hardware specifics, allowing NT to run on x86, MIPS, Alpha, and PowerPC processors.
* **Preemptive Multitasking**: The operating system kernel maintained absolute scheduling control over the CPU, preventing rogue applications from locking the machine.
* **Strict Memory Protection**: User applications executed in isolated virtual address spaces and could not access hardware or kernel memory directly.
* **Object-Oriented Architecture**: Every resource (files, processes, threads, semaphores, shared memory) was abstracted as an **Object** governed by a unified security system called the **Security Reference Monitor (SRM)**.
* **NTFS (NT File System)**: Replaced the fragile FAT16 filesystem with a robust journaling filesystem featuring Access Control Lists (ACLs), alternate data streams, and 64-bit addressing.

Windows NT 3.1 debuted in 1993, followed by Windows NT 4.0 in 1996 and **Windows 2000 (NT 5.0)**, which introduced **Active Directory (AD)**, Kerberos enterprise authentication, and Group Policy Objects (GPOs).

#### 4. The Unification with Windows XP (2001)
Until 2001, Microsoft maintained two competing codebases: the crash-prone consumer DOS-based series (Windows 95, 98, ME) and the rock-solid enterprise series (Windows NT, 2000). 
In October 2001, Microsoft officially discontinued the MS-DOS lineage with the release of **Windows XP (Windows NT 5.1)**, uniting all consumer and business computing on the Windows NT kernel.

#### 5. Windows Vista & Modern Enterprise Hardening (2006–Present)
Following the devastating network-worm pandemics of the early 2000s (Code Red, Nimda, Blaster, Sasser), Microsoft initiated the Trustworthy Computing initiative. This culminated in **Windows Vista (NT 6.0)** and **Windows Server 2008**, which introduced core security architectures present today:
* **User Account Control (UAC)**: Stripped full administrative tokens from administrators during interactive sessions, forcing elevation prompts for administrative actions.
* **Address Space Layout Randomization (ASLR)** & **Data Execution Prevention (DEP)**: Neutralized classic memory corruption and buffer overflow exploits.
* **Mandatory Integrity Control (MIC)**: Implemented security integrity labels (Untrusted, Low, Medium, High, System) preventing sandboxed applications from tampering with higher-integrity processes.
* **Modern Windows (Windows 10, 11, Server 2025)**: Added Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), Credential Guard (protecting LSASS memory), and the Antimalware Scan Interface (AMSI).

---

## 3. Deep Architectural Comparison: Windows NT vs. Linux

Understanding operating system internals requires analyzing how the CPU executes code, how memory is partitioned, and how security boundaries are enforced:

```
+-----------------------------------------------------------------------------------------------+
|                                    CPU PRIVILEGE RINGS                                        |
+-----------------------------------------------------------------------------------------------+
|                                                                                               |
|   +---------------------------------------------------------------------------------------+   |
|   | USER SPACE (Ring 3 - Least Privileged)                                                |   |
|   |                                                                                       |   |
|   |  LINUX:                                       WINDOWS NT:                             |   |
|   |  - Applications (bash, python, nginx)         - Applications (cmd, powershell, chrome)|   |
|   |  - C Standard Library (glibc / musl)          - Win32 Subsystem (kernel32, user32)    |   |
|   |  - Process Virtual Memory (User Mode)         - Native API DLL (ntdll.dll)            |   |
|   |                                               - Subsystem Servers (csrss.exe, lsass)  |   |
|   +---------------------------------------------------------------------------------------+   |
|                                       │                               │                       |
|                 Assembly Instruction: │ syscall                       │ syscall               |
|                                       ▼                               ▼                       |
|   +---------------------------------------------------------------------------------------+   |
|   | KERNEL SPACE (Ring 0 - Most Privileged / Supervisor Mode)                             |   |
|   |                                                                                       |   |
|   |  LINUX (Monolithic Architecture):             WINDOWS NT (Hybrid Architecture):       |   |
|   |  - System Call Interface (sys_call_table)     - Executive (Object Manager, Process,   |   |
|   |  - Process Scheduler & Virtual Memory (VFS)     Memory, Security Reference Monitor)   |   |
|   |  - Network Stack & Device Drivers             - Microkernel (Scheduler, Synch)        |   |
|   |  - Loadable Kernel Modules (.ko)              - Hardware Abstraction Layer (hal.dll)  |   |
|   |  - Linux Security Modules (SELinux, eBPF)     - Kernel Drivers (ntoskrnl.exe, .sys)   |   |
|   +---------------------------------------------------------------------------------------+   |
|                                       │                               │                       |
|                                       ▼                               ▼                       |
|                               [ PHYSICAL HARDWARE: CPU, RAM, DISK, NIC ]                      |
+-----------------------------------------------------------------------------------------------+
```

### 3.1 Architectural Matrix

| Architectural Dimension | Linux Operating System | Microsoft Windows NT |
| :--- | :--- | :--- |
| **Kernel Type** | **Monolithic Kernel**: Core subsystems (scheduler, memory manager, VFS, networking, device drivers) execute within a unified single address space in Ring 0. Highly performant due to zero IPC context switches for kernel functions. | **Hybrid Kernel**: Combines microkernel modularity with monolithic performance. The Executive and Microkernel run in Ring 0, while environment subsystems (`csrss.exe`, `lsass.exe`) run in Ring 3. |
| **Philosophy** | **"Everything is a file"**: Uniform text stream abstraction via virtual filesystems (`/proc`, `/sys`, `/dev`). Resources manipulated through standard file descriptors (`fd`). | **"Everything is an Object"**: Governed by the Object Manager. Resources (files, processes, registry keys, threads, sections) have typed handles, attributes, and security descriptors. |
| **System Call Dispatch** | Application calls C library (`glibc` wrapper) $\rightarrow$ executes `syscall` instruction $\rightarrow$ kernel indexes `sys_call_table` using CPU register values (`RAX`). | Application calls Win32 API (`kernel32.dll`) $\rightarrow$ calls Native API (`ntdll.dll` stub) $\rightarrow$ executes `syscall` $\rightarrow$ kernel indexes SSDT (System Service Descriptor Table). |
| **Process Model** | Created via `fork()` (clones parent process address space via Copy-on-Write) and `execve()` (replaces memory image with new binary). Lightweight threads created via `clone()`. | Created via `CreateProcess()` / `NtCreateUserProcess()`. Heavyweight objects containing an explicit Process Environment Block (PEB) and Thread Environment Blocks (TEB). |
| **Primary Identity** | Integer User IDs (**UID**) and Group IDs (**GID**). Root is `UID 0`. Unprivileged users start at `1000`. | Variable-length binary/string **Security Identifiers (SIDs)** (e.g., `S-1-5-18` for SYSTEM, `S-1-5-32-544` for Administrators, `S-1-5-21-...` for domain users). |
| **Access Control** | **POSIX DAC**: Owner, Group, Others with Read (`r`), Write (`w`), Execute (`x`) bits. Extended by POSIX ACLs (`setfacl`) and Linux Capabilities (`cap_net_raw`). | **Windows DACLs/SACLs**: Every securable object possesses a Security Descriptor containing a Discretionary ACL (ACE entries) and System ACL (Auditing). Evaluated by SRM. |
| **Configuration Model** | **Decentralized Plaintext Files**: Human-readable text configuration files stored primarily within `/etc/`. Edited with standard text editors and shell scripts. | **Centralized Binary Registry**: Structured hierarchical database stored in binary hive files (`HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`) and accessed via Win32 APIs/`reg.exe`. |
| **CLI & Shell** | Text-stream based: Standard input, output, and error passing raw ASCII/UTF-8 byte sequences through pipes (Bash, Zsh, Sh). | Object-oriented pipeline: PowerShell passes rich .NET objects with properties and methods across the pipeline rather than raw unstructured text streams. |

---

## 4. Linux Filesystem Hierarchy Standard (FHS) & Directory Structure

The Linux directory structure does not use drive letters (`C:`, `D:`). Instead, it forms a single, unified inverted tree originating at the **Root Directory (`/`)**. Storage devices, network shares, and virtual filesystems are grafted ("mounted") onto specific directory branches within this tree.

```
/ (Root Directory)
├── bin -> usr/bin          (Essential user command binaries for all users)
├── boot                    (Static bootloader, kernel images: vmlinuz, initramfs)
├── dev                     (Special device files: /dev/null, /dev/sda, /dev/urandom)
├── etc                     (Host-specific system-wide configuration files)
│   ├── passwd              (User account definitions - world readable)
│   ├── shadow              (Hashed user passwords - restricted to root)
│   ├── sudoers             (Sudo privilege delegation rules)
│   └── ssh/                (OpenSSH daemon configs and host keys)
├── home                    (Standard user personal home directories: /home/alice)
├── lib -> usr/lib          (Essential shared libraries required by system binaries)
├── media                   (Mount points for removable media: USB flash drives, CD-ROMs)
├── mnt                     (Temporary mount points for filesystems mounted by sysadmin)
├── opt                     (Optional third-party proprietary software packages)
├── proc                    (Virtual pseudo-filesystem: kernel runtime process state)
│   ├── [pid]/              (Per-process runtime metadata: cmdline, environ, fd/)
│   └── sys/                (Kernel security toggles: ip_forward, aslr)
├── root                    (Home directory for the superuser 'root')
├── run                     (Runtime variable data describing system since boot)
├── sbin -> usr/sbin        (Essential system administration binaries: fdisk, iptables)
├── srv                     (Data for services provided by this system)
├── sys                     (Virtual pseudo-filesystem: kernel device model & hardware)
├── tmp                     (Temporary files - world writable with sticky bit 't')
├── usr                     (Secondary user hierarchy: read-only user data & utilities)
│   ├── bin                 (Primary location for modern Linux commands)
│   ├── lib                 (Libraries for binaries in /usr/bin)
│   ├── local/              (Locally compiled binaries and software)
│   └── share/              (Architecture-independent data: man pages, documentation)
└── var                     (Variable data files that change dynamically during operation)
    ├── log/                (System and application logs: syslog, auth.log, wtmp)
    ├── mail/               (User mailboxes)
    ├── spool/              (Spool directories: cron jobs, printing queues)
    └── www/                (Default web server document roots: /var/www/html)
```

### 4.1 Exhaustive Linux Directory Reference & Security Audit Points

| Directory | Technical Purpose & Architecture | Security Assessment & VAPT Relevance |
| :--- | :--- | :--- |
| **`/`** | The root of the entire filesystem hierarchy. Every file, device, and mounted disk resides under `/`. | Directory permissions must be `755` (`drwxr-xr-x`) owned by `root:root`. If `/` is writable by unprivileged users, complete system compromise is trivial. |
| **`/bin`** & **`/usr/bin`** | Essential executable binaries used by both system administrators and ordinary users (e.g., `ls`, `cat`, `bash`, `cp`, `grep`). In modern systems, `/bin` is a symlink to `/usr/bin`. | **SUID/SGID Audit**: Target for auditing binaries with SUID bits set (`chmod u+s`). Vulnerabilities or misconfigurations in SUID binaries allow immediate local privilege escalation to root (GTFOBins). |
| **`/sbin`** & **`/usr/sbin`** | Essential system administration utilities intended for execution by `root` (e.g., `fdisk`, `iptables`, `reboot`, `useradd`). | Ordinary users should not have write access to `/sbin`. Audit for custom scripts placed in `/sbin` with weak file permissions. |
| **`/etc`** | The nerve center of Linux configuration. Contains host-specific, static system configuration files and startup scripts. Does not contain binary executables. | **Primary Target for Credential Harvesting**: <br/>• `/etc/passwd`: Inspect for unexpected users with `UID 0`.<br/>• `/etc/shadow`: Validate permissions are `640` or `000` owned by `root:shadow`.<br/>• `/etc/sudoers`: Audit for unsafe delegations (e.g., `NOPASSWD: ALL` or GTFOBins binaries).<br/>• `/etc/crontab` & `/etc/cron.*`: Check for writable scheduled task scripts. |
| **`/dev`** | Special device files representing hardware and virtual devices managed by the `udev` daemon. Device nodes do not occupy disk space; they act as interfaces to kernel drivers. | **Direct Memory & Disk Access**: <br/>• `/dev/sda` / `/dev/nvme0n1`: Raw disk access. If readable by a user, sensitive data can be carved bypassing filesystem permissions.<br/>• `/dev/urandom`: Cryptographically secure pseudorandom number generator.<br/>• `/dev/shm`: Shared memory temporary filesystem (`tmpfs`). Often used by malware to execute payloads entirely in RAM. |
| **`/proc`** | A virtual, in-memory pseudo-filesystem generated dynamically by the Linux kernel on-the-fly. Provides an interactive window into kernel data structures and active processes. | **Process & Memory Triage**: <br/>• `/proc/[PID]/cmdline`: Reveals plain-text passwords passed via CLI arguments.<br/>• `/proc/[PID]/environ`: Exposes environment variables (API keys, tokens).<br/>• `/proc/[PID]/maps`: Process virtual memory layout (useful for exploit development).<br/>• `/proc/sys/kernel/randomize_va_space`: ASLR status (`0`=Disabled, `2`=Full). |
| **`/sys`** | Virtual pseudo-filesystem representing the kernel's unified device model, bus controllers, power states, and hardware parameters. | Used by kernel exploit writers to inspect kernel address pointers, CPU hardware mitigation flags (Meltdown, Spectre), and driver interfaces. |
| **`/var`** | Variable data generated during normal system operation. Contains runtime logs, mail queues, lock files, and databases. | **Forensics & Persistence**: <br/>• `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL): Records all SSH logins, sudo attempts, and authentication failures.<br/>• `/var/spool/cron/crontabs/`: User-specific cron scheduled tasks.<br/>• `/var/www/html/`: Web server root. Inspect for web shells and configuration leaks (`wp-config.php`, `.env`). |
| **`/tmp`** | Temporary directory accessible to all users. Traditionally mounted on a temporary RAM filesystem (`tmpfs`). | **Shared Workspace & Exploitation**: Configured with the **Sticky Bit (`1777` - `drwxrwxrwt`)**, allowing anyone to write files but only allowing file owners to delete them. Standard location for compiling local privilege escalation exploits or downloading assessment payloads. |
| **`/home`** | Houses personal user home directories (e.g., `/home/bob/`). Stores user documents, personal configurations, and shell history. | **Audit Targets**: <br/>• `~/.ssh/id_rsa`: Private SSH keys.<br/>• `~/.bash_history`: Plaintext logs of commands executed by the user (often contains typed passwords).<br/>• `~/.bashrc`: Potential persistence location. |
| **`/root`** | The private home directory of the root superuser. Kept separate from `/home` to ensure root can log in even if `/home` is on an unmounted network partition. | Must strictly maintain `700` (`drwx------`) permissions. Contains `root`'s SSH keys, bash history, and administrative tooling. |
| **`/opt`** | Dedicated to optional, self-contained third-party software packages (e.g., Google Chrome, Splunk, custom enterprise agents). | Third-party software installed in `/opt` frequently features permissive permissions (`777`) or outdated bundled libraries vulnerable to local privilege escalation. |

---

## 5. Windows Operating System Directory Structure & Key Subsystems

Unlike Linux, Windows organizes physical and logical partitions under **Drive Letters** (`C:`, `D:`, `E:`). The standard system drive is almost universally designated as `C:`.

```
C:\ (System Drive Root)
├── PerfLogs                        (Performance monitor logs)
├── Program Files                   (Native 64-bit application installations)
├── Program Files (x86)             (Legacy 32-bit application installations on 64-bit OS)
├── ProgramData                     (Hidden: All-users shared application data & caches)
├── Users                           (User profiles directory)
│   ├── Administrator               (Built-in local admin profile)
│   ├── Public                      (Shared folder accessible by all local/domain accounts)
│   └── <Username>                  (Standard interactive user profile)
│       ├── Desktop                 (User desktop files)
│       ├── Documents               (Personal documents)
│       ├── Downloads               (Downloaded internet files)
│       └── AppData                 (Hidden: User-specific configuration & secrets)
│           ├── Local               (Machine-specific config, temp files, browser profiles)
│           │   └── Temp            (Per-user temporary execution folder)
│           ├── LocalLow            (Sandboxed low-integrity data: browser protected mode)
│           └── Roaming             (Network-roaming configuration: SSH keys, Slack, Discord)
└── Windows                         (Operating System Core - %SystemRoot% / %WINDIR%)
    ├── System32                    (Primary 64-bit system binaries, DLLs, kernel drivers)
    │   ├── cmd.exe                 (Command Prompt)
    │   ├── powershell.exe          (Windows PowerShell)
    │   ├── lsass.exe               (Local Security Authority Subsystem Service)
    │   ├── config/                 (Active Binary Registry Hives: SAM, SYSTEM, SECURITY)
    │   ├── drivers/etc/            (Network configuration files: hosts, services)
    │   └── Tasks/                  (Windows Task Scheduler XML job definitions)
    ├── SysWOW64                    (32-bit system binaries & DLLs for backward compatibility)
    ├── Temp                        (System-wide temporary directory)
    └── WinSxS                      (Windows Component Store / Side-by-Side assembly cache)
```

### 5.1 Exhaustive Windows Directory Reference & Security Audit Points

| Windows Directory | Technical Purpose & Architecture | Security Assessment & VAPT Relevance |
| :--- | :--- | :--- |
| **`C:\Windows`** (`%WINDIR%`) | The primary operating system root directory. Houses the core operating system files, diagnostic logs, and default administrative tools. | Standard users have Read and Execute permissions, but cannot modify files directly. Writable subdirectories in `C:\Windows` (such as `C:\Windows\Tasks` or `C:\Windows\Tracing`) can be leveraged for persistence or DLL hijacking. |
| **`C:\Windows\System32`** | The most critical directory in Windows. On 64-bit Windows, **System32 contains native 64-bit system files, executables, DLLs, and device drivers**. | **Host Defense & EDR Focal Point**: <br/>• Contains core processes: `ntoskrnl.exe` (Kernel), `lsass.exe` (Authentication), `svchost.exe` (Service Host), `services.exe` (Service Control Manager).<br/>• Target of DLL search-order hijacking if applications look for DLLs without explicit paths. |
| **`C:\Windows\SysWOW64`** | **"Windows-on-Windows 64-bit"**. Despite the "64" in its name, on a 64-bit OS, **this directory contains the 32-bit versions of system binaries and DLLs** to allow 32-bit legacy applications to execute seamlessly. | Understanding the file system redirector is essential: when a 32-bit process attempts to access `C:\Windows\System32`, the Windows kernel transparently redirects the call to `C:\Windows\SysWOW64`. |
| **`C:\Windows\System32\config`** | Stores the active on-disk binary database files known as **Registry Hives**: `SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, and `DEFAULT`. | **Primary Offline Credential Target**: <br/>• `SAM`: Contains local user NTLM password hashes.<br/>• `SYSTEM`: Contains the Boot Key (`Syskey`) required to decrypt the SAM and LSA secrets.<br/>• Protected by exclusive OS kernel file locks. Auditors extract them via Volume Shadow Copies (`vssadmin`), registry backups (`reg save`), or LSASS memory dumps. |
| **`C:\Windows\System32\drivers\etc`** | Houses standard networking flat files: `hosts` (local DNS overrides), `services` (port-to-protocol mapping), and `networks`. | **Adversary Redirection**: Modifying the `hosts` file allows an attacker to hijack internal domain names, redirecting authentication traffic to rogue listening proxies. |
| **`C:\Program Files`** | Default installation directory for native **64-bit applications** on 64-bit Windows. | **Unquoted Service Paths**: Services installed with spaces in their path without quotes (e.g., `C:\Program Files\Common Tools\agent.exe`) allow privilege escalation if a user can write `C:\Program.exe`. |
| **`C:\Program Files (x86)`** | Default installation directory for **32-bit legacy applications** on 64-bit Windows. | Evaluated identically to `Program Files`. 32-bit enterprise legacy software frequently suffers from older, unpatched vulnerabilities. |
| **`C:\ProgramData`** (`%ALLUSERSPROFILE%`) | A hidden directory used by software vendors to store shared application data, local databases, and temporary configuration files accessible by all users. | **Weak Access Control Lists (ACLs)**: Applications frequently grant permissive permissions (`Everyone: (F)` or `Users: (M)`) to their subfolders in `ProgramData`. This allows local users to overwrite binary dependencies, configuration files, or logs to escalate privileges. |
| **`C:\Users\<Username>`** | The User Profile directory. Contains user-specific file stores: `Desktop`, `Documents`, `Downloads`, `Pictures`, and personal configuration files. | **User Reconnaissance**: Inspect `Downloads` for downloaded installers, VPN configuration profiles, passwords saved in documents, and PowerShell history files (`ConsoleHost_history.txt`). |
| **`AppData\Local`** | Stores non-roaming user configuration data, browser databases (Chrome/Edge SQLite history and session cookies), and application local caches. | **Credential & Token Hunting**: Browser profiles in `AppData\Local\Google\Chrome\User Data` store encrypted session cookies and saved credentials decrypted via the Windows Data Protection API (DPAPI). |
| **`AppData\Roaming`** | Stores user configuration data designed to synchronize across domain-joined computers via Active Directory Roaming Profiles. | **High-Value Target**: Stores saved configuration files for developer tools: SSH keys (`.ssh`), Git credentials, Slack/Discord authentication tokens, and PuTTY session profiles. |
| **`C:\Windows\Temp`** & **`AppData\Local\Temp`** | System-wide and per-user temporary execution directories. | Standard landing pad for payload staging. Often monitored heavily by EDR products with stricter heuristics. |

---

## 6. Top 50 Essential Linux Commands for Security Auditors

Every security engineer, system auditor, and penetration tester must possess instinctive command-line mastery. Below are the 50 most vital Linux commands, structured by operational domain with exact syntax, common flags, practical security examples, and expected output analysis.

### Domain 1: System Information & Host Reconnaissance

#### 1. `uname` — Print System & Kernel Architecture Information
* **Syntax**: `uname [OPTION]...`
* **Key Flags**: `-a` (print all information), `-r` (kernel release), `-m` (machine architecture: `x86_64`, `aarch64`).
* **Security Example**:
  ```bash
  uname -a
  ```
* **Audit Context**: Immediately identifies the exact Linux kernel version (e.g., `Linux target 5.10.0-8-amd64 #1 SMP PREEMPT x86_64 GNU/Linux`) to cross-reference against known local kernel vulnerabilities (Dirty COW, Dirty Pipe, OverlayFS).

#### 2. `hostnamectl` — Query and Control System Hostname & Machine Metadata
* **Syntax**: `hostnamectl [OPTIONS...] {status}`
* **Security Example**:
  ```bash
  hostnamectl status
  ```
* **Audit Context**: Instantly detects whether the target host is running inside a virtualized hypervisor container (e.g., `Virtualization: vmware`, `kvm`, `docker`) or directly on bare metal.

#### 3. `lscpu` — Display Microprocessor Architecture Details
* **Syntax**: `lscpu [options]`
* **Key Flags**: `-e` (display CPU summary table), `-J` (JSON output format).
* **Security Example**:
  ```bash
  lscpu | grep -E "Model name|Virtualization|Vulnerability"
  ```
* **Audit Context**: Details CPU hardware architecture, virtualization extensions (VT-x/AMD-V), and kernel hardware vulnerability mitigations (Spectre, Meltdown, MDS, Retbleed).

#### 4. `free` — Display Amount of Free and Used Memory in the System
* **Syntax**: `free [options]`
* **Key Flags**: `-h` (human-readable: GB, MB), `-m` (megabytes).
* **Security Example**:
  ```bash
  free -h
  ```
* **Audit Context**: Evaluates host capacity before launching resource-intensive scanning or password-cracking tools. In denial-of-service assessments, tracks RAM and swap exhaustion.

#### 5. `uptime` — Tell How Long the System Has Been Running
* **Syntax**: `uptime [options]`
* **Key Flags**: `-p` (pretty print duration), `-s` (system up since timestamp).
* **Security Example**:
  ```bash
  uptime -s
  ```
* **Audit Context**: Discloses the exact time the machine last rebooted. An uptime of 3 years indicates that critical kernel security patches requiring a reboot have not been applied.

#### 6. `lsblk` — List Block Storage Devices
* **Syntax**: `lsblk [options] [device...]`
* **Key Flags**: `-f` (output filesystem info: UUID, mount point, filesystem type: ext4, xfs).
* **Security Example**:
  ```bash
  lsblk -f
  ```
* **Audit Context**: Identifies unmounted physical hard drives, hidden partitions, LUKS encrypted volumes, or USB flash drives containing sensitive forensic artifacts.

#### 7. `df` — Report File System Disk Space Usage
* **Syntax**: `df [OPTION]... [FILE]...`
* **Key Flags**: `-h` (human-readable), `-T` (print filesystem type).
* **Security Example**:
  ```bash
  df -hT | grep -v "tmpfs"
  ```
* **Audit Context**: Displays mounted physical partitions and confirms whether partitions are mounted with restrictive security options such as `noexec` (preventing binary execution) or `nosuid`.

#### 8. `du` — Estimate File Space Usage
* **Syntax**: `du [OPTION]... [FILE]...`
* **Key Flags**: `-s` (summary total), `-h` (human-readable), `--max-depth=N`.
* **Security Example**:
  ```bash
  du -sh /var/log/
  ```
* **Audit Context**: Identifies abnormally large directories, discovering massive database dumps, hidden archive staging directories, or runaway log files.

#### 9. `dmesg` — Print or Control the Kernel Ring Buffer
* **Syntax**: `dmesg [options]`
* **Key Flags**: `-T` (human-readable timestamps), `-l` (restrict output to specific log levels: err, crit, alert).
* **Security Example**:
  ```bash
  dmesg -T | grep -E "segfault|promiscuous|USB"
  ```
* **Audit Context**: Discloses kernel-level hardware events, network cards placed in promiscuous mode (sniffing), segmentation faults caused by buffer overflow attempts, and newly inserted USB hardware.

#### 10. `journalctl` — Query the systemd System Journal
* **Syntax**: `journalctl [OPTIONS...] [MATCHES...]`
* **Key Flags**: `-u [unit]` (filter by specific systemd service), `-xe` (jump to end with explanatory details), `-f` (follow live output), `-p err` (filter errors only).
* **Security Example**:
  ```bash
  journalctl -u ssh -n 20 --no-pager
  ```
* **Audit Context**: The modern unified logging utility on systemd systems. Extracts raw service logs, authentication attempts, and system crash diagnostics.

---

### Domain 2: File Navigation, Inspection & Manipulation

#### 11. `ls` — List Directory Contents
* **Syntax**: `ls [OPTION]... [FILE]...`
* **Key Flags**: `-l` (long listing format: permissions, owner, group, size, date), `-a` (all files including hidden dotfiles), `-h` (human-readable sizes), `-t` (sort by modification time).
* **Security Example**:
  ```bash
  ls -la /var/www/html/
  ```
* **Audit Context**: Reveals hidden configuration files (e.g., `.env`, `.git/`, `.htaccess`) and evaluates file permissions.

#### 12. `cd` — Change the Working Directory
* **Syntax**: `cd [directory]`
* **Key Flags**: `~` (home directory), `-` (toggle back to previous directory), `..` (move up one directory).
* **Security Example**:
  ```bash
  cd /var/log && pwd
  ```
* **Audit Context**: Fundamental shell navigation primitive used across all automation scripts and manual investigation workflows.

#### 13. `pwd` — Print Name of Current/Working Directory
* **Syntax**: `pwd [OPTION]...`
* **Key Flags**: `-P` (print physical path resolving all symlinks).
* **Security Example**:
  ```bash
  pwd -P
  ```
* **Audit Context**: Confirms absolute physical location, avoiding navigation errors caused by nested symbolic links.

#### 14. `cat` — Concatenate Files and Print on Standard Output
* **Syntax**: `cat [OPTION]... [FILE]...`
* **Key Flags**: `-n` (number all output lines), `-A` (show all non-printing characters).
* **Security Example**:
  ```bash
  cat -n /etc/issue
  ```
* **Audit Context**: Fast file content inspection. Displays system banners, small configuration files, and script contents.

#### 15. `less` — Opposite of More (Paged File Inspection)
* **Syntax**: `less [OPTION]... FILE...`
* **Key Flags**: `-N` (line numbers), `-S` (chop long lines). Inside less: `/pattern` searches forward, `q` exits.
* **Security Example**:
  ```bash
  less -N /var/log/auth.log
  ```
* **Audit Context**: Essential for analyzing massive log files without loading the entire multi-gigabyte file into memory, preventing terminal memory exhaustion.

#### 16. `head` — Output the First Part of Files
* **Syntax**: `head [OPTION]... [FILE]...`
* **Key Flags**: `-n [N]` (print first N lines), `-c [N]` (print first N bytes).
* **Security Example**:
  ```bash
  head -n 5 /etc/passwd
  ```
* **Audit Context**: Rapid triage of the top rows of database dumps, CSV files, and header records.

#### 17. `tail` — Output the Last Part of Files
* **Syntax**: `tail [OPTION]... [FILE]...`
* **Key Flags**: `-n [N]` (print last N lines), `-f` (follow: continuously output appended data as file grows).
* **Security Example**:
  ```bash
  tail -f /var/log/nginx/access.log
  ```
* **Audit Context**: Real-time monitoring of live application traffic, brute-force attacks, and server responses during testing.

#### 18. `cp` — Copy Files and Directories
* **Syntax**: `cp [OPTION]... SOURCE... DIRECTORY`
* **Key Flags**: `-r` / `-R` (recursive copy), `-p` (preserve file attributes: timestamps, ownership, permissions), `-a` (archive mode).
* **Security Example**:
  ```bash
  cp -a /etc/shadow /tmp/shadow.backup
  ```
* **Audit Context**: Creating forensically pristine backups of critical configuration files before conducting modifications.

#### 19. `mv` — Move (Rename) Files
* **Syntax**: `mv [OPTION]... SOURCE... DIRECTORY`
* **Key Flags**: `-n` (do not overwrite existing file), `-v` (verbose).
* **Security Example**:
  ```bash
  mv payload.sh /opt/security_tools/
  ```
* **Audit Context**: Moving staged binaries and reorganizing evidence stores during assessments.

#### 20. `rm` — Remove Files or Directories
* **Syntax**: `rm [OPTION]... [FILE]...`
* **Key Flags**: `-r` (recursive), `-f` (force: ignore nonexistent files, never prompt).
* **Security Example**:
  ```bash
  rm -f /tmp/temporary_artifact.bin
  ```
* **Audit Context**: Post-assessment cleanup of temporary audit files, ensuring no residual testing files are left behind on client hosts.

#### 21. `mkdir` — Make Directories
* **Syntax**: `mkdir [OPTION]... DIRECTORY...`
* **Key Flags**: `-p` (create parent directories as needed without error), `-m [mode]` (set file mode directly).
* **Security Example**:
  ```bash
  mkdir -p -m 700 /tmp/audit_staging/
  ```
* **Audit Context**: Creating dedicated, restrictive temporary staging folders protected against snooping by other local unprivileged users.

#### 22. `touch` — Change File Timestamps / Create Empty Files
* **Syntax**: `touch [OPTION]... FILE...`
* **Key Flags**: `-a` (access time only), `-m` (modification time only), `-r [reference_file]` (copy timestamps from reference file).
* **Security Example**:
  ```bash
  touch -r /bin/ls modified_script.sh
  ```
* **Audit Context**: Known as "timestomping" in incident response. Attackers match file modification dates to surrounding system files to evade naive timeline analysis; defenders must detect timestamp discrepancies using filesystem metadata.

#### 23. `ln` — Make Links Between Files
* **Syntax**: `ln [OPTION]... TARGET LINK_NAME`
* **Key Flags**: `-s` (create symbolic/soft link), `-f` (force removal of destination file).
* **Security Example**:
  ```bash
  ln -s /etc/shadow /tmp/shadow_symlink
  ```
* **Audit Context**: Symbolic link races (TOCTOU) and path traversal exploits frequently utilize symlinks to fool applications into opening privileged files.

#### 24. `tar` — Archive and Compress Files
* **Syntax**: `tar [OPTION...] [FILE]...`
* **Key Flags**: `-c` (create archive), `-x` (extract archive), `-z` (compress with gzip), `-v` (verbose), `-f [file]` (archive filename).
* **Security Example**:
  ```bash
  tar -czvf evidence_logs.tar.gz /var/log/
  ```
* **Audit Context**: Secure packaging of log files, digital evidence collections, and assessment artifacts for cryptographic hashing and transport.

---

### Domain 3: Permissions, Ownership & Access Control

#### 25. `chmod` — Change File Mode Bits (Permissions)
* **Syntax**: `chmod [OPTION]... MODE[,MODE]... FILE...`
* **Key Modes**: Numeric (`755`, `644`, `600`), Symbolic (`u+x`, `g-w`, `o=r`), SUID (`4755`), SGID (`2755`), Sticky bit (`1777`).
* **Security Example**:
  ```bash
  chmod 600 ~/.ssh/id_rsa
  ```
* **Audit Context**: Enforcing strict permissions on private keys. Removing unnecessary execute or world-writable permissions from system directories.

#### 26. `chown` — Change File Owner and Group
* **Syntax**: `chown [OPTION]... [OWNER][:[GROUP]] FILE...`
* **Key Flags**: `-R` (operate recursively).
* **Security Example**:
  ```bash
  chown -R root:root /etc/cron.d/
  ```
* **Audit Context**: Remediating orphaned files (files belonging to deleted UIDs) and ensuring privileged service scripts are owned exclusively by `root`.

#### 27. `umask` — Set or Display File Mode Creation Mask
* **Syntax**: `umask [-S] [mode]`
* **Key Flags**: `-S` (print symbolic umask).
* **Security Example**:
  ```bash
  umask 027
  ```
* **Audit Context**: Defines default permissions for newly created files. A system umask of `022` creates world-readable files (`644`), whereas a hardened enterprise umask of `027` prevents "others" from reading newly created files.

#### 28. `getfacl` — Get File Access Control Lists
* **Syntax**: `getfacl [-aceEsRLPtpndvh] file ...`
* **Key Flags**: `-R` (recursive), `-a` (display file access control list).
* **Security Example**:
  ```bash
  getfacl /var/backups/database.sql
  ```
* **Audit Context**: Standard `ls -l` only displays traditional owner/group/other permissions (a trailing `+` indicates ACL presence). `getfacl` exposes hidden granular user/group permissions that may grant unprivileged users unauthorized access.

#### 29. `setfacl` — Set File Access Control Lists
* **Syntax**: `setfacl [-bkndRLP] [{-m|-x} acl_spec] [{-M|-X} acl_file] file ...`
* **Key Flags**: `-m [rule]` (modify existing ACL), `-x [rule]` (remove ACL entry), `-b` (remove all extended ACL entries).
* **Security Example**:
  ```bash
  setfacl -m u:alice:r-- /opt/confidential.txt
  ```
* **Audit Context**: Allows fine-grained access control delegation without changing the primary group ownership of a sensitive file.

---

### Domain 4: Text Processing, Pattern Matching & Search

#### 30. `grep` — Print Lines Matching a Pattern
* **Syntax**: `grep [OPTION...] PATTERNS [FILE...]`
* **Key Flags**: `-i` (case-insensitive), `-r` / `-R` (recursive), `-n` (line numbers), `-v` (invert match), `-E` (extended regular expressions).
* **Security Example**:
  ```bash
  grep -rnEi "password|secret|api_key" /var/www/html/
  ```
* **Audit Context**: The universal text searching tool. Locates hardcoded credentials in source code, parses log entries, and filters reconnaissance output.

#### 31. `find` — Search for Files in a Directory Hierarchy
* **Syntax**: `find [-H] [-L] [-P] [path...] [expression]`
* **Key Expressions**: `-name [glob]`, `-type [f/d/l]`, `-perm [mode]`, `-user [name]`, `-exec [cmd] {} \;`.
* **Security Example**:
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```
* **Audit Context**: **The most important Linux privilege-escalation discovery command.** The command above finds every binary on the entire filesystem with the SUID bit set (`-perm -4000`), suppressing permission denied errors (`2>/dev/null`).

#### 32. `awk` — Pattern Scanning and Processing Language
* **Syntax**: `awk [options] 'program' [file...]`
* **Key Flags**: `-F [delim]` (define input field separator).
* **Security Example**:
  ```bash
  awk -F: '($3 == 0) {print $1}' /etc/passwd
  ```
* **Audit Context**: Identifies all user accounts in `/etc/passwd` that possess `UID 0` (super-user privileges). In a secure environment, `root` must be the only account returned.

#### 33. `sed` — Stream Editor for Filtering and Transforming Text
* **Syntax**: `sed [OPTION]... {script} [input-file]...`
* **Key Flags**: `-i` (edit files in-place), `-e` (add script to commands).
* **Security Example**:
  ```bash
  sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  ```
* **Audit Context**: Rapid automated hardening of configuration files across fleets of servers without manual interactive text editing.

#### 34. `wc` — Print Newline, Word, and Byte Counts for Each File
* **Syntax**: `wc [OPTION]... [FILE]...`
* **Key Flags**: `-l` (lines count), `-c` (byte count), `-w` (word count).
* **Security Example**:
  ```bash
  cat /var/log/auth.log | grep "Failed password" | wc -l
  ```
* **Audit Context**: Quantifies brute-force attack attempts, calculates dictionary line lengths, and verifies file sizes.

#### 35. `sort` — Sort Lines of Text Files
* **Syntax**: `sort [OPTION]... [FILE]...`
* **Key Flags**: `-u` (unique), `-n` (numeric sort), `-r` (reverse order).
* **Security Example**:
  ```bash
  cat web_access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 10
  ```
* **Audit Context**: Classic security analysis pipeline: extracts IP addresses, counts frequency of occurrence, sorts numerically, and returns the top 10 most aggressive connecting client IPs.

#### 36. `uniq` — Report or Omit Repeated Lines
* **Syntax**: `uniq [OPTION]... [INPUT [OUTPUT]]`
* **Key Flags**: `-c` (prefix lines by number of occurrences), `-d` (only print duplicate lines).
* **Security Example**:
  ```bash
  uniq -c ip_list.txt
  ```
* **Audit Context**: Deduplicates lists of enumerated subdomains, open ports, and usernames.

#### 37. `diff` — Compare Files Line by Line
* **Syntax**: `diff [OPTION]... FILES`
* **Key Flags**: `-u` (unified output format), `-r` (recursive directory comparison).
* **Security Example**:
  ```bash
  diff -u /etc/sudoers /etc/sudoers.clean_baseline
  ```
* **Audit Context**: Detects unauthorized modifications or backdoor additions by comparing live configuration files against pristine, known-good baselines.

---

### Domain 5: Process Management, Services & Scheduling

#### 38. `ps` — Report a Snapshot of the Current Processes
* **Syntax**: `ps [options]`
* **Key Flags**: `aux` (BSD syntax: all users, user format, include processes without TTY), `-ef` (Standard syntax: all processes with full listing).
* **Security Example**:
  ```bash
  ps aux | grep -i root
  ```
* **Audit Context**: Identifies all running processes, their parent PIDs, user ownership, memory utilization, and the exact command-line arguments passed at execution.

#### 39. `top` / `htop` — Display Linux Processes Dynamically
* **Syntax**: `top [options]`
* **Key Commands Inside top**: `k` (kill process), `M` (sort by memory), `P` (sort by CPU), `q` (quit).
* **Security Example**:
  ```bash
  top -b -n 1 | head -n 20
  ```
* **Audit Context**: Real-time performance monitor. Detects hidden cryptominers, runaway exploit loops, and denial-of-service thread exhaustion.

#### 40. `kill` / `pkill` — Send Signals to Processes
* **Syntax**: `kill [-s sigspec | -n signum | -sigspec] pid...`
* **Key Signals**: `9` (`SIGKILL` - immediate non-catchable termination), `15` (`SIGTERM` - graceful termination signal).
* **Security Example**:
  ```bash
  kill -9 1337
  pkill -f nc
  ```
* **Audit Context**: Terminating rogue network listeners, malicious reverse shells, or unresponsive services.

#### 41. `systemctl` — Control the systemd System and Service Manager
* **Syntax**: `systemctl [OPTIONS...] COMMAND [UNIT...]`
* **Key Commands**: `status [service]`, `start`, `stop`, `restart`, `enable`, `disable`, `list-units --type=service`.
* **Security Example**:
  ```bash
  systemctl list-units --type=service --state=running
  ```
* **Audit Context**: Audits active background daemons. Identifies unauthorized background services and inspects service isolation settings (`systemctl show -p ProtectSystem [service]`).

#### 42. `crontab` — Maintain Crontab Files for Individual Users
* **Syntax**: `crontab [-u user] file`
* **Key Flags**: `-l` (list user's crontab entries), `-e` (edit crontab).
* **Security Example**:
  ```bash
  crontab -l
  crontab -u root -l
  ```
* **Audit Context**: Primary Linux persistence mechanism. Adversaries schedule periodic cron scripts to maintain access across reboots.

#### 43. `lsof` — List Open Files and Associated Network Sockets
* **Syntax**: `lsof [options] [file]`
* **Key Flags**: `-i` (list all network sockets), `-i :[port]` (list processes on specific port), `-p [PID]` (list all files opened by specific PID).
* **Security Example**:
  ```bash
  lsof -i :443
  ```
* **Audit Context**: Connects open network ports directly to the exact process executable and PID handling the traffic. Essential for hunting unmapped backdoors and rogue listeners.

---

### Domain 6: Identity, User Management & Authentication

#### 44. `whoami` — Print Effective User ID
* **Syntax**: `whoami [OPTION]...`
* **Security Example**:
  ```bash
  whoami
  ```
* **Audit Context**: Immediate confirmation of the active shell identity (e.g., `www-data`, `kali`, `root`).

#### 45. `id` — Print Real and Effective User and Group IDs
* **Syntax**: `id [OPTION]... [USER]`
* **Key Flags**: `-u` (UID only), `-g` (GID only), `-G` (all group IDs).
* **Security Example**:
  ```bash
  id
  ```
* **Audit Context**: **More informative than `whoami`**. Discloses secondary group memberships. If a user is a member of the `docker`, `lxd`, `disk`, or `sudo` groups, immediate privilege escalation to root is typically possible.

#### 46. `sudo` — Execute a Command as Another User (Superuser)
* **Syntax**: `sudo [-u user] command`
* **Key Flags**: `-l` (list allowed/forbidden commands for invoking user), `-i` (simulate initial login as root).
* **Security Example**:
  ```bash
  sudo -l
  ```
* **Audit Context**: **The primary command executed upon gaining access to a Linux shell.** Discloses whether the current user is permitted to execute specific binaries with root privileges without entering a password (`NOPASSWD`).

#### 47. `useradd` / `usermod` / `userdel` — User Account Administration
* **Syntax**: `useradd [options] LOGIN`
* **Key Flags**: `-m` (create home dir), `-s [shell]` (login shell), `-G [groups]` (append secondary groups).
* **Security Example**:
  ```bash
  useradd -m -s /bin/bash audit_analyst
  usermod -aG sudo audit_analyst
  ```
* **Audit Context**: Creating dedicated, non-root user accounts for assessment activities or locking dormant accounts (`usermod -L [user]`).

#### 48. `passwd` — Change User Password
* **Syntax**: `passwd [options] [LOGIN]`
* **Key Flags**: `-l` (lock account password), `-u` (unlock account), `-S` (display password status).
* **Security Example**:
  ```bash
  passwd -S root
  ```
* **Audit Context**: Auditing password status (Password set `P`, Locked `L`, No password `NP`) across system accounts.

---

### Domain 7: Networking, Routing & Sockets

#### 49. `ss` — Another Utility to Investigate Sockets (Modern Netstat Replacement)
* **Syntax**: `ss [options] [FILTER]`
* **Key Flags**: `-t` (TCP sockets), `-u` (UDP sockets), `-l` (listening sockets), `-n` (numeric: show port numbers), `-p` (show process using socket).
* **Security Example**:
  ```bash
  ss -tulnp
  ```
* **Audit Context**: **High-speed socket auditing.** Instantly identifies all internal services listening on `127.0.0.1` (loopback) that are hidden from external network port scans.

#### 50. `ip` — Show / Manipulate Routing, Network Devices, Interfaces and Tunnels
* **Syntax**: `ip [ OPTIONS ] OBJECT { COMMAND | help }`
* **Key Objects**: `addr` (IP addresses), `route` (routing tables), `neigh` (ARP cache).
* **Security Example**:
  ```bash
  ip a
  ip route show
  ```
* **Audit Context**: Modern replacement for `ifconfig` and `route`. Discloses multi-homed network adapters, VLAN tags, and internal default gateways used for pivoting.

---

## 7. Top 50 Essential Windows Commands for Security Auditors

Windows assessment environments require proficiency across both the traditional Windows Command Prompt (`cmd.exe` / CLI built-ins) and the modern object-oriented **PowerShell** scripting environment (`powershell.exe`). The following 50 commands cover the full spectrum of Windows administrative and host auditing tasks.

### Domain 1: System Reconnaissance & Architecture

#### 1. `systeminfo` (CMD) / `Get-ComputerInfo` (PowerShell)
* **Syntax (CMD)**: `systeminfo [/s computer [/u domain\user [/p password]]] [/fo {TABLE|LIST|CSV}]`
* **Syntax (PS)**: `Get-ComputerInfo [[-Property] <String[]>]`
* **Security Example**:
  ```cmd
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
  ```
  ```powershell
  Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture, OsHotFixes
  ```
* **Audit Context**: Extracts operating system build numbers, domain membership, hotfix patch count, and memory configuration to identify missing security updates.

#### 2. `hostname` (CMD / PS)
* **Syntax**: `hostname`
* **Security Example**:
  ```cmd
  hostname
  ```
* **Audit Context**: Confirms the local computer name. Often hints at system roles (`DC01` = Domain Controller, `SQLPROD` = Production Database).

#### 3. `wmic qfe` (CMD) / `Get-HotFix` (PowerShell)
* **Syntax (CMD)**: `wmic qfe get Caption,Description,HotFixID,InstalledOn`
* **Syntax (PS)**: `Get-HotFix [-Id <String[]>]`
* **Security Example**:
  ```cmd
  wmic qfe get HotFixID,InstalledOn
  ```
  ```powershell
  Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
  ```
* **Audit Context**: Enumerates installed Quick Fix Engineering (QFE) patches. Cross-referencing against Microsoft Security Bulletins reveals whether the machine is vulnerable to specific local privilege escalation exploits.

#### 4. `set` (CMD) / `Get-ChildItem Env:` (PowerShell)
* **Syntax (CMD)**: `set [variable=[string]]`
* **Syntax (PS)**: `Get-ChildItem Env:`
* **Security Example**:
  ```cmd
  set
  ```
  ```powershell
  Get-ChildItem Env: | Select-Object Name, Value
  ```
* **Audit Context**: Dumps all system and user environment variables. Exposes Active Directory Logon Servers (`LOGONSERVER`), User Domains (`USERDOMAIN`), and third-party API tokens stored in session variables.

#### 5. `driverquery` (CMD)
* **Syntax**: `driverquery [/v] [/fo {TABLE|LIST|CSV}]`
* **Key Flags**: `/v` (verbose output: includes driver path and state).
* **Security Example**:
  ```cmd
  driverquery /v /fo csv | findstr /i "Kernel"
  ```
* **Audit Context**: Enumerates installed third-party kernel drivers (`.sys`). Vulnerable, signed third-party drivers (Bring Your Own Vulnerable Driver - BYOVD) are commonly targeted by threat actors to disable EDR sensors from Ring 0.

#### 6. `gpresult` (CMD)
* **Syntax**: `gpresult [/s Computer [/u Domain\User [/p Password]]] [/user TargetUserName] [/r | /v | /z]`
* **Key Flags**: `/r` (summary RSoP data), `/v` (verbose details), `/scope {user|computer}`.
* **Security Example**:
  ```cmd
  gpresult /r
  ```
* **Audit Context**: Displays the **Resultant Set of Policy (RSoP)** applied via Active Directory Group Policy Objects (GPOs). Confirms AppLocker rules, audit policies, and restricted group memberships.

#### 7. `nltest` (CMD)
* **Syntax**: `nltest [/options]`
* **Key Flags**: `/dsgetdc:[domain]` (locate domain controller), `/dclist:[domain]` (list all domain controllers), `/domain_trusts` (map domain trust relationships).
* **Security Example**:
  ```cmd
  nltest /domain_trusts
  ```
* **Audit Context**: Primary Active Directory reconnaissance utility. Maps trust relationships between enterprise forests (one-way, two-way, transitive) and locates accessible Domain Controllers.

---

### Domain 2: User Accounts, Groups & Privilege Auditing

#### 8. `whoami /all` (CMD / PS)
* **Syntax**: `whoami [/user] [/groups] [/priv] [/fo {table|list|csv}] [/all]`
* **Security Example**:
  ```cmd
  whoami /all
  ```
* **Audit Context**: **The single most vital Windows enumeration command.** Displays:
  1. User name and Security Identifier (**SID**).
  2. Group memberships (e.g., `BUILTIN\Administrators`, `Remote Desktop Users`).
  3. Security Privileges (e.g., `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`).
  4. Mandatory Integrity Level (e.g., `High Mandatory Level` vs `Medium Mandatory Level`).

#### 9. `whoami /priv` (CMD / PS)
* **Syntax**: `whoami /priv`
* **Security Example**:
  ```cmd
  whoami /priv
  ```
* **Audit Context**: Rapidly isolates token privileges. If `SeImpersonatePrivilege` is enabled, local privilege escalation to `NT AUTHORITY\SYSTEM` is achievable via Potato family exploits (SweetPotato, PrintSpoofer).

#### 10. `net user` (CMD) / `Get-LocalUser` (PowerShell)
* **Syntax (CMD)**: `net user [username [password | *] [options]] [/domain]`
* **Syntax (PS)**: `Get-LocalUser [[-Name] <String[]>]`
* **Security Example**:
  ```cmd
  net user
  net user /domain
  net user Administrator
  ```
* **Audit Context**: Lists local accounts. When appended with `/domain`, queries the Active Directory Domain Controller to list all enterprise domain user accounts.

#### 11. `net localgroup` (CMD) / `Get-LocalGroupMember` (PowerShell)
* **Syntax (CMD)**: `net localgroup [groupname [/comment:"text"]] [/domain]`
* **Syntax (PS)**: `Get-LocalGroupMember [-Group] <LocalGroup>`
* **Security Example**:
  ```cmd
  net localgroup administrators
  ```
  ```powershell
  Get-LocalGroupMember -Group "Administrators"
  ```
* **Audit Context**: Identifies all local and domain accounts possessing administrative control over the machine.

#### 12. `cmdkey` (CMD)
* **Syntax**: `cmdkey [{/list | /generic:target | /delete:target}]`
* **Security Example**:
  ```cmd
  cmdkey /list
  ```
* **Audit Context**: Lists credentials cached in the Windows Credential Manager. If credentials have `Type: Domain Password` stored, commands can be spawned as that credential using `runas /savecred`.

#### 13. `klist` (CMD)
* **Syntax**: `klist [tickets | tgt | purge]`
* **Security Example**:
  ```cmd
  klist
  ```
* **Audit Context**: Displays cached Kerberos tickets (Ticket Granting Tickets - TGT, and Service Tickets - TGS) in current user session memory. Used to detect pass-the-ticket and Kerberoasting attacks.

#### 14. `qwinsta` / `query user` (CMD)
* **Syntax**: `qwinsta [username | sessionname | sessionid]`
* **Security Example**:
  ```cmd
  qwinsta
  ```
* **Audit Context**: Queries active Remote Desktop (RDP) sessions. Discloses logged-in high-privilege administrative users whose sessions can be hijacked if local administrative access is attained.

---

### Domain 3: File & Directory Manipulation

#### 15. `dir` (CMD) / `Get-ChildItem` (PowerShell)
* **Syntax (CMD)**: `dir [drive:][path][filename] [/p] [/w] [/a[[:]attributes]] [/o[[:]sortorder]] [/s]`
* **Key Flags (CMD)**: `/a` (display all files including hidden/system), `/s` (recurse into subdirectories).
* **Syntax (PS)**: `Get-ChildItem [-Path <string[]>] [-Recurse] [-Force]`
* **Security Example**:
  ```cmd
  dir /a /s C:\Users\*.kdbx
  ```
  ```powershell
  Get-ChildItem -Path C:\Users\ -Filter *.kdbx -Recurse -Force -ErrorAction SilentlyContinue
  ```
* **Audit Context**: Locates KeePass password vaults (`.kdbx`), configuration files (`web.config`, `unattend.xml`), and backup archives across all drives.

#### 16. `type` (CMD) / `Get-Content` (PowerShell)
* **Syntax (CMD)**: `type [drive:][path]filename`
* **Syntax (PS)**: `Get-Content [-Path] <string[]>`
* **Security Example**:
  ```cmd
  type C:\Windows\System32\drivers\etc\hosts
  ```
  ```powershell
  Get-Content C:\Windows\System32\drivers\etc\hosts
  ```
* **Audit Context**: Reads text file contents directly to standard output. Equivalent to Linux `cat`.

#### 17. `copy` / `xcopy` / `robocopy` (CMD) / `Copy-Item` (PowerShell)
* **Syntax (CMD)**: `robocopy <Source> <Destination> [<File>[ ...]] [<Options>]`
* **Security Example**:
  ```cmd
  robocopy C:\Logs C:\EvidenceBackup /E /ZB /COPYALL
  ```
* **Audit Context**: `robocopy` (Robust File Copy) features advanced forensic capability: the `/ZB` flag attempts restartable mode and falls back to Backup mode, copying files even when access would normally be blocked by ACLs if the user has `SeBackupPrivilege`.

#### 18. `del` (CMD) / `Remove-Item` (PowerShell)
* **Syntax (CMD)**: `del [/p] [/f] [/s] [/q] [/a[[:]attributes]] names`
* **Security Example**:
  ```cmd
  del /f /q C:\Temp\test_payload.exe
  ```
* **Audit Context**: Deletes files without moving them to the Recycle Bin. Used during remediation and post-testing cleanup.

#### 19. `tree` (CMD)
* **Syntax**: `tree [drive:][path] [/f] [/a]`
* **Key Flags**: `/f` (display names of files in each folder), `/a` (use ASCII characters).
* **Security Example**:
  ```cmd
  tree C:\inetpub\wwwroot /f /a
  ```
* **Audit Context**: Generates an instantaneous visual hierarchical tree of web applications and deep folder structures.

---

### Domain 4: Process & Service Auditing

#### 20. `tasklist` (CMD) / `Get-Process` (PowerShell)
* **Syntax (CMD)**: `tasklist [/s Computer [/u Domain\User [/p Password]]] [/m [Module] | /svc | /v]`
* **Key Flags (CMD)**: `/svc` (maps running services to host processes), `/v` (verbose).
* **Security Example**:
  ```cmd
  tasklist /svc
  ```
  ```powershell
  Get-Process | Select-Object Id, ProcessName, Path, Company | Sort-Object Id
  ```
* **Audit Context**: Maps active processes to running Windows Services. Crucial for identifying third-party security agents (CrowdStrike, SentinelOne, Carbon Black) and unquoted service paths.

#### 21. `taskkill` (CMD) / `Stop-Process` (PowerShell)
* **Syntax (CMD)**: `taskkill [/s Computer [/u Domain\User [/p Password]]] { [/fi Filter] [/pid ProcessID | /im ImageName] } [/f] [/t]`
* **Key Flags (CMD)**: `/f` (force termination), `/t` (terminate process and all child processes).
* **Security Example**:
  ```cmd
  taskkill /f /im rogue_service.exe
  ```
* **Audit Context**: Forcefully terminating malicious processes or stopping hanging assessment tools.

#### 22. `sc` (Service Controller) (CMD) / `Get-Service` (PowerShell)
* **Syntax (CMD)**: `sc <server> [command] [service_name] <option1> <option2>...`
* **Key Commands**: `query [name]`, `qc [name]` (query configuration: binary path, start type), `config`, `start`, `stop`.
* **Security Example**:
  ```cmd
  sc qc Spooler
  ```
  ```powershell
  Get-Service -Name Spooler | Select-Object Name, DisplayName, Status, StartType
  ```
* **Audit Context**: **The standard utility for service privilege-escalation auditing.** `sc qc` displays the `BINARY_PATH_NAME` and `SERVICE_START_NAME` (account context, e.g., `LocalSystem`). If unprivileged users can modify service configurations via `sc config`, immediate root/SYSTEM elevation is attained.

#### 23. `schtasks` (CMD) / `Get-ScheduledTask` (PowerShell)
* **Syntax (CMD)**: `schtasks [/run | /end | /create | /delete | /query | /change]`
* **Security Example**:
  ```cmd
  schtasks /query /fo LIST /v | findstr /i "TaskName Author Next"
  ```
  ```powershell
  Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, TaskPath
  ```
* **Audit Context**: Audits automated scheduled jobs running under SYSTEM privileges that execute writable scripts or binaries.

---

### Domain 5: Network Sockets, Interfaces & Firewall

#### 24. `ipconfig` (CMD) / `Get-NetIPConfiguration` (PowerShell)
* **Syntax (CMD)**: `ipconfig [/all | /renew | /release | /flushdns | /displaydns]`
* **Security Example**:
  ```cmd
  ipconfig /all
  ```
  ```powershell
  Get-NetIPConfiguration
  ```
* **Audit Context**: Displays IP addresses, subnet masks, default gateways, and corporate DNS domain suffix search lists. Reveals secondary interfaces attached to internal networks.

#### 25. `netstat` (CMD) / `Get-NetTCPConnection` (PowerShell)
* **Syntax (CMD)**: `netstat [-a] [-b] [-e] [-n] [-o] [-p proto] [-r] [-s] [interval]`
* **Key Flags (CMD)**: `-a` (all connections and listening ports), `-n` (numerical addresses), `-o` (display owning process PID), `-b` (display executable involved in connection creation - requires admin).
* **Security Example**:
  ```cmd
  netstat -ano
  ```
  ```powershell
  Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
  ```
* **Audit Context**: **Identifies hidden internal listeners.** Discloses administrative web dashboards, database interfaces, and debug ports listening strictly on `127.0.0.1`.

#### 26. `route print` (CMD) / `Get-NetRoute` (PowerShell)
* **Syntax (CMD)**: `route [-f] [-p] [command [destination] [MASK netmask] [gateway] [METRIC metric]]`
* **Security Example**:
  ```cmd
  route print
  ```
  ```powershell
  Get-NetRoute -AddressFamily IPv4
  ```
* **Audit Context**: Displays the IPv4 and IPv6 kernel routing tables. Identifies static routes configured to tunnel traffic through internal enterprise VPNs or management networks.

#### 27. `arp -a` (CMD) / `Get-NetNeighbor` (PowerShell)
* **Syntax (CMD)**: `arp [-a [inet_addr] [-N if_addr]]`
* **Security Example**:
  ```cmd
  arp -a
  ```
  ```powershell
  Get-NetNeighbor -AddressFamily IPv4
  ```
* **Audit Context**: Dumps the local Address Resolution Protocol (ARP) cache. Reveals IP-to-MAC mappings of recently contacted neighboring hosts on the local network segment, instantly identifying active peers without sending network probe packets.

#### 28. `tracert` (CMD) / `Test-NetConnection` (PowerShell)
* **Syntax (CMD)**: `tracert [-d] [-h maximum_hops] target_name`
* **Syntax (PS)**: `Test-NetConnection -ComputerName <string> -Port <int>`
* **Security Example**:
  ```powershell
  Test-NetConnection -ComputerName 10.10.10.10 -Port 445
  ```
* **Audit Context**: `Test-NetConnection` is a versatile modern diagnostic tool that acts as ping, traceroute, and a TCP port scanner in one command, verifying socket connectivity across firewalls.

#### 29. `nslookup` (CMD) / `Resolve-DnsName` (PowerShell)
* **Syntax (CMD)**: `nslookup [-subcommand ...] [computer-to-find | - [server]]`
* **Security Example**:
  ```cmd
  nslookup -type=SRV _ldap._tcp.corp.internal
  ```
  ```powershell
  Resolve-DnsName -Name corp.internal -Type ALL
  ```
* **Audit Context**: Queries internal DNS servers for SRV records, locating Active Directory Domain Controllers (`_ldap._tcp.dc._msdcs.<domain>`) and Kerberos Key Distribution Centers.

#### 30. `netsh advfirewall` (CMD) / `Get-NetFirewallRule` (PowerShell)
* **Syntax (CMD)**: `netsh advfirewall firewall show rule name=all`
* **Security Example**:
  ```cmd
  netsh advfirewall show allprofiles state
  ```
  ```powershell
  Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object Name, DisplayName, Action
  ```
* **Audit Context**: Audits host firewall enforcement (Domain, Private, Public profiles) and inspects permitted inbound ports.

---

### Domain 6: Permissions, Access Control & The Registry

#### 31. `icacls` (CMD) / `Get-Acl` (PowerShell)
* **Syntax (CMD)**: `icacls <fileName> [/grant[:r] <Sid:perm>[...]] [/deny <Sid:perm>[...]] [/reset]`
* **Common Permissions**: `(F)` = Full Access, `(M)` = Modify, `(RX)` = Read & Execute, `(W)` = Write.
* **Security Example**:
  ```cmd
  icacls "C:\Program Files\EnterpriseApp\*"
  ```
  ```powershell
  Get-Acl -Path "C:\Program Files\EnterpriseApp" | Format-List
  ```
* **Audit Context**: **The primary Windows permission auditing tool.** Evaluates whether standard users possess `(M)` Modify or `(W)` Write permissions over service binaries, allowing binary replacement privilege escalation.

#### 32. `takeown` (CMD)
* **Syntax**: `takeown [/s Computer [/u [Domain\]User [/p Password]]] /f FileName [/a] [/r [/d {Y|N}]]`
* **Key Flags**: `/f` (target file/directory), `/a` (give ownership to Administrators group instead of user).
* **Security Example**:
  ```cmd
  takeown /f C:\ProtectedDirectory /r /a
  ```
* **Audit Context**: Reassigns file ownership to administrators when files have restrictive DACLs left by former users or legacy processes.

#### 33. `reg query` (CMD) / `Get-ItemProperty` (PowerShell)
* **Syntax (CMD)**: `reg query [KeyName] [/v ValueName | /ve] [/s]`
* **Key Hives**: `HKLM` (Local Machine), `HKCU` (Current User), `HKCR` (Classes Root).
* **Security Example**:
  ```cmd
  reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
  ```
* **Audit Context**: Queries registry values. The second example checks whether **LSA Protection (RunAsPPL)** is enabled, which prevents non-kernel processes from dumping LSASS memory.

#### 34. `reg add` (CMD) / `Set-ItemProperty` (PowerShell)
* **Syntax (CMD)**: `reg add [KeyName] [/v ValueName | /ve] [/t Type] [/d Data] [/f]`
* **Security Example**:
  ```cmd
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
  ```
* **Audit Context**: Modifies system configuration settings via the registry. Adversaries modify persistence keys; defenders write hardening policies.

#### 35. `reg save` (CMD)
* **Syntax**: `reg save [KeyName] [FileName] [/y]`
* **Security Example**:
  ```cmd
  reg save HKLM\SAM C:\Temp\sam.hive /y
  reg save HKLM\SYSTEM C:\Temp\system.hive /y
  ```
* **Audit Context**: Dumps entire registry hives to binary disk files. When executed by an administrator, copies of the `SAM` and `SYSTEM` hives can be extracted for offline password hash cracking.

#### 36. `findstr` (CMD) / `Select-String` (PowerShell)
* **Syntax (CMD)**: `findstr [/s] [/i] [/m] [/n] strings [[drive:][path]filename[ ...]]`
* **Security Example**:
  ```cmd
  findstr /si "password" *.txt *.xml *.ini *.config
  ```
  ```powershell
  Get-ChildItem -Path C:\inetpub\ -Recurse | Select-String -Pattern "connectionString"
  ```
* **Audit Context**: Recursively searches directory trees for plaintext credentials and connection strings inside configuration files.

#### 37. `certutil` (CMD)
* **Syntax**: `certutil [options] [arguments]`
* **Key Flags**: `-hashfile [file] [algo]` (calculate hash: SHA256, MD5), `-urlcache -split -f [url] [dest]` (file download utility).
* **Security Example**:
  ```cmd
  certutil -hashfile C:\Windows\System32\cmd.exe SHA256
  ```
* **Audit Context**: A versatile built-in administrative tool. Used to verify file hashes against baseline integrity lists, but frequently classified as a "Living-off-the-Land Binary" (LOLBIN) because it can also download arbitrary files from HTTP URLs.

#### 38. `wevtutil` (CMD) / `Get-WinEvent` (PowerShell)
* **Syntax (CMD)**: `wevtutil [{cl | clear-log} logname] [{qe | query-events} path [/q:query]]`
* **Security Example**:
  ```powershell
  Get-WinEvent -FilterHashtable @{LogName=Security; Id=4624} -MaxEvents 5
  ```
* **Audit Context**: Queries the Windows Event Log. Event ID `4624` tracks successful logons, Event ID `4625` tracks failed logins, and Event ID `4720` tracks account creation.

#### 39. `cipher` (CMD)
* **Syntax**: `cipher [/e | /d | /c] [/s:directory] [/b] [filename [...]]`
* **Security Example**:
  ```cmd
  cipher /w:C:\Temp
  ```
* **Audit Context**: Displays or configures NTFS Encryption (EFS). When run with `/w`, wipes deleted data in free unallocated disk space, preventing file carving recovery.

#### 40. `dsquery` (Active Directory CLI)
* **Syntax**: `dsquery [user | computer | group | server | contact | subnet]`
* **Security Example**:
  ```cmd
  dsquery user -name *admin*
  ```
* **Audit Context**: Directly queries the Active Directory LDAP catalog to discover enterprise domain administrators, high-value target servers, and subnets.

---

### Domain 7: Advanced PowerShell Security & Administration Commands

#### 41. `Get-ExecutionPolicy` & `Set-ExecutionPolicy` (PowerShell)
* **Syntax**: `Get-ExecutionPolicy [-List]`; `Set-ExecutionPolicy [-ExecutionPolicy] <Policy> [-Scope <Scope>]`
* **Security Example**:
  ```powershell
  Get-ExecutionPolicy -List
  ```
* **Audit Context**: Audits whether PowerShell script execution is restricted (`Restricted`, `RemoteSigned`, `Unrestricted`, `Bypass`). Note that Execution Policy is a safety control, not a security boundary.

#### 42. `Get-Acl` & `Set-Acl` (PowerShell)
* **Syntax**: `Get-Acl [[-Path] <String[]>]`
* **Security Example**:
  ```powershell
  (Get-Acl C:\Windows\System32\sethc.exe).AccessToString
  ```
* **Audit Context**: Audits Access Control Entries (ACEs) on accessibility binaries commonly targeted by Sticky Keys backdoors.

#### 43. `Get-ItemProperty` & `Set-ItemProperty` (PowerShell Registry)
* **Syntax**: `Get-ItemProperty [-Path] <string[]> [[-Name] <string[]>]`
* **Security Example**:
  ```powershell
  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher
  ```
* **Audit Context**: Inventories all installed applications on the Windows endpoint by interrogating the uninstall registry keys.

#### 44. `Invoke-WebRequest` / `Invoke-RestMethod` (PowerShell)
* **Syntax**: `Invoke-WebRequest [-Uri] <Uri> [-OutFile <string>] [-Headers <hashtable>]`
* **Security Example**:
  ```powershell
  Invoke-WebRequest -Uri "http://10.10.10.10/agent.msi" -OutFile "$env:TEMP\agent.msi"
  ```
* **Audit Context**: Downloads external toolsets, tests web endpoint availability, and interacts with REST APIs.

#### 45. `Get-WmiObject` / `Get-CimInstance` (PowerShell)
* **Syntax**: `Get-CimInstance [-ClassName] <string> [-Namespace <string>]`
* **Security Example**:
  ```powershell
  Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, OSArchitecture, LastBootUpTime
  Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
  ```
* **Audit Context**: Interrogates Windows Management Instrumentation (WMI). The second example audits WMI Event Subscriptions, one of the most stealthy fileless persistence mechanisms in Windows.

#### 46. `Get-AppLockerPolicy` (PowerShell)
* **Syntax**: `Get-AppLockerPolicy -Effective -Xml`
* **Security Example**:
  ```powershell
  Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
  ```
* **Audit Context**: Audits active application whitelisting policies to discover allowed executable paths or directory bypasses.

#### 47. `Test-Path` (PowerShell)
* **Syntax**: `Test-Path [-Path] <string[]>`
* **Security Example**:
  ```powershell
  Test-Path "C:\Windows\System32\drivers\CrowdStrike"
  ```
* **Audit Context**: Programmatically validates whether specific security sensors, registry keys, or credential stores exist without throwing error exceptions.

#### 48. `Export-Clixml` / `Import-Clixml` (PowerShell Secure Strings)
* **Syntax**: `Export-Clixml [-Path] <string> [-InputObject <psobject>]`
* **Security Example**:
  ```powershell
  $Cred = Get-Credential
  $Cred | Export-Clixml -Path "$env:USERPROFILE\secure_cred.xml"
  ```
* **Audit Context**: Demonstrates DPAPI-protected PowerShell credential export tied specifically to the user profile.

#### 49. `Get-Clipboard` (PowerShell)
* **Syntax**: `Get-Clipboard [-Raw]`
* **Security Example**:
  ```powershell
  Get-Clipboard
  ```
* **Audit Context**: Dumps current clipboard contents, which frequently contain passwords copied from password managers during administrative sessions.

#### 50. `Clear-History` & History File Audit (PowerShell)
* **Syntax**: `Clear-History [-Id <Int32[]>]`
* **Security Example**:
  ```powershell
  Get-Content (Get-PSReadLineOption).HistorySavePath
  ```
* **Audit Context**: Exposes the PSReadLine history file (located at `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`), which preserves all PowerShell commands executed across sessions.

---

## 8. Dual-Platform Command Rosetta Stone

The following cross-reference table allows security engineers to immediately map common administrative, audit, and investigative objectives between Linux, Windows CMD, and Windows PowerShell:

| Operational Objective | Linux Command | Windows Command Prompt (CMD) | Windows PowerShell |
| :--- | :--- | :--- | :--- |
| **Print User & Identity** | `whoami` / `id` | `whoami` | `whoami` / `[System.Security.Principal.WindowsIdentity]::GetCurrent().Name` |
| **List User Privileges** | `sudo -l` | `whoami /priv` | `whoami /priv` |
| **System Info & OS Build** | `uname -a` | `systeminfo` | `Get-ComputerInfo` |
| **List Directory Contents** | `ls -la` | `dir /a` | `Get-ChildItem -Force` |
| **Current Working Path** | `pwd` | `cd` | `Get-Location` / `pwd` |
| **Read File Contents** | `cat [file]` | `type [file]` | `Get-Content [file]` |
| **Continuous Log Follow** | `tail -f [file]` | *(No native utility)* | `Get-Content [file] -Wait -Tail 10` |
| **Search File Content** | `grep -i [pattern] [file]` | `findstr /i [pattern] [file]` | `Select-String -Pattern [pattern] -Path [file]` |
| **Find Files by Name** | `find / -name [pattern]` | `dir /s /b [pattern]` | `Get-ChildItem -Path C:\ -Filter [pattern] -Recurse` |
| **Find SUID / Privileged Executables** | `find / -perm -4000 2>/dev/null` | *(Inspect ACLs via `icacls`)* | `Get-ChildItem ... | Get-Acl` |
| **Copy Files** | `cp -r [src] [dst]` | `copy` / `robocopy [src] [dst]` | `Copy-Item -Recurse [src] [dst]` |
| **Move / Rename Files** | `mv [src] [dst]` | `move [src] [dst]` | `Move-Item [src] [dst]` |
| **Delete Files** | `rm -f [file]` | `del /f [file]` | `Remove-Item -Force [file]` |
| **Create Directory** | `mkdir -p [dir]` | `mkdir [dir]` | `New-Item -ItemType Directory -Path [dir]` |
| **Audit Permissions** | `ls -l [file]` / `getfacl [file]`| `icacls [file]` | `Get-Acl [file]` |
| **Modify Permissions** | `chmod [mode] [file]` | `icacls [file] /grant [rule]` | `Set-Acl [file]` |
| **Change File Owner** | `chown [owner] [file]` | `takeown /f [file]` | `(Get-Acl [file]).SetOwner(...)` |
| **List Running Processes** | `ps aux` | `tasklist` | `Get-Process` |
| **Kill Process by PID** | `kill -9 [pid]` | `taskkill /f /pid [pid]` | `Stop-Process -Id [pid] -Force` |
| **List Active Services** | `systemctl list-units --type=service`| `net start` / `sc query` | `Get-Service` |
| **Service Configuration** | `cat /etc/systemd/system/*.service` | `sc qc [service]` | `Get-CimInstance Win32_Service -Filter "Name=..."` |
| **Scheduled Tasks** | `crontab -l` / `cat /etc/crontab` | `schtasks /query /fo LIST` | `Get-ScheduledTask` |
| **List Network Interfaces**| `ip a` / `ifconfig` | `ipconfig /all` | `Get-NetIPConfiguration` |
| **List Listening Ports** | `ss -tulnp` / `netstat -tulnp` | `netstat -ano` | `Get-NetTCPConnection -State Listen` |
| **Routing Table** | `ip route show` | `route print` | `Get-NetRoute` |
| **ARP Cache** | `ip neigh` / `arp -a` | `arp -a` | `Get-NetNeighbor` |
| **DNS Resolution** | `dig [domain]` / `nslookup` | `nslookup [domain]` | `Resolve-DnsName [domain]` |
| **Test Remote TCP Port** | `nc -zv [host] [port]` | `telnet [host] [port]` | `Test-NetConnection [host] -Port [port]` |
| **Download Web File** | `curl -O [url]` / `wget [url]`| `certutil -urlcache -split -f [url]` | `Invoke-WebRequest -Uri [url] -OutFile [file]` |
| **Calculate File Hash** | `sha256sum [file]` | `certutil -hashfile [file] SHA256` | `Get-FileHash -Algorithm SHA256 [file]` |
| **List Logged-In Users** | `who` / `w` / `last` | `qwinsta` / `query user` | `Get-CimInstance Win32_LoggedOnUser` |
| **Local Accounts Audit** | `cat /etc/passwd` | `net user` | `Get-LocalUser` |
| **Local Admin Group** | `grep sudo /etc/group` | `net localgroup administrators` | `Get-LocalGroupMember -Group "Administrators"` |
| **Inspect Event Logs** | `journalctl -xe` / `/var/log/*`| `wevtutil qe Security /c:5` | `Get-WinEvent -LogName Security -MaxEvents 5` |
| **Environment Variables** | `env` / `printenv` | `set` | `Get-ChildItem Env:` |

---

## 9. Progressive Practice Exercises & Knowledge Verification

### Level 1: Foundational Host Reconnaissance (Beginner)
1. **Linux Practice**: Log into a Linux terminal. Run commands to output:
   - Kernel release string and hardware architecture (`uname -a`).
   - All environment variables currently set for your user (`env`).
   - All network sockets currently in a `LISTEN` state, resolving process IDs (`ss -tulnp`).
2. **Windows Practice**: Open Command Prompt (`cmd.exe`) and PowerShell. Run commands to output:
   - Operating system product name, build version, and installed hotfixes (`systeminfo`).
   - Your effective user SID and all enabled security privileges (`whoami /all`).
   - All local groups of which your user account is an active member (`net user %USERNAME%`).

### Level 2: Filesystem & Permission Auditing (Intermediate)
1. **Linux Practice**: Using `find`, locate all regular files in `/etc` modified within the last 7 days. Using `grep`, search `/var/log/` for any lines recording failed authentication attempts.
2. **Windows Practice**: In PowerShell, recursively search `C:\Program Files\` for `.exe` files and inspect their access control lists using `Get-Acl` to identify whether the `BUILTIN\Users` group possesses Write or Modify permissions.

### Level 3: Dual-Platform Cross-Analysis (Advanced)
1. Translate a bash reconnaissance one-liner that finds world-writable directories (`find / -type d -perm -0002 2>/dev/null`) into an equivalent PowerShell command utilizing `Get-ChildItem` and `Get-Acl`.
2. Trace the exact system call sequence of executing an unprivileged command (`cat /etc/issue`) on Linux using `strace cat /etc/issue` and compare it against the process/thread token access validation performed by the Windows Security Reference Monitor when `type C:\Windows\System32\drivers\etc\hosts` is executed.

---

## 10. Key Takeaways & Authoritative References

### Core Tenets
* **Different Philosophies, Identical Physics**: While Linux abstracts system entities as byte streams across virtual filesystems and Windows abstracts resources as securable objects, both systems adhere strictly to CPU privilege rings (Ring 0 vs. Ring 3) and page-based virtual memory protection.
* **Privilege Is Multi-Dimensional**: On Linux, root execution is bounded by Linux Capabilities and LSMs (SELinux/AppArmor). On Windows, administrative tokens are bounded by Integrity Levels, UAC filtering, and Token Privileges (`SeDebugPrivilege`).
* **Command Fluent Mastery**: A senior penetration tester or application security auditor must switch between Bash and PowerShell with zero cognitive friction, understanding not just the syntax, but the underlying OS APIs executed by each command.

### Authoritative References
* **NIST Special Publication 800-145**: *The NIST Definition of Cloud Computing & OS Virtualization*.
* **POSIX IEEE Std 1003.1-2017**: *Standard for Information Technology — Portable Operating System Interface (POSIX)* (`standards.ieee.org`).
* **Filesystem Hierarchy Standard (FHS 3.0)**: *Linux Foundation Reference Specification* (`refspecs.linuxfoundation.org`).
* **Microsoft Learn Windows Internals**: *Windows Internals, Part 1 & Part 2 (7th Edition)* by Pavel Yosifovich, Alex Ionescu, Mark Russinovich, and David Solomon.
* **The Linux Programming Interface**: *A Linux and UNIX System Programming Handbook* by Michael Kerrisk.
