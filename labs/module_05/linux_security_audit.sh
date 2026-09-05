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
echo -e "\n[*] [CHECK 3] Auditing SUID Binaries for Dangerous Living-off-the-Land Executables..."
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
