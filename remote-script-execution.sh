#!/bin/bash
# Optimized cPanel CVE-2026-41940 IOC Detection Script - STRICT MODE
# Only reports SUCCESSFUL exploits, logs blocked attempts separately

set -uo pipefail

# Configuration
SESSIONS_DIR="/var/cpanel/sessions"
LOG_DIR="/var/log/cpanel_ioc_scans"
BACKUP_DIR="/root/cpanel_session_backups"
QUARANTINE_DIR="/root/cpanel_quarantine_sessions"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname -s)
LOG_FILE="$LOG_DIR/scan_${HOSTNAME}_${TIMESTAMP}.log"
CSV_FILE="$LOG_DIR/scan_${HOSTNAME}_${TIMESTAMP}.csv"
SCANNER_LOG="$LOG_DIR/scanner_activity_${HOSTNAME}_${TIMESTAMP}.log"
SUMMARY_FILE="/var/log/cpanel_ioc_scan_LATEST.summary"
COMPROMISED=0
BLOCKED_ATTEMPTS=0

# Create directories
mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$QUARANTINE_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "========================================================================="
log "cPanel CVE-2026-41940 IOC Detection Script - TWO-TIER MODE"
log "========================================================================="
log "Server: $HOSTNAME"
log "Session directory: $SESSIONS_DIR"
log "Access log scope: All 2026 logs (current + archives)"
log "Mode: CONFIRMED exploits + SUSPICIOUS activity (manual review)"
log ""

# ========================================================================
# DEPENDENCY INSTALLATION
# ========================================================================
log "Checking dependencies..."

# Check for ripgrep
if ! command -v rg >/dev/null 2>&1; then
    log "ripgrep not found. Installing..."
    if command -v yum >/dev/null 2>&1; then
        yum install -y ripgrep 2>&1 | tee -a "$LOG_FILE" || log "WARNING: ripgrep installation failed, will use grep fallback"
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y ripgrep 2>&1 | tee -a "$LOG_FILE" || log "WARNING: ripgrep installation failed, will use grep fallback"
    else
        log "WARNING: Unknown package manager, skipping ripgrep installation"
    fi
fi

# Check for GNU parallel
if ! command -v parallel >/dev/null 2>&1; then
    log "GNU parallel not found. Installing..."
    if command -v yum >/dev/null 2>&1; then
        yum install -y parallel 2>&1 | tee -a "$LOG_FILE" || log "WARNING: parallel installation failed, will use sequential processing"
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y parallel 2>&1 | tee -a "$LOG_FILE" || log "WARNING: parallel installation failed, will use sequential processing"
    else
        log "WARNING: Unknown package manager, skipping parallel installation"
    fi
fi

log ""

# ========================================================================
# CPU DETECTION
# ========================================================================
CPU_CORES=$(lscpu | awk -F: '/^CPU\(s\):/ {gsub(/ /,"",$2); print $2}')
if [ -z "$CPU_CORES" ] || [ "$CPU_CORES" -lt 1 ]; then
    CPU_CORES=4  # Fallback
    log "Could not detect CPU cores, using default: $CPU_CORES"
else
    log "Detected CPU cores: $CPU_CORES"
fi

# Use all cores for parallel processing
PARALLEL_JOBS=$CPU_CORES
log "Will use $PARALLEL_JOBS parallel jobs"
log ""

# ========================================================================
# CSV HEADER
# ========================================================================
echo "Server,Timestamp,SessionFile,IOCType,Severity,TokenUsed,CPSecurityToken,SourceIP,Details,Action" > "$CSV_FILE"

# Scanner activity log header
echo "# Scanner Activity Log - Blocked Exploitation Attempts" > "$SCANNER_LOG"
echo "# These attempts were blocked by the patch - no credential rotation needed" >> "$SCANNER_LOG"
echo "Timestamp,SessionFile,SourceIP,AttackType,Status" >> "$SCANNER_LOG"

# ========================================================================
# SCAN FUNCTION (two-tier mode)
# ========================================================================

# Function to check if token was used in ANY 2026 access log
check_token_usage_2026() {
    local token="$1"
    local result=""

    # Search current access log
    result=$(grep -a "$token" /usr/local/cpanel/logs/access_log 2>/dev/null | grep " 200 " || true)
    [ -n "$result" ] && echo "$result" && return

    # Search all 2026 archived logs (compressed in archive directory)
    for logfile in /usr/local/cpanel/logs/archive/access_log-*-2026.gz; do
        [ -f "$logfile" ] || continue

        result=$(zgrep -a "$token" "$logfile" 2>/dev/null | grep " 200 " || true)
        [ -n "$result" ] && echo "$result" && return
    done

    echo ""
}

scan_session_file() {
    local session_file="$1"
    local session_name=$(basename "$session_file")
    local preauth_file="$SESSIONS_DIR/preauth/$session_name"

    # Single-pass file read
    local token_denied=""
    local cp_security_token=""
    local origin=""
    local tfa_verified=""
    local external_auth=""
    local has_badpass=""
    local has_form_login=""
    local has_create_session=""
    local has_auth_transfer=""
    local multiline_pass=""
    local source_ip=""

    while IFS= read -r line; do
        case "$line" in
            token_denied=*) token_denied="${line#*=}" ;;
            cp_security_token=*) cp_security_token="${line#*=}" ;;
            origin_as_string=*) 
                origin="${line#*=}"
                # Extract IP from origin string
                if [[ "$origin" =~ address=([0-9.]+) ]]; then
                    source_ip="${BASH_REMATCH[1]}"
                fi
                [[ "$origin" == *"method=badpass"* ]] && has_badpass="1"
                [[ "$origin" == *"method=handle_form_login"* ]] && has_form_login="1"
                [[ "$origin" == *"method=create_user_session"* ]] && has_create_session="1"
                [[ "$origin" == *"method=handle_auth_transfer"* ]] && has_auth_transfer="1"
                ;;
            tfa_verified=*) tfa_verified="${line#*=}" ;;
            successful_external_auth_with_timestamp=*) external_auth="${line#*=}" ;;
        esac
    done < "$session_file"

    # Check for multiline pass (requires binary-safe grep)
    if grep -qzP '(?m)^pass=.*\n.' "$session_file" 2>/dev/null; then
        multiline_pass="1"
    fi

    # ====================================================================
    # TWO-TIER DETECTION LOGIC
    # ====================================================================

    # Check if injected token was actually used in ANY 2026 access log (HTTP 200 response)
    local token_used=""
    if [ -n "$cp_security_token" ]; then
        token_used=$(check_token_usage_2026 "$cp_security_token")
    fi

    # IOC 1A: CONFIRMED token injection (method=badpass + token used)
    if [ -n "$has_badpass" ] && [ -n "$cp_security_token" ] && [ -n "$token_used" ]; then
        echo "$HOSTNAME,$(date '+%Y-%m-%d %H:%M:%S'),$session_name,TOKEN_INJECTION_CONFIRMED,CRITICAL,YES,$cp_security_token,$source_ip,Pre-auth injection (method=badpass) + token used successfully,QUARANTINED" >> "$CSV_FILE"

        # Backup and quarantine
        local backup_file="$BACKUP_DIR/${session_name}_${TIMESTAMP}.bak"
        cp "$session_file" "$backup_file" 2>/dev/null
        mv "$session_file" "$QUARANTINE_DIR/" 2>/dev/null
        echo "$(date '+%Y-%m-%d %H:%M:%S'),$HOSTNAME,$session_name,TOKEN_INJECTION_CONFIRMED,quarantined" >> "$LOG_DIR/purge_log.csv"

        COMPROMISED=1
        return
    fi

    # IOC 1B: SUSPICIOUS token usage (potential false positive - no method=badpass)
    if [ -n "$token_denied" ] && [ -n "$cp_security_token" ] && [ -n "$token_used" ] && [ -z "$has_badpass" ]; then
        echo "$HOSTNAME,$(date '+%Y-%m-%d %H:%M:%S'),$session_name,TOKEN_USAGE_SUSPICIOUS,WARNING,YES,$cp_security_token,$source_ip,Token denied but later used (likely expired bookmark) - investigate IP,NOT_QUARANTINED" >> "$CSV_FILE"

        # Backup only (don't quarantine - likely false positive)
        local backup_file="$BACKUP_DIR/${session_name}_${TIMESTAMP}.bak"
        cp "$session_file" "$backup_file" 2>/dev/null

        # Don't set COMPROMISED=1, but log for review
        return
    fi

    # IOC 2: SUCCESSFUL pre-auth session promotion
    if [ -f "$preauth_file" ] && [ -n "$external_auth" ]; then
        echo "$HOSTNAME,$(date '+%Y-%m-%d %H:%M:%S'),$session_name,PREAUTH_PROMOTION_SUCCESSFUL,CRITICAL,N/A,$cp_security_token,$source_ip,Pre-auth session successfully promoted to authenticated,QUARANTINED" >> "$CSV_FILE"

        # Backup and quarantine
        local backup_file="$BACKUP_DIR/${session_name}_${TIMESTAMP}.bak"
        cp "$session_file" "$backup_file" 2>/dev/null
        mv "$session_file" "$QUARANTINE_DIR/" 2>/dev/null
        echo "$(date '+%Y-%m-%d %H:%M:%S'),$HOSTNAME,$session_name,PREAUTH_PROMOTION,quarantined" >> "$LOG_DIR/purge_log.csv"

        COMPROMISED=1
        return
    fi

    # IOC 3: SUCCESSFUL TFA bypass
    if [ "$tfa_verified" = "1" ] && [ -z "$has_form_login" ] && [ -z "$has_create_session" ] && [ -z "$has_auth_transfer" ]; then
        # Check if this session was actually used in ANY 2026 access log
        local session_id="${session_name#*:}"
        local session_used=$(check_token_usage_2026 "$session_id")

        if [ -n "$session_used" ]; then
            echo "$HOSTNAME,$(date '+%Y-%m-%d %H:%M:%S'),$session_name,TFA_BYPASS_SUCCESSFUL,CRITICAL,YES,$cp_security_token,$source_ip,TFA bypassed and session used,QUARANTINED" >> "$CSV_FILE"

            # Backup and quarantine
            local backup_file="$BACKUP_DIR/${session_name}_${TIMESTAMP}.bak"
            cp "$session_file" "$backup_file" 2>/dev/null
            mv "$session_file" "$QUARANTINE_DIR/" 2>/dev/null
            echo "$(date '+%Y-%m-%d %H:%M:%S'),$HOSTNAME,$session_name,TFA_BYPASS,quarantined" >> "$LOG_DIR/purge_log.csv"

            COMPROMISED=1
            return
        fi
    fi

    # ====================================================================
    # Log blocked attempts (informational only)
    # ====================================================================

    # Multiline pass field = exploitation attempt (blocked)
    if [ -n "$multiline_pass" ] && [ -z "$token_used" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),$session_name,$source_ip,Newline injection,BLOCKED" >> "$SCANNER_LOG"
        BLOCKED_ATTEMPTS=$((BLOCKED_ATTEMPTS + 1))
    fi

    # Token injection attempt but not used (blocked)
    if [ -n "$token_denied" ] && [ -n "$cp_security_token" ] && [ -z "$token_used" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),$session_name,$source_ip,Token injection,BLOCKED" >> "$SCANNER_LOG"
        BLOCKED_ATTEMPTS=$((BLOCKED_ATTEMPTS + 1))
    fi
}

# Export function for parallel
export -f scan_session_file check_token_usage_2026
export SESSIONS_DIR CSV_FILE SCANNER_LOG HOSTNAME BACKUP_DIR QUARANTINE_DIR TIMESTAMP LOG_DIR COMPROMISED BLOCKED_ATTEMPTS

# ========================================================================
# SCANNING
# ========================================================================
log "Starting session file scan..."
SCAN_START=$(date +%s)

# Count total files
TOTAL_FILES=$(find "$SESSIONS_DIR/raw" -type f 2>/dev/null | wc -l)
log "Total session files to scan: $TOTAL_FILES"
log ""

if [ "$TOTAL_FILES" -eq 0 ]; then
    log "No session files found. Exiting."
    echo "SUMMARY: CLEAN" > "$SUMMARY_FILE"
    echo "FILES_SCANNED: 0" >> "$SUMMARY_FILE"
    exit 0
fi

# Run scan (parallel if available, sequential otherwise)
if command -v parallel >/dev/null 2>&1; then
    log "Using parallel processing ($PARALLEL_JOBS jobs)..."
    find "$SESSIONS_DIR/raw" -type f 2>/dev/null | parallel -j "$PARALLEL_JOBS" scan_session_file {} 2>&1 | tee -a "$LOG_FILE"
else
    log "Using sequential processing..."
    for session_file in "$SESSIONS_DIR/raw"/*; do
        [ -f "$session_file" ] || continue
        scan_session_file "$session_file"
    done
fi

SCAN_END=$(date +%s)
SCAN_DURATION=$((SCAN_END - SCAN_START))

log ""
log "Scan completed in ${SCAN_DURATION} seconds"
log ""

# ========================================================================
# SUMMARY REPORT
# ========================================================================
CONFIRMED_EXPLOITS=$(grep -c ",CRITICAL," "$CSV_FILE" 2>/dev/null || true)
SUSPICIOUS_FINDINGS=$(grep -c ",WARNING," "$CSV_FILE" 2>/dev/null || true)
BLOCKED_ATTEMPTS=$(grep -c "BLOCKED$" "$SCANNER_LOG" 2>/dev/null || true)
QUARANTINED_COUNT=$(grep -c ",QUARANTINED$" "$CSV_FILE" 2>/dev/null || true)

# Handle empty results
CONFIRMED_EXPLOITS=${CONFIRMED_EXPLOITS:-0}
SUSPICIOUS_FINDINGS=${SUSPICIOUS_FINDINGS:-0}
BLOCKED_ATTEMPTS=${BLOCKED_ATTEMPTS:-0}
QUARANTINED_COUNT=${QUARANTINED_COUNT:-0}

TOTAL_FINDINGS=$((CONFIRMED_EXPLOITS + SUSPICIOUS_FINDINGS))

log "========================================================================="
log "SCAN SUMMARY - TWO-TIER MODE"
log "========================================================================="
log "Files scanned: $TOTAL_FILES"
log "Confirmed exploits (CRITICAL): $CONFIRMED_EXPLOITS"
log "Suspicious findings (WARNING): $SUSPICIOUS_FINDINGS"
log "Blocked attempts: $BLOCKED_ATTEMPTS"
log "Sessions quarantined: $QUARANTINED_COUNT"
log ""

if [ "$TOTAL_FINDINGS" -gt 0 ]; then
    log "Detailed CSV report: $CSV_FILE"
    if [ "$QUARANTINED_COUNT" -gt 0 ]; then
        log "Quarantined sessions: $QUARANTINE_DIR"
    fi
    log "Session backups: $BACKUP_DIR"
else
    log "No exploits or suspicious activity detected."
fi

if [ "$BLOCKED_ATTEMPTS" -gt 0 ]; then
    log "Blocked attempts logged: $SCANNER_LOG"
fi

log ""

# Write summary file for easy cross-server checking
{
    if [ "$CONFIRMED_EXPLOITS" -gt 0 ]; then
        echo "SUMMARY: COMPROMISED"
    elif [ "$SUSPICIOUS_FINDINGS" -gt 0 ]; then
        echo "SUMMARY: SUSPICIOUS_ACTIVITY"
    else
        echo "SUMMARY: CLEAN"
    fi
    echo "SCAN_TIME: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "FILES_SCANNED: $TOTAL_FILES"
    echo "CONFIRMED_EXPLOITS: $CONFIRMED_EXPLOITS"
    echo "SUSPICIOUS_FINDINGS: $SUSPICIOUS_FINDINGS"
    echo "BLOCKED_ATTEMPTS: $BLOCKED_ATTEMPTS"
    echo "QUARANTINED: $QUARANTINED_COUNT"
    echo "SCAN_DURATION: ${SCAN_DURATION}s"
    echo "LOG_FILE: $LOG_FILE"
    if [ "$TOTAL_FINDINGS" -gt 0 ]; then
        echo "CSV_FILE: $CSV_FILE"
    fi
} > "$SUMMARY_FILE"

# Display findings if any detected
if [ "$CONFIRMED_EXPLOITS" -gt 0 ]; then
    log "========================================================================="
    log "!!! CONFIRMED EXPLOITATION DETECTED !!!"
    log "========================================================================="
    grep ",CRITICAL," "$CSV_FILE" | tail -n +2 | column -t -s ',' 2>/dev/null | tee -a "$LOG_FILE" || grep ",CRITICAL," "$CSV_FILE" | tee -a "$LOG_FILE"
    log "========================================================================="
    log ""
    log "[!] CRITICAL: Server was successfully exploited"
    log ""
    log "IMMEDIATE ACTIONS REQUIRED:"
    log "  1. Review quarantined sessions in: $QUARANTINE_DIR"
    log "  2. Force password reset for root and all WHM users"
    log "  3. Rotate all API tokens and SSH keys"
    log "  4. Audit /var/log/wtmp and WHM access logs for unauthorized access"
    log "  5. Check for persistence (cron, SSH keys, backdoors, modified files)"
    log "  6. Review CSV report: $CSV_FILE"
    log ""
fi

if [ "$SUSPICIOUS_FINDINGS" -gt 0 ]; then
    log "========================================================================="
    log "SUSPICIOUS ACTIVITY - MANUAL REVIEW NEEDED"
    log "========================================================================="
    grep ",WARNING," "$CSV_FILE" | tail -n +2 | column -t -s ',' 2>/dev/null | tee -a "$LOG_FILE" || grep ",WARNING," "$CSV_FILE" | tee -a "$LOG_FILE"
    log "========================================================================="
    log ""
    log "[*] Suspicious token usage detected (likely false positives)"
    log "[*] Review source IPs to rule out malicious activity"
    log "[*] Session backups available in: $BACKUP_DIR"
    log ""
fi

if [ "$CONFIRMED_EXPLOITS" -eq 0 ] && [ "$SUSPICIOUS_FINDINGS" -eq 0 ]; then
    log "[+] No confirmed exploits or suspicious activity detected"
    if [ "$BLOCKED_ATTEMPTS" -gt 0 ]; then
        log "[*] Blocked $BLOCKED_ATTEMPTS exploitation attempts (patch is working)"
    fi
    log ""
    exit 0
fi

# Exit with error only for confirmed exploits
if [ "$CONFIRMED_EXPLOITS" -gt 0 ]; then
    exit 1
else
    exit 0
fi
