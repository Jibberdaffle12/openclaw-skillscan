#!/bin/bash
# skill_scan.sh v3.0 - Static security analysis for ClawHub skills
# https://github.com/Jibberdaffle12/openclaw-skillscan
#
# Scans OpenClaw skills for:
#   - Prompt injection vectors & config tampering
#   - Undeclared network calls & domain enforcement
#   - Social engineering in documentation
#   - Obfuscated payloads & credential theft patterns
#
# 4-layer scoring system (0-140) with automatic tiering:
#   Tier A (90+): Auto-approve
#   Tier B (60-89): Manual review recommended
#   Tier C (1-59): Deep review required
#   Tier D (0): Auto-reject
#
# Usage: ./skill_scan.sh /path/to/quarantine/skill-name
# Optional env vars: VT_CLEAN=true (VirusTotal passed), STAR_COUNT=N (GitHub stars)

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/skill-directory"
  echo "Scans an OpenClaw skill for security issues before installation."
  exit 1
fi

SKILL_DIR="$1"
SKILL_NAME=$(basename "$SKILL_DIR")
AUDIT_LOG="${SKILLSCAN_LOG:-./skill_audit_log.csv}"
SCORE=100
MAX_SCORE=100
BLOCKED=false
BLOCKERS=""
WARNINGS=""
WARNING_COUNT=0
DOC_WARNINGS=""
DOC_WARNING_COUNT=0
ADDITIONS_ELIGIBLE=true

if [ ! -d "$SKILL_DIR" ]; then
  echo "ERROR: Directory '$SKILL_DIR' does not exist."
  exit 1
fi

echo "Scanning skill: $SKILL_NAME"
echo "Directory: $SKILL_DIR"
echo ""

# ==============================================================================
# MODE A: CODE FILE SCAN
# ==============================================================================

CODE_TARGETS=$(find "$SKILL_DIR" \
  -not -path "*/node_modules/*" \
  -not -path "*/.git/*" \
  \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \
     -o -name "*.mjs" -o -name "*.cjs" -o -name "*.jsx" -o -name "*.tsx" \) \
  -print0 2>/dev/null || true)

if [ -z "$CODE_TARGETS" ]; then
  echo "[INFO] No executable code files found. Proceeding with doc-scan only."
fi

# BLOCKER patterns - any match = score 0 (fixed-string grep via -F)
# These patterns indicate high-risk behaviors that should never appear
# in a skill without explicit justification.
BLOCKER_PATTERNS_FIXED=(
  "eval("
  "exec("
  "Function("
  "subprocess.call"
  "rm -rf"
  "rimraf"
  "rmSync"
  "rmtree"
  "atob("
  "b64decode"
  "Buffer.from"
  "ssh-keygen"
  "id_rsa"
  "authorized_keys"
  "SOUL.md"
  "MEMORY.md"
  "USER.md"
  "openclaw.json"
  "AGENTS.md"
  "IDENTITY.md"
  "HEARTBEAT.md"
)

if [ -n "$CODE_TARGETS" ]; then
  for pattern in "${BLOCKER_PATTERNS_FIXED[@]}"; do
    if echo "$CODE_TARGETS" | xargs -0 grep -lF "$pattern" 2>/dev/null; then
      BLOCKERS="$BLOCKERS | BLOCKER: '$pattern'"
      BLOCKED=true
    fi
  done
fi

# ==============================================================================
# DOMAIN ENFORCEMENT
# ==============================================================================
# Skills should declare what domains they connect to in SKILL.md.
# Any undeclared outbound connection is a blocker.
# Subdomain suffix matching: declaring "example.com" permits "api.example.com"
# Localhost/loopback is always exempt.

EXEMPT_DOMAINS="localhost 127.0.0.1 0.0.0.0 ::1"

if [ -f "$SKILL_DIR/SKILL.md" ]; then
  DECLARED_DOMAINS=$(grep -iE '(domain|endpoint|url|host)' "$SKILL_DIR/SKILL.md" \
    | grep -oE '[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}' | sort -u || true)

  if [ -n "$CODE_TARGETS" ]; then
    CODE_DOMAINS=$(echo "$CODE_TARGETS" | xargs -0 grep -ohE 'https?://[a-zA-Z0-9][-a-zA-Z0-9.]*' 2>/dev/null \
      | sed 's|https\?://||' | cut -d'/' -f1 | sort -u || true)

    if [ -n "$CODE_DOMAINS" ]; then
      if [ -z "$DECLARED_DOMAINS" ]; then
        NON_EXEMPT=false
        for domain in $CODE_DOMAINS; do
          if ! echo "$EXEMPT_DOMAINS" | grep -qwF "$domain"; then
            NON_EXEMPT=true
            break
          fi
        done
        if $NON_EXEMPT; then
          BLOCKERS="$BLOCKERS | BLOCKER: Code contains URLs but SKILL.md declares no domains"
          BLOCKED=true
        fi
      else
        for domain in $CODE_DOMAINS; do
          if echo "$EXEMPT_DOMAINS" | grep -qwF "$domain"; then
            continue
          fi
          DOMAIN_MATCHED=false
          for declared in $DECLARED_DOMAINS; do
            if [ "$domain" = "$declared" ] || echo "$domain" | grep -qF ".$declared"; then
              DOMAIN_MATCHED=true
              break
            fi
          done
          if ! $DOMAIN_MATCHED; then
            BLOCKERS="$BLOCKERS | BLOCKER: Undeclared domain '$domain'"
            BLOCKED=true
          fi
        done
      fi
    fi
  fi
fi

if $BLOCKED; then
  SCORE=0
  ADDITIONS_ELIGIBLE=false
else
  # WARNING patterns - score penalty, -20 each, max -60
  WARNING_PATTERNS_FIXED=(
    "subprocess"
    "child_process"
    "os.system"
    "execSync"
    "puppeteer"
    "playwright"
    "selenium"
    "chromedp"
    "pip install"
    "npm install"
    "apt-get"
  )

  if [ -n "$CODE_TARGETS" ]; then
    for pattern in "${WARNING_PATTERNS_FIXED[@]}"; do
      if echo "$CODE_TARGETS" | xargs -0 grep -lF "$pattern" 2>/dev/null; then
        WARNINGS="$WARNINGS | WARNING: '$pattern'"
        WARNING_COUNT=$((WARNING_COUNT + 1))
        ADDITIONS_ELIGIBLE=false
      fi
    done
  fi

  DEDUCT=$((WARNING_COUNT * 20))
  if [ $DEDUCT -gt 60 ]; then DEDUCT=60; fi
  SCORE=$((SCORE - DEDUCT))

  if [ ! -f "$SKILL_DIR/SKILL.md" ]; then
    WARNINGS="$WARNINGS | No SKILL.md found"
    SCORE=$((SCORE - 20))
    ADDITIONS_ELIGIBLE=false
  fi
fi

# ==============================================================================
# MODE B: DOC FILE SCAN
# ==============================================================================
# ClawHub supply-chain attacks have used SKILL.md to socially engineer
# users into running malicious commands. This scans docs for those patterns.

DOC_TARGETS=$(find "$SKILL_DIR" \
  -not -path "*/node_modules/*" \
  -not -path "*/.git/*" \
  -not -name "CHANGELOG*" \
  -not -name "LICENSE*" \
  \( -name "*.md" -o -name "*.txt" -o -name "README*" \) \
  -print0 2>/dev/null || true)

DOC_BLOCKER_PATTERNS=(
  "curl | bash"
  "curl |bash"
  "wget | sh"
  "curl -sSL"
  "powershell -encodedcommand"
  "Invoke-Expression"
  "iex("
)

DOC_WARNING_PATTERNS=(
  "eval \$("
  "base64 -d"
)

if [ -n "$DOC_TARGETS" ]; then
  for pattern in "${DOC_BLOCKER_PATTERNS[@]}"; do
    if echo "$DOC_TARGETS" | xargs -0 grep -lF "$pattern" 2>/dev/null; then
      BLOCKERS="$BLOCKERS | BLOCKER (doc): '$pattern'"
      BLOCKED=true
      SCORE=0
      ADDITIONS_ELIGIBLE=false
    fi
  done

  for pattern in "${DOC_WARNING_PATTERNS[@]}"; do
    if echo "$DOC_TARGETS" | xargs -0 grep -lF "$pattern" 2>/dev/null; then
      DOC_WARNINGS="$DOC_WARNINGS | DOC-WARNING: '$pattern'"
      DOC_WARNING_COUNT=$((DOC_WARNING_COUNT + 1))
      ADDITIONS_ELIGIBLE=false
    fi
  done

  TOTAL_WARNINGS=$((WARNING_COUNT + DOC_WARNING_COUNT))
  TOTAL_DEDUCT=$((TOTAL_WARNINGS * 20))
  if [ $TOTAL_DEDUCT -gt 60 ]; then TOTAL_DEDUCT=60; fi
  if ! $BLOCKED; then
    SCORE=$((100 - TOTAL_DEDUCT))
    if [ ! -f "$SKILL_DIR/SKILL.md" ]; then
      SCORE=$((SCORE - 20))
    fi
  fi
fi

# ==============================================================================
# ADDITIONS (bonus points for trust signals)
# ==============================================================================
# Only eligible if no blockers and no warnings detected.

if $ADDITIONS_ELIGIBLE && [ $SCORE -ge 60 ]; then
  MAX_SCORE=140
  ADDITION_POINTS=0

  # Official OpenClaw org check
  REMOTE_URL=$(cd "$SKILL_DIR" && git remote get-url origin 2>/dev/null || echo "")
  if echo "$REMOTE_URL" | grep -qF "github.com/openclaw/"; then
    ADDITION_POINTS=$((ADDITION_POINTS + 10))
    WARNINGS="$WARNINGS | +10 official org"
  fi

  # VirusTotal clean (set VT_CLEAN=true before running)
  if [ "${VT_CLEAN:-false}" = "true" ]; then
    ADDITION_POINTS=$((ADDITION_POINTS + 10))
    WARNINGS="$WARNINGS | +10 VT clean"
  fi

  # GitHub stars (set STAR_COUNT=N before running)
  STAR_COUNT="${STAR_COUNT:-0}"
  if [ "$STAR_COUNT" -gt 500 ]; then
    ADDITION_POINTS=$((ADDITION_POINTS + 10))
    WARNINGS="$WARNINGS | +10 stars>500"
  elif [ "$STAR_COUNT" -gt 100 ]; then
    ADDITION_POINTS=$((ADDITION_POINTS + 5))
    WARNINGS="$WARNINGS | +5 stars>100"
  fi

  # Recency check (last commit within 30 days)
  LAST_COMMIT_DATE=$(cd "$SKILL_DIR" && git log -1 --format=%ci 2>/dev/null || echo "")
  if [ -n "$LAST_COMMIT_DATE" ]; then
    DAYS_AGO=$(( ($(date +%s) - $(date -d "$LAST_COMMIT_DATE" +%s 2>/dev/null || echo 0)) / 86400 ))
    if [ "$DAYS_AGO" -lt 30 ] 2>/dev/null; then
      ADDITION_POINTS=$((ADDITION_POINTS + 5))
      WARNINGS="$WARNINGS | +5 updated<30d"
    fi
  fi

  SCORE=$((SCORE + ADDITION_POINTS))
fi

# Floor at 0
if [ $SCORE -lt 0 ]; then SCORE=0; fi

# ==============================================================================
# TIER ASSIGNMENT
# ==============================================================================

if [ $SCORE -eq 0 ]; then
  TIER="D"
  DECISION="rejected"
elif [ $SCORE -lt 60 ]; then
  TIER="C"
  DECISION="quarantined"
elif [ $SCORE -lt 90 ]; then
  TIER="B"
  DECISION="pending-review"
else
  TIER="A"
  DECISION="approved"
fi

COMMIT_HASH=$(cd "$SKILL_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "none")
TIMESTAMP=$(date -Iseconds 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%S%z")
FINDINGS="${BLOCKERS}${WARNINGS}${DOC_WARNINGS}"
FINDINGS=${FINDINGS# | }

# ==============================================================================
# OUTPUT
# ==============================================================================

echo ""
echo "==============================="
echo "SKILL:    $SKILL_NAME"
echo "SCORE:    $SCORE / $MAX_SCORE"
echo "TIER:     $TIER ($DECISION)"
echo "HASH:     $COMMIT_HASH"
echo "FINDINGS: ${FINDINGS:-clean}"
echo "==============================="

# Append to audit log CSV
if [ ! -f "$AUDIT_LOG" ]; then
  echo "timestamp,skill_name,source,commit_hash,score,max_score,tier,decision,findings,reviewer" > "$AUDIT_LOG"
fi
echo "$TIMESTAMP,$SKILL_NAME,ClawHub/unverified,$COMMIT_HASH,$SCORE,$MAX_SCORE,$TIER,$DECISION,\"${FINDINGS:-clean}\",skillscan" >> "$AUDIT_LOG"

echo ""
echo "Audit log: $AUDIT_LOG"

# Actionable recommendations
case $TIER in
  A) echo "[SAFE] Skill passed all checks. Safe to install." ;;
  B) echo "[REVIEW] Skill has minor warnings. Manual review recommended before install." ;;
  C) echo "[CAUTION] Skill has significant warnings. Deep review required." ;;
  D) echo "[BLOCKED] Skill contains dangerous patterns. Do NOT install." ;;
esac
