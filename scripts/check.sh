#!/usr/bin/env bash
# scripts/check.sh - repository checks
#
# Usage: scripts/check.sh [--fast] [--strict]
#   (no option)  sanitization + version-sync, then PSScriptAnalyzer and Pester when pwsh is available
#   --fast       sanitization + version-sync only (used by .githooks/pre-commit)
#   --strict     a step that cannot run (for example pwsh missing) counts as a failure (used by CI)
#
# Exit codes: 0 every check that ran passed, 1 a check failed, 2 the script could not run.
#
# Settings:
#   scripts/check.conf     repo-specific version-sync rules (defines version_sync)
#   .sanitize-allow        reviewed exceptions, one per line: path-glob|check-id|reason
#                          check-id is one of: filename ignored privkey secret token ip host email deny all
#                          a reason is required; lines without one are rejected
#   .sanitize-deny.local   optional, git-ignored, never commit it: one extended regex per line for terms
#                          that must never appear in the repo (an employer domain, internal hostnames)
#
# The sanitization scan is a heuristic safety net, not proof that nothing sensitive is present.
# It does not detect real hostnames under public domains or unquoted secrets; review changes by eye.
# Matched secret values are never printed.

set -u

FAST=0
STRICT=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    --strict) STRICT=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not inside a git repository" >&2; exit 2; }
cd "$ROOT" || exit 2

PROBLEMS=0
RAN=()
NOT_RUN=()
ALLOW_FILE=.sanitize-allow
DENY_FILE=.sanitize-deny.local

fail() { printf 'FAIL [%s] %s\n' "$1" "$2"; PROBLEMS=$((PROBLEMS + 1)); }
note() { printf 'note [%s] %s\n' "$1" "$2"; }

# ---- file list: tracked + untracked-but-not-ignored, present on disk ---------------------------
FILES=()
while IFS= read -r -d '' f; do
  [ -f "$f" ] && FILES+=("$f")
done < <(git ls-files -z --cached --others --exclude-standard)

# ---- allowlist -------------------------------------------------------------------------------
allowed() { # $1 = path, $2 = check id
  [ -f "$ALLOW_FILE" ] || return 1
  local g c r
  while IFS='|' read -r g c r; do
    g=${g%$'\r'}; r=${r%$'\r'}
    case "$g" in ''|'#'*) continue ;; esac
    [ -n "$r" ] || continue
    # shellcheck disable=SC2254
    case "$1" in $g) { [ "$c" = all ] || [ "$c" = "$2" ]; } && return 0 ;; esac
  done < "$ALLOW_FILE"
  return 1
}

check_allowlist_format() {
  [ -f "$ALLOW_FILE" ] || return 0
  local n=0 g c r
  while IFS='|' read -r g c r; do
    n=$((n + 1)); r=${r%$'\r'}
    case "$g" in ''|'#'*) continue ;; esac
    if [ -z "$c" ] || [ -z "$r" ]; then
      fail allowlist "$ALLOW_FILE:$n: expected path-glob|check-id|reason (a reason is required)"
    fi
  done < "$ALLOW_FILE"
}

report_lines() { # id file message ; reads line numbers on stdin
  local id=$1 f=$2 msg=$3 ln
  while IFS= read -r ln; do
    [ -n "$ln" ] && fail "$id" "$f:$ln: $msg"
  done
}

# ---- sanitization ------------------------------------------------------------------------------
Q="[\"']"
SECRET_RE="(password|passwd|pwd|secret|token|api[_-]?key|apikey|client[_-]?secret)[A-Za-z0-9_]*${Q}?[[:space:]]*[:=][[:space:]]*${Q}[^\"'\$<{%[:space:]][^\"']{5,}${Q}"
PLACEHOLDER_RE='redacted|example|changeme|placeholder|your[_-]|<[A-Za-z_ -]+>|\*\*\*|x{4,}|\$\{|\$env:|\$\(|%[A-Za-z_]+%'
TOKEN_RE='(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|gh[ousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})'
HOST_RE='(^|[^A-Za-z0-9.-])[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.(local|corp|internal|lan|intranet|localdomain|home\.arpa)\b'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
IP_AWK='
{
  line = $0
  while (match(line, /[0-9]+(\.[0-9]+)+/)) {
    tok = substr(line, RSTART, RLENGTH)
    prev = (RSTART > 1) ? substr(line, RSTART - 1, 1) : ""
    nxt = substr(line, RSTART + RLENGTH, 1)
    line = substr(line, RSTART + RLENGTH)
    if (split(tok, o, ".") != 4) continue
    if (prev ~ /[A-Za-z0-9_]/ || nxt ~ /[A-Za-z0-9_]/) continue
    bad = 0
    for (i = 1; i <= 4; i++) if (o[i] + 0 > 255 || length(o[i]) > 3) bad = 1
    if (bad) continue
    if (tok ~ /^(127\.|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/ || tok == "0.0.0.0") continue
    printf "%s:%d: IPv4 address outside the documentation ranges (%s)\n", FILENAME, NR, tok
  }
}'

check_sanitization() {
  RAN+=("sanitization")
  check_allowlist_format

  local f b
  for f in ${FILES[@]+"${FILES[@]}"}; do
    b=${f##*/}
    case "$b" in *.example|*.example.*|*.sample) continue ;; esac
    case "$b" in
      .env|*.env|.env.*|*.pfx|*.p12|*.pem|*.key|*.kdbx|*.clixml|id_rsa|id_ed25519|*[Cc]redential*.xml|*[Cc]redential*.json)
        allowed "$f" filename || fail filename "$f looks like a credential or secret file" ;;
    esac
  done

  while IFS= read -r -d '' f; do
    [ -e "$f" ] || continue
    allowed "$f" ignored || fail ignored "$f is tracked but matches an ignore rule (remove it from the index)"
  done < <(git ls-files -ci --exclude-standard -z)

  local deny=""
  if [ -f "$DENY_FILE" ]; then
    deny=$(mktemp)
    tr -d '\r' < "$DENY_FILE" | grep -vE '^[[:space:]]*(#|$)' > "$deny" || true
    [ -s "$deny" ] || { rm -f "$deny"; deny=""; }
  fi

  for f in ${FILES[@]+"${FILES[@]}"}; do
    [ "$f" = scripts/check.sh ] && continue
    grep -Iq . "$f" 2>/dev/null || continue   # skip binary and empty files

    allowed "$f" privkey || report_lines privkey "$f" "private key marker" \
      < <(grep -nIE -- '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' "$f" | cut -d: -f1)

    allowed "$f" secret || report_lines secret "$f" "literal credential-looking assignment (value hidden)" \
      < <(grep -nIEi "$SECRET_RE" "$f" | grep -viE "$PLACEHOLDER_RE" | cut -d: -f1)

    allowed "$f" token || report_lines token "$f" "token-like string (value hidden)" \
      < <(grep -nIE "$TOKEN_RE" "$f" | cut -d: -f1)

    if ! allowed "$f" ip; then
      while IFS= read -r l; do [ -n "$l" ] && fail ip "$l"; done < <(awk "$IP_AWK" "$f")
    fi

    allowed "$f" host || report_lines host "$f" "hostname with a private-network suffix" \
      < <(grep -noIiE "$HOST_RE" "$f" | grep -viE '\.docker\.internal$' | cut -d: -f1)

    allowed "$f" email || report_lines email "$f" "email address" \
      < <(grep -noIE "$EMAIL_RE" "$f" | grep -viE '@(example\.(com|net|org)|users\.noreply\.github\.com)$|^[0-9]+:noreply@' | cut -d: -f1)

    if [ -n "$deny" ] && ! allowed "$f" deny; then
      report_lines deny "$f" "matches a term in $DENY_FILE (term hidden)" \
        < <(grep -nIiEf "$deny" "$f" | cut -d: -f1)
    fi
  done
  [ -n "$deny" ] && rm -f "$deny"
  return 0
}

# ---- version-sync helpers (used by scripts/check.conf) -------------------------------------------
# ver_from FILE REGEX : first line matching REGEX; prints the last dotted number in the match.
#                       REGEX should end at the version. Prints nothing if the file or match is missing.
ver_from() {
  [ -f "$1" ] || return 0
  grep -m1 -oE "$2" "$1" 2>/dev/null | tr -d '\r' | grep -oE '[0-9]+(\.[0-9]+)+' | tail -n1
}

# expect_same LABEL V1 V2 ... : every version must be found and equal.
expect_same() {
  local label=$1 first v
  shift
  first=${1:-}
  if [ -z "$first" ]; then fail version "$label: version not found in the first source"; return; fi
  for v in "$@"; do
    if [ -z "$v" ]; then fail version "$label: a version source is missing or its pattern did not match"; return; fi
    if [ "$v" != "$first" ]; then fail version "$label: versions disagree ($*)"; return; fi
  done
}

# tag_check VERSION : the newest vX.Y.Z tag must not be newer than VERSION, and a tag for VERSION must be annotated.
tag_check() {
  local v=$1 latest
  git rev-parse --verify -q HEAD >/dev/null 2>&1 || return 0
  latest=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | sed 's/^v//' | sort -V | tail -n1)
  if [ -z "$latest" ]; then
    if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
      note version "shallow clone and no tags visible; tag check skipped"
    else
      note version "no vX.Y.Z tags found"
    fi
    return 0
  fi
  if [ "$(printf '%s\n%s\n' "$latest" "$v" | sort -V | tail -n1)" != "$v" ]; then
    fail version "newest tag v$latest is newer than the version in the code ($v)"
  fi
  if git rev-parse -q --verify "refs/tags/v$v" >/dev/null 2>&1; then
    [ "$(git cat-file -t "refs/tags/v$v")" = tag ] || fail version "tag v$v is lightweight; use an annotated tag"
  fi
  local t lightweight=""
  for t in $(git tag -l 'v[0-9]*.[0-9]*.[0-9]*'); do
    [ "$(git cat-file -t "refs/tags/$t")" = tag ] || lightweight="$lightweight $t"
  done
  [ -n "$lightweight" ] && note version "lightweight tag(s), annotated tags are the standard:$lightweight"
  return 0
}

check_versions() {
  if [ -f scripts/check.conf ]; then
    # shellcheck disable=SC1091
    . scripts/check.conf
    if declare -F version_sync >/dev/null; then
      RAN+=("version-sync")
      version_sync
    else
      NOT_RUN+=("version-sync (scripts/check.conf defines no version_sync)")
    fi
  else
    NOT_RUN+=("version-sync (no scripts/check.conf)")
  fi
}

# ---- analyzer and tests (need pwsh) ----------------------------------------------------------------
has_ps_files() { printf '%s\n' ${FILES[@]+"${FILES[@]}"} | grep -qiE '\.(ps1|psm1|psd1)$'; }

step_unavailable() { # label reason
  NOT_RUN+=("$1 ($2)")
  [ "$STRICT" = 1 ] && fail env "$1 could not run: $2 (--strict)"
  return 0
}

check_powershell() {
  if ! has_ps_files; then NOT_RUN+=("analyzer (no PowerShell files)"); return; fi
  if ! command -v pwsh >/dev/null 2>&1; then
    step_unavailable "analyzer" "pwsh not found"
    [ -d tests ] && step_unavailable "tests" "pwsh not found"
    return
  fi

  pwsh -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) { Write-Host "PSScriptAnalyzer module is not installed"; exit 3 }
    $p = @{ Path = "."; Recurse = $true }
    if (Test-Path ./PSScriptAnalyzerSettings.psd1) { $p.Settings = "./PSScriptAnalyzerSettings.psd1" }
    $r = @(Invoke-ScriptAnalyzer @p)
    if ($r.Count -gt 0) { $r | Sort-Object Severity, ScriptName, Line | Format-Table Severity, RuleName, ScriptName, Line -AutoSize | Out-String -Width 200 | Write-Host }
    $e = @($r | Where-Object { $_.Severity -eq "Error" }).Count
    Write-Host ("analyzer: {0} finding(s), {1} error(s); only errors fail the check" -f $r.Count, $e)
    if ($e -gt 0) { exit 1 }
  '
  case $? in
    0) RAN+=("analyzer") ;;
    3) step_unavailable "analyzer" "PSScriptAnalyzer module not installed" ;;
    *) RAN+=("analyzer"); fail analyzer "PSScriptAnalyzer reported errors" ;;
  esac

  if [ -d tests ]; then
    pwsh -NoProfile -NonInteractive -Command '
      if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 })) { Write-Host "Pester 5 is not installed"; exit 3 }
      Import-Module Pester -MinimumVersion 5.0
      $c = New-PesterConfiguration
      $c.Run.Path = "tests"
      $c.Run.Exit = $true
      Invoke-Pester -Configuration $c
    '
    case $? in
      0) RAN+=("tests") ;;
      3) step_unavailable "tests" "Pester 5 not installed" ;;
      *) RAN+=("tests"); fail tests "Pester reported failures" ;;
    esac
  else
    NOT_RUN+=("tests (no tests/ folder)")
  fi
}

# ---- run -----------------------------------------------------------------------------------------------
check_sanitization
check_versions
if [ "$FAST" = 0 ]; then
  check_powershell
else
  NOT_RUN+=("analyzer and tests (--fast)")
fi

echo
echo "ran:     ${RAN[*]:-none}"
echo "not run: ${NOT_RUN[*]:-none}"
if [ "$PROBLEMS" -gt 0 ]; then
  echo "RESULT: FAIL ($PROBLEMS problem(s))"
  exit 1
fi
echo "RESULT: PASS (only the checks listed under 'ran' were verified)"
exit 0
