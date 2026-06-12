#!/bin/bash

# ============================================================
#  Recon Scanner — nmap + gobuster + feroxbuster
#  Feroxbuster results parsed, categorised & colour-reported
# ============================================================

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()   { echo -e "${CYAN}[*] $*${RESET}"; }
ok()     { echo -e "${GREEN}[+] $*${RESET}"; }
warn()   { echo -e "${YELLOW}[!] $*${RESET}"; }
err()    { echo -e "${RED}[!] $*${RESET}" >&2; }
div()    { printf '%0.s─' {1..60}; echo; }
divdot() { printf '%0.s·' {1..56}; echo; }
divEq()  { printf '%0.s═' {1..60}; echo; }

# ── Banner ────────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
  echo -e "        nmap + gobuster + feroxbuster${RESET}"
  echo
}

# ── Dependency check ─────────────────────────────────────────
check_tools() {
  info "Checking dependencies..."
  local missing=0
  for tool in nmap gobuster feroxbuster jq; do
    if command -v "$tool" &>/dev/null; then
      echo -e "  ${GREEN}[✔]${RESET} $tool found"
    else
      echo -e "  ${RED}[✘]${RESET} $tool NOT found"
      missing=1
    fi
  done
  echo
  return $missing
}

# ── Wordlist ─────────────────────────────────────────────────
find_wordlist() {
  WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  if [[ ! -f "$WORDLIST" ]]; then
    err "Wordlist not found at ${WORDLIST}. Exiting."
    exit 1
  fi
  ok "Using wordlist: $WORDLIST"
}

# ── IP validation ────────────────────────────────────────────
validate_ip() {
  local ip="$1"
  if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 1
  fi
  IFS='.' read -ra parts <<< "$ip"
  for part in "${parts[@]}"; do
    (( part < 0 || part > 255 )) && return 1
  done
  return 0
}

# ── Status code colour ───────────────────────────────────────
status_colour() {
  local code=$1
  case $code in
    200|201|204) echo -e "${GREEN}${BOLD}${code}${RESET}" ;;
    301|302|307|308) echo -e "${CYAN}${BOLD}${code}${RESET}" ;;
    401|403) echo -e "${YELLOW}${BOLD}${code}${RESET}" ;;
    404) echo -e "${DIM}${code}${RESET}" ;;
    5*) echo -e "${RED}${BOLD}${code}${RESET}" ;;
    *) echo "$code" ;;
  esac
}

# ── File-type label & risk ────────────────────────────────────
# Returns "LABEL|RISK"  where RISK = high | medium | low | none
classify_ext() {
  case "$1" in
    .php|.aspx|.jsp|.py|.sh|.env|.config|.conf|.ini|.bak|.old|.sql|.db)
      echo "Script/Config/Sensitive|high" ;;
    .json|.xml|.yaml|.yml|.log|.txt|.md|.toml)
      echo "Data/Config|medium" ;;
    .html|.htm)
      echo "HTML Page|low" ;;
    .css|.js|.swf|.png|.jpg|.jpeg|.ttf|.woff*)
      echo "Static Asset|none" ;;
    *)
      echo "|none" ;;
  esac
}

# ── Helper: get path from URL ─────────────────────────────────
url_to_path() {
  echo "$1" | sed 's|https\?://[^/]*||'
}

# ── Helper: get extension from path ──────────────────────────
get_ext() {
  local path="$1"
  local base
  base=$(basename "$path")
  if [[ "$base" == *.* ]]; then
    echo ".${base##*.}" | tr '[:upper:]' '[:lower:]'
  else
    echo ""
  fi
}

# ── Helper: get parent dir from path ─────────────────────────
get_parent() {
  local path="$1"
  local ext
  ext=$(get_ext "$path")
  if [[ "$path" == */ ]] || [[ -z "$ext" ]]; then
    echo "$path"         # it IS a directory
  else
    dirname "$path"
  fi
}

# ── Stage 1 — nmap ───────────────────────────────────────────
run_nmap() {
  local target="$1" outdir="$2"
  echo -e "\n${CYAN}${BOLD}[*] Starting nmap -sCV scan on ${target}...${RESET}"
  echo

  nmap -sCV "$target" \
       -oN "${outdir}/nmap_scan.txt" \
       -oX "${outdir}/nmap_scan.xml"

  if [[ $? -ne 0 ]]; then
    err "nmap scan failed. Are you running as root?"
    exit 1
  fi

  echo
  echo -e "${GREEN}${BOLD}[+] nmap scan complete. Results:${RESET}"
  div
  cat "${outdir}/nmap_scan.txt"
  div
  echo
}

# ── Stage 2 — Parse HTTP ports ───────────────────────────────
parse_http_ports() {
  local nmap_file="$1"
  HTTP_PORTS=()

  while IFS= read -r line; do
    if echo "$line" | grep -qiE "^[0-9]+/tcp[[:space:]]+open[[:space:]]+(http|ssl/http)"; then
      local port service proto
      port=$(echo "$line"    | grep -oE "^[0-9]+")
      service=$(echo "$line" | awk '{print $3}' | tr '[:upper:]' '[:lower:]')
      if echo "$service" | grep -qi "ssl"; then
        proto="https"
      else
        proto="http"
      fi
      HTTP_PORTS+=("${port}|${service}|${proto}")
      ok "Found HTTP service → Port ${BOLD}${port}${RESET} (${service})"
    fi
  done < "$nmap_file"
  echo
}

# ── Stage 3a — gobuster ──────────────────────────────────────
run_gobuster() {
  local url="$1" wordlist="$2" outdir="$3" port="$4"
  info "Running gobuster on ${url}..."

  gobuster dir \
    --url      "$url" \
    --wordlist "$wordlist" \
    --output   "${outdir}/gobuster_port${port}.txt" \
    --threads  40 \
    --timeout  10s \
    --no-error \
    -k
  echo

  if [[ -s "${outdir}/gobuster_port${port}.txt" ]]; then
    ok "gobuster results saved → ${outdir}/gobuster_port${port}.txt"
  else
    warn "gobuster found no results for ${url}"
  fi
  echo
}

# ── Stage 3b — feroxbuster + organised report ────────────────
run_feroxbuster() {
  local url="$1" wordlist="$2" outdir="$3" port="$4"
  local raw_json="${outdir}/feroxbuster_port${port}_raw.json"
  local report="${outdir}/feroxbuster_port${port}_report.txt"

  info "Running feroxbuster on ${url} (recursive)..."
  echo -e "${DIM}    (running quietly in the background — please wait...)${RESET}"
  echo

  feroxbuster \
    --url      "$url" \
    --wordlist "$wordlist" \
    --output   "$raw_json" \
    --threads  40 \
    --timeout  10 \
    --insecure \
    --no-state \
    --json     \
    --silent   \
    2>/dev/null

  if [[ ! -s "$raw_json" ]]; then
    warn "feroxbuster returned no output for ${url}"
    return
  fi

  print_ferox_report "$raw_json" "$url" "$report"
}

# ── Feroxbuster report printer ───────────────────────────────
print_ferox_report() {
  local json_file="$1"
  local base_url="$2"
  local save_file="$3"

  # Pull only response objects (skips the big config block)
  local responses
  responses=$(jq -c 'select(.type == "response") | {url:.url, status:.status, size:.content_length}' \
              "$json_file" 2>/dev/null)

  # Pull open-directory-listing heuristic messages
  local dir_listings
  dir_listings=$(jq -r 'select(.type == "heuristics") |
                         select(.msg | ascii_downcase | contains("directory listing")) |
                         .url' "$json_file" 2>/dev/null)

  if [[ -z "$responses" ]]; then
    warn "feroxbuster found no results."
    return
  fi

  echo -e "${GREEN}${BOLD}[+] feroxbuster scan complete for ${base_url}${RESET}"
  divEq

  # ── Section 1: Discovered Paths ──────────────────────────
  echo -e "\n${CYAN}${BOLD}  DISCOVERED PATHS${RESET}"
  div

  # Collect unique parent directories in order
  declare -A seen_parents
  local all_parents=()
  while IFS= read -r entry; do
    local url path parent
    url=$(echo "$entry" | jq -r '.url')
    path=$(url_to_path "$url")
    parent=$(get_parent "$path")
    if [[ -z "${seen_parents[$parent]+_}" ]]; then
      seen_parents["$parent"]=1
      all_parents+=("$parent")
    fi
  done <<< "$responses"

  # Sort and iterate
  IFS=$'\n' sorted_parents=($(printf '%s\n' "${all_parents[@]}" | sort)); unset IFS

  for parent in "${sorted_parents[@]}"; do

    # Check open directory listing flag
    local listing_flag=""
    if echo "$dir_listings" | grep -qF "$parent"; then
      listing_flag="  ${RED}${BOLD}⚠  OPEN DIRECTORY LISTING${RESET}"
    fi

    echo -e "\n  ${CYAN}${BOLD}📁 ${parent}${RESET}${listing_flag}"
    divdot

    # Print entries belonging to this parent
    while IFS= read -r entry; do
      local url status size path ext parent_check label risk colour tag star sc
      url=$(echo "$entry"    | jq -r '.url')
      status=$(echo "$entry" | jq -r '.status')
      size=$(echo "$entry"   | jq -r '.size')
      path=$(url_to_path "$url")
      ext=$(get_ext "$path")
      parent_check=$(get_parent "$path")

      [[ "$parent_check" != "$parent" ]] && continue

      local info_raw
      info_raw=$(classify_ext "$ext")
      label=$(echo "$info_raw" | cut -d'|' -f1)
      risk=$(echo "$info_raw"  | cut -d'|' -f2)

      case $risk in
        high)   colour="$RED";    star=" ${RED}${BOLD}★${RESET}" ;;
        medium) colour="$YELLOW"; star=" ${YELLOW}${BOLD}★${RESET}" ;;
        *)      colour="$DIM";    star="" ;;
      esac

      tag=""
      [[ -n "$label" ]] && tag="  ${colour}[${label}]${RESET}"

      sc=$(status_colour "$status")
      echo -e "      ${sc}  ${BOLD}${path}${RESET}${tag}${star}  ${DIM}(${size} bytes)${RESET}"

    done <<< "$responses"
  done

  div

  # ── Section 2: Findings Summary ──────────────────────────
  echo -e "\n${CYAN}${BOLD}  FINDINGS SUMMARY${RESET}"
  div

  # Open directory listings
  local dl_count=0
  if [[ -n "$dir_listings" ]]; then
    dl_count=$(echo "$dir_listings" | grep -c .)
    echo -e "\n  ${RED}${BOLD}⚠  Open Directory Listings (${dl_count}):${RESET}"
    while IFS= read -r u; do
      [[ -n "$u" ]] && echo -e "       ${YELLOW}${u}${RESET}"
    done <<< "$dir_listings"
  fi

  # High-interest files
  local high_entries=() med_entries=()
  while IFS= read -r entry; do
    local url path ext risk
    url=$(echo "$entry" | jq -r '.url')
    path=$(url_to_path "$url")
    ext=$(get_ext "$path")
    risk=$(classify_ext "$ext" | cut -d'|' -f2)
    [[ "$risk" == "high"   ]] && high_entries+=("$entry")
    [[ "$risk" == "medium" ]] && med_entries+=("$entry")
  done <<< "$responses"

  if [[ ${#high_entries[@]} -gt 0 ]]; then
    echo -e "\n  ${RED}${BOLD}🔴 High-Interest Files (${#high_entries[@]}):${RESET}"
    for entry in "${high_entries[@]}"; do
      local url status path ext label sc
      url=$(echo "$entry"    | jq -r '.url')
      status=$(echo "$entry" | jq -r '.status')
      path=$(url_to_path "$url")
      ext=$(get_ext "$path")
      label=$(classify_ext "$ext" | cut -d'|' -f1)
      sc=$(status_colour "$status")
      echo -e "       ${sc}  ${BOLD}${url}${RESET}  ${RED}[${label}]${RESET}"
    done
  fi

  if [[ ${#med_entries[@]} -gt 0 ]]; then
    echo -e "\n  ${YELLOW}${BOLD}🟡 Medium-Interest Files (${#med_entries[@]}):${RESET}"
    for entry in "${med_entries[@]}"; do
      local url status path ext label sc
      url=$(echo "$entry"    | jq -r '.url')
      status=$(echo "$entry" | jq -r '.status')
      path=$(url_to_path "$url")
      ext=$(get_ext "$path")
      label=$(classify_ext "$ext" | cut -d'|' -f1)
      sc=$(status_colour "$status")
      echo -e "       ${sc}  ${BOLD}${url}${RESET}  ${YELLOW}[${label}]${RESET}"
    done
  fi

  # Counts
  local total dirs files
  total=$(echo "$responses" | grep -c .)
  dirs=0; files=0
  while IFS= read -r entry; do
    local url path ext
    url=$(echo "$entry" | jq -r '.url')
    path=$(url_to_path "$url")
    ext=$(get_ext "$path")
    if [[ "$path" == */ ]] || [[ -z "$ext" ]]; then
      (( dirs++ ))
    else
      (( files++ ))
    fi
  done <<< "$responses"

  echo -e "${BOLD}
  ┌──────────────────────────────────┐
  │  Total URLs found  : $(printf '%-11s' $total) │
  │  Directories       : $(printf '%-11s' $dirs) │
  │  Files             : $(printf '%-11s' $files) │
  │  Dir listings open : $(printf '%-11s' $dl_count) │
  │  High-interest     : $(printf '%-11s' ${#high_entries[@]}) │
  │  Medium-interest   : $(printf '%-11s' ${#med_entries[@]}) │
  └──────────────────────────────────┘${RESET}"
  echo

  divEq

  # ── Save plain-text report ────────────────────────────────
  {
    echo "feroxbuster Report — ${base_url}"
    echo "Generated : $(date '+%Y-%m-%d %H:%M:%S')"
    printf '=%.0s' {1..60}; echo
    echo

    if [[ -n "$dir_listings" ]]; then
      echo "OPEN DIRECTORY LISTINGS:"
      while IFS= read -r u; do
        [[ -n "$u" ]] && echo "  [OPEN DIR] $u"
      done <<< "$dir_listings"
      echo
    fi

    echo "ALL DISCOVERED URLS:"
    while IFS= read -r entry; do
      local url status size path ext label flag
      url=$(echo "$entry"    | jq -r '.url')
      status=$(echo "$entry" | jq -r '.status')
      size=$(echo "$entry"   | jq -r '.size')
      path=$(url_to_path "$url")
      ext=$(get_ext "$path")
      label=$(classify_ext "$ext" | cut -d'|' -f1)
      flag=""; [[ -n "$label" ]] && flag="  [${label}]"
      echo "  [${status}]  ${url}${flag}  (${size} bytes)"
    done <<< "$responses"

    echo
    echo "SUMMARY:"
    echo "  Total URLs       : ${total}"
    echo "  Dir listings     : ${dl_count}"
    echo "  High-interest    : ${#high_entries[@]}"
    echo "  Medium-interest  : ${#med_entries[@]}"
  } > "$save_file"

  ok "Formatted report saved → ${save_file}"
  echo
}

# ── Main ─────────────────────────────────────────────────────
main() {
  banner

  check_tools
  if [[ $? -ne 0 ]]; then
    err "One or more required tools are missing. Exiting."
    exit 1
  fi

  find_wordlist
  echo

  read -rp "$(echo -e "${BOLD}Enter target IP address: ${RESET}")" TARGET
  if ! validate_ip "$TARGET"; then
    err "Invalid IP address format. Exiting."
    exit 1
  fi

  local timestamp outdir
  timestamp=$(date +%Y%m%d_%H%M%S)
  outdir="recon_${TARGET}_${timestamp}"
  mkdir -p "$outdir"
  ok "Results will be saved to: ${BOLD}${outdir}/${RESET}"
  echo

  # Stage 1 — nmap
  run_nmap "$TARGET" "$outdir"

  # Stage 2 — HTTP ports
  info "Searching nmap results for HTTP/HTTPS services..."
  parse_http_ports "${outdir}/nmap_scan.txt"

  # Stage 3 — Directory enumeration
  if [[ ${#HTTP_PORTS[@]} -eq 0 ]]; then
    warn "No HTTP/HTTPS services detected on ${TARGET}."
    warn "Skipping directory enumeration. Scan complete."
  else
    echo -e "${CYAN}${BOLD}[*] HTTP services found — starting directory enumeration...${RESET}"
    echo

    for entry in "${HTTP_PORTS[@]}"; do
      local port service proto url
      port=$(echo "$entry"    | cut -d'|' -f1)
      service=$(echo "$entry" | cut -d'|' -f2)
      proto=$(echo "$entry"   | cut -d'|' -f3)
      url="${proto}://${TARGET}:${port}"

      divEq
      echo -e "${CYAN}${BOLD}  Target URL : ${url}${RESET}"
      divEq
      echo

      run_gobuster    "$url" "$WORDLIST" "$outdir" "$port"
      run_feroxbuster "$url" "$WORDLIST" "$outdir" "$port"
    done
  fi

  # Done
  echo -e "${GREEN}${BOLD}[✔] All scans complete!${RESET}"
  echo -e "${BOLD}    Results saved to: ${outdir}/${RESET}"
  echo
  echo -e "${BOLD}  Files generated:${RESET}"
  for f in $(ls "$outdir" | grep -v "_raw"); do
    echo "    $f"
  done
  echo
}

main
