# ADScop

A lightweight bash-based reconnaissance tool for Active Directory environments. Designed for internal network engagements, `adscope` automates the initial enumeration phase: host discovery, DC identification, and pre-authentication attack surface mapping.

## Features

- **Interface selection** — choose the network interface to scan, with automatic subnet CIDR derivation
- **Host discovery** — fping sweep with ARP cache intersection to identify live hosts
- **DC identification** — port-signature detection (88, 389, 445) to flag Domain Controller candidates
- **Domain extraction** — anonymous LDAP RootDSE query to retrieve the naming context
- **SMB null session check** — identify anonymous SMB access and DC metadata
- **AS-REP roasting** — pre-auth hash extraction with casing sweep for maximum coverage
- **Organized output** — per-host recon directories with raw results preserved

## Requirements

- Kali Linux (or any Debian-based distro)
- `fping`
- `nmap`
- `ldapsearch` (ldap-utils)
- `nxc` (NetExec)
- `impacket-GetNPUsers` (python3-impacket)

Install dependencies:

```bash
sudo apt install fping nmap ldap-utils python3-impacket
pip install netexec
