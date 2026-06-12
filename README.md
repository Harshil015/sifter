# Sifter — Automated Reconnaissance Scanner

A bash-based recon automation script that chains **nmap**, **gobuster**, and **feroxbuster** into a single workflow — scan a target, find HTTP services, enumerate directories, and get a clean categorised report, all without jumping between tools manually.

Built for CTF labs, OSCP-style practice, and authorised pentesting engagements.

---

## Why I built this

I got tired of running the same three tools in sequence on every box, copy-pasting ports, and then manually sifting through feroxbuster's raw JSON to find the files that actually matter. So I automated the whole pipeline and added a report layer that highlights high-interest findings (config files, backups, exposed scripts) without making you scroll through 300 lines of static assets.

---

## What it does

1. **Port scan** — runs `nmap -sCV` on the target and saves results (`.txt` + `.xml`)
2. **Service detection** — parses nmap output to extract HTTP and HTTPS ports automatically
3. **Directory enumeration** — runs `gobuster` and `feroxbuster` against every discovered web service
4. **Smart reporting** — feroxbuster's JSON output is parsed, paths are grouped by parent directory, and findings are classified by file type and risk level
5. **Summary** — prints a clean box with counts: total URLs, directories, open directory listings, high/medium interest files

All output is saved to a timestamped folder (`sifter_<IP>_<YYYYMMDD_HHMMSS>/`) so results never get overwritten between runs.

---

## Dependencies

You'll need these installed and in your `$PATH`:

| Tool | Purpose | Install |
|---|---|---|
| `nmap` | Port scanning & service detection | `sudo apt install nmap` |
| `gobuster` | Fast directory brute-forcing | `sudo apt install gobuster` |
| `feroxbuster` | Recursive content discovery | [GitHub releases](https://github.com/epi052/feroxbuster/releases) |
| `jq` | JSON parsing for feroxbuster output | `sudo apt install jq` |

The script will check for all four and exit cleanly if anything is missing.

**Default wordlist**: `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
This comes with Kali Linux and ParrotOS. If you're on something else, install `dirbuster` or point the script to your preferred list.

---

## Setup

```bash
git clone https://github.com/Harshil015/sifter
cd sifter
chmod +x sifter.sh
```

No install step, no Python environments, no config files. Just mark it executable and run it.

---

## Usage

```bash
sudo ./sifter.sh
```

The script will prompt for a target IP:

```
Enter target IP address: 10.10.11.45
```

Then it runs everything automatically. You'll see live nmap output, then gobuster results, then feroxbuster's categorised report.

> **Note**: nmap's `-sCV` scan requires root privileges. Run with `sudo`.

---

## Output

### Terminal output

The feroxbuster report is printed in sections:

**Discovered Paths** — grouped by parent directory, with HTTP status codes colour-coded:
- Green → `200 OK`
- Cyan → `3xx` redirects
- Yellow → `401 / 403`
- Red → `5xx` errors

Files are tagged by type and risk:

| Tag | Examples | Risk |
|---|---|---|
| `Script/Config/Sensitive` | `.php`, `.env`, `.bak`, `.sql`, `.conf` | 🔴 High |
| `Data/Config` | `.json`, `.yaml`, `.log`, `.xml` | 🟡 Medium |
| `HTML Page` | `.html`, `.htm` | Low |
| `Static Asset` | `.css`, `.js`, `.png` | None |

Open directory listings are flagged inline and collected in the summary.

### Saved files

Each run creates a folder like `sifter_10.10.11.45_20250614_143021/` containing:

```
nmap_scan.txt                      — human-readable nmap output
nmap_scan.xml                      — machine-readable nmap output
gobuster_port80.txt                — gobuster results (one file per port)
feroxbuster_port80_report.txt      — clean plain-text feroxbuster report
```

Raw feroxbuster JSON (`_raw.json`) is kept for reference but excluded from the file listing at the end.

---

## Example run (condensed)

```
[*] Starting nmap -sCV scan on 10.10.11.45...

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    Apache httpd 2.4.52

[+] Found HTTP service → Port 80 (http)

[*] Running gobuster on http://10.10.11.45:80...
[*] Running feroxbuster on http://10.10.11.45:80 (recursive)...

[+] feroxbuster scan complete for http://10.10.11.45:80
════════════════════════════════════════════════════════════

  DISCOVERED PATHS
────────────────────────────────────────────────────────────

  📁 /
  ·······················
      200  /index.html
      403  /server-status

  📁 /admin/  ⚠  OPEN DIRECTORY LISTING
  ·······················
      200  /admin/config.php  [Script/Config/Sensitive] ★
      200  /admin/db.bak      [Script/Config/Sensitive] ★

  FINDINGS SUMMARY
────────────────────────────────────────────────────────────

  ⚠  Open Directory Listings (1):
       http://10.10.11.45/admin/

  🔴 High-Interest Files (2):
       200  http://10.10.11.45/admin/config.php  [Script/Config/Sensitive]
       200  http://10.10.11.45/admin/db.bak      [Script/Config/Sensitive]

  ┌──────────────────────────────────┐
  │  Total URLs found  : 4           │
  │  Directories       : 2           │
  │  Files             : 2           │
  │  Dir listings open : 1           │
  │  High-interest     : 2           │
  │  Medium-interest   : 0           │
  └──────────────────────────────────┘
```

---

## How it works (under the hood)

- nmap output is parsed line-by-line with regex to extract port numbers and detect whether the service is plain HTTP or SSL/HTTP
- feroxbuster is run with `--json` and `--silent` so all output goes cleanly into a JSON file
- `jq` filters response objects from the JSON, stripping the config block
- Paths are grouped by parent directory using `dirname` logic — files without extensions are treated as directories
- Open directory listing detection reads feroxbuster's heuristics messages from the same JSON stream
- Status codes drive colour selection through a `case` statement, keeping terminal output readable at a glance

---

## Limitations & known issues

- Requires root for nmap's service version detection (`-sCV`)
- Wordlist path is hardcoded — if you use a custom list, edit `find_wordlist()` in the script
- IPv4 only (validation regex doesn't handle IPv6 or hostnames)
- Tested on Kali Linux and Ubuntu 22.04; not tested on macOS (BSD `date` syntax differs)

---

## Legal disclaimer

**Use only on systems you own or have explicit written permission to test.**

This tool is intended for authorised penetration testing, CTF competitions, and security research in controlled lab environments. Running it against systems without permission is illegal in most jurisdictions and is not something I endorse or support. If you're prepping for OSCP, HTB, or TryHackMe — this is the use case it was built for.

---

## Roadmap (maybe)

- [ ] Hostname/FQDN support alongside IP input
- [ ] Configurable wordlist via CLI argument
- [ ] Optional Nikto integration
- [ ] HTML report output
- [ ] Rate limiting option for slower, stealthier scans

---

## Author

Made as part of my security tooling practice while grinding through CTFs and working toward OSCP. Feedback and PRs welcome.
