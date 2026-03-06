#  Git Leak Explorer

<div align="center">

**Advanced forensic analysis, recovery, and reporting tool for exposed `.git` repositories and other artifacts publicly accessible over HTTP — with a modern visual interface, built for serious reconnaissance.**


<img width="1111" height="428" alt="_multi_menu" src="https://github.com/user-attachments/assets/2864a605-6659-481a-b38a-5755cda9394d" />


[About](#about) | [Legal Notice](#️-legal-notice) | [Features](#-key-features) | [Screenshots](#screenshots) | [Installation](#-installation--setup) | [Usage](#-how-to-use) | [Thanks](#tophat-thanks-)

<br>

### <a href="http://demo-gitleak-explorer.rodrigo.londrina.br/" target="_blank">Live report demo available here</a>

<br>

<a href="https://github.com/roodriiigooo/GITLEAK_EXPLORER/releases/latest">
  <img src="https://img.shields.io/github/v/release/roodriiigooo/GITLEAK_EXPLORER?style=flat&color=blue" alt="Latest Release">
</a>

<a href="https://www.python.org/">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat&logo=python&logoColor=white" alt="Python Version">
</a>

<a href="https://desktop.github.com/download/">
  <img src="https://img.shields.io/badge/GitHub_Desktop-3.5.4%2B-3776AB?logo=github&logoColor=white" alt="Github">
</a>

<a href="LICENSE">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License">
</a>

<img src="https://img.shields.io/badge/Status-Active-success?style=flat" alt="Status">

</div>

<br>

---

## About

**Git Leak Explorer** is an all-in-one tool designed for security researchers, penetration testers, and system administrators. It identifies, downloads, reconstructs, and analyzes artifacts from `.git` folders inadvertently exposed on web servers.

The tool goes far beyond a simple downloader. It offers commit history reconstruction with file-level diffs and stash recovery, security exposure detection (hardening analysis), packfile support, secrets scanning with entropy-based filtering, **SAST static analysis via Semgrep** (with OWASP/CWE mapping), infrastructure mapping, brute-force file discovery, and a modern interactive HTML interface with Dark Mode for all generated reports.

It also optionally detects leaks from SVN, Mercurial, `.env`, and `.DS_Store` artifacts. Mass scanning over a list of targets and brute-force recovery using custom wordlists are both supported.

Everything in a single Python file. Lightweight, direct, and effective.

> **Contributing**
> Feel free to contribute, submit suggestions, and open pull requests. 🙂

---

## ⚠️ Legal Notice

This tool was developed for ethical professional use, education, and authorized security auditing only. Accessing third-party systems without explicit permission is illegal, unethical, and subject to legal penalties.

**The developer assumes no responsibility for misuse of this software.**

---

## ✨ Key Features

- **👁️ Blind Mode** — Intelligent recovery even when `.git/index` is absent or blocked (HTTP 403/404), by crawling commit trees and object references directly.
- **🔍 Artifact Reconstruction** — Downloads and reconstructs files locally from the remote `.git/index`, restoring the original directory structure.
- **📜 Commit History** — Reconstructs the full commit chain (messages, authors, timestamps, changed files) without cloning the repository, with stash recovery, orphan/reflog detection, and side-by-side diff viewing.
- **🛡️ Hardening Analysis** — Checks exposure of sensitive Git files (`config`, `HEAD`, `logs`, `packed-refs`, `index`, etc.) and generates a risk report with Critical/Warning severity levels.
- **📦 Packfile Support** — Detects, downloads, and unpacks `.pack` files (compressed Git objects) automatically. Requires `git` to be installed for unpacking.
- **🔐 Secrets Scanner** — Scans recovered source files using regex patterns and Shannon entropy analysis to detect credentials, API keys, tokens, and connection strings. Includes per-pattern validation to suppress false positives.
- **🧪 SAST (Static Analysis)** — Runs [Semgrep](https://semgrep.dev/) on reconstructed source files to detect exploitable vulnerability patterns: SQL injection, XSS, command injection, path traversal, insecure deserialization, hardcoded credentials, weak cryptography, SSRF, and more. Each finding is enriched with its OWASP Top 10 category and CWE identifier. Supports custom rule files via `--sast-rules` for fully offline use.
- **🌐 Infrastructure Mapping** — Extracts API endpoints, external hosts, and IP addresses from recovered source and config files, with an interactive network graph view.
- **📊 Unified Reports** — Generates a complete interactive HTML dashboard (`report.html`) covering files, history, hardening, secrets, infrastructure, and more. All reports share a consistent navigation bar and dark theme.
- **🎨 Modern Interface** — Every HTML report features a terminal-noir dark theme (with light mode toggle), real-time search, sorting, and pagination.
- **💪 Brute-Force Recovery** — Probes for common files and paths using a built-in wordlist or a custom one. Automatically fingerprints the server's 404 response to eliminate false positives (catch-all pages, custom error pages, homepage redirects).
- **🚀 High Performance** — Multi-threaded downloads using a pooled session for parallel object retrieval. Configurable worker count.
- **🔍 Additional Leak Detection** — Scans for SVN (`wc.db`), Mercurial, `.env`, `.DS_Store`, Git hooks, and other artifacts via `--full-scan`.
- **🌍 Proxy Support** — Connect through any proxy, including Burp Suite, OWASP ZAP, and the Tor network (SOCKS5).
- **🕵️ Random User-Agents** — Rotates User-Agent headers by default to reduce detection likelihood.
- **💻 Local Mode** — Analyze an already-cloned or recovered local `.git` folder without making any network requests.
- **📺 Built-in HTTP Server** — Serve generated reports locally via `--serve` for convenient browser-based review.

---

## Screenshots

<details>
  <summary>Multi-Scan Overview</summary>
  <img width="1032" height="554" alt="image" src="https://github.com/user-attachments/assets/2864a605-6659-481a-b38a-5755cda9394d" />
</details>

<details>
  <summary>Target Dashboard</summary>
  <img width="1227" height="2154" alt="image" src="https://github.com/user-attachments/assets/90eb3771-a71f-49ec-8084-974dfabb9eae" />

</details>

<details>
  <summary>Secrets Report</summary>
  <img width="1466" height="767" alt="_secrets" src="https://github.com/user-attachments/assets/fbf439d0-774b-4e30-9839-a418ea648a02" />
</details>

<details>
  <summary>Hardening Analysis</summary>
  <img width="1284" height="963" alt="_hardening" src="https://github.com/user-attachments/assets/8cb1fd9f-918d-4fd3-9659-001703d10ebd" />
</details>

<details>
  <summary>Users / OSINT (from history)</summary>
  <img width="1284" height="963" alt="_users" src="https://github.com/user-attachments/assets/75a2389e-8c57-4bae-887a-63558916db6c" />
</details>

<details>
  <summary>Git Timeline (Commit History, Stash and Orphan)</summary>
  <img width="1903" height="2486" alt="image" src="https://github.com/user-attachments/assets/a9a2599d-4be1-4a3a-8ada-495b19df1d4a" />
</details>

<details>
  <summary>File Listing (with filter)</summary>
  <img width="1641" height="1231" alt="_listing" src="https://github.com/user-attachments/assets/098c40d7-9126-4812-a999-6c3ddcbe02d4" />
</details>

<details>
  <summary>Brute-Force & Path Traversal (with filter)</summary>
  <img width="1512" height="822" alt="_brute_traversal" src="https://github.com/user-attachments/assets/d205e83a-cea6-48b7-9805-0456c8f5059c" />
</details>

<details>
  <summary>Infrastructure Map</summary>
  <img width="1136" height="852" alt="_outros" src="https://github.com/user-attachments/assets/9b2e4361-3940-4cd8-8514-e172135e2853" />
</details>

---

## 🚀 Installation & Setup

> [!TIP]
> This repository includes a **standalone Windows build** (`.exe`) in the [Releases](https://github.com/roodriiigooo/GITLEAK_EXPLORER/releases/latest) section. Copy it to a directory of your choice, register it in your system `PATH`, and you can skip the steps below.
> Git still needs to be installed on the system for packfile unpacking.

**Requirements:** [Python 3.8+](https://www.python.org/downloads/) and [Git](https://desktop.github.com/download/) (required for unpacking `.pack` objects).

> [!NOTE]
> **SAST scanning** (`--sast-scan`) requires Semgrep as an additional optional dependency: `pip install semgrep`

[![Python](https://img.shields.io/badge/Python-Download-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![GitHub Desktop](https://img.shields.io/badge/Git-Download-181717?logo=git&logoColor=white)](https://git-scm.com/downloads)

<br>

**Clone the repository:**
```bash
git clone https://github.com/roodriiigooo/GITLEAK_EXPLORER.git
cd GITLEAK_EXPLORER
```

### Option 1: pip (recommended)
```bash
pip install -r requirements.txt
```

### Option 2: Pipenv
```bash
pipenv install requests
pipenv shell
python git_leak.py --help
```

### Option 3: Poetry
```bash
poetry init -n
poetry add requests
poetry run python git_leak.py --help
```

### Option 4: 🐳 Docker
```bash
docker build -t gitleak_explorer .
docker run -v $(pwd)/repo:/app/repo gitleak_explorer http://target.com/.git --default --output-dir /app/repo
```

### Option 5: 📦 Compile to .EXE (Windows)
To create a portable standalone executable:

1. Install PyInstaller:
```bash
pip install pyinstaller
```
2. Compile:
```bash
pyinstaller --onefile --name "git_leak" git_leak.py
```
The resulting `git_leak.exe` will be found in the `dist/` folder.

---

## 📖 How to Use

> [!TIP]
> If you are using the Windows standalone release, replace `python git_leak.py` with `git_leak.exe` in all commands below.

### Available Flags

```
git_leak.py — Full forensic recovery and analysis toolkit for exposed Git repositories.

Usage: python git_leak.py <URL> [OPTIONS]
Example: python git_leak.py http://target.com --full-scan

Core flags:
  --parse-index           Download .git/index and convert to JSON
  --blind                 Blind mode: crawl commits/trees when .git/index is absent or blocked (403/404)
  --reconstruct           Download blobs from dump.json and rebuild .git/objects locally
  --list                  Generate listing.html — a searchable file listing from the index
  --reconstruct-history   Rebuild the commit chain as an interactive UI (history.json + history.html)
  --detect-hardening      Check exposure of sensitive Git files; generate hardening_report.json/.html
  --packfile [MODE]       Manage .pack files  (modes: list | download | download-unpack)
  --secrets               Run regex + Shannon entropy scanner to detect credentials and API keys
  --sast-scan             Run SAST (Semgrep) on recovered source files to detect exploitable patterns
  --sast-rules PATH       Path to a local Semgrep YAML rule file (optional; uses 'auto' if omitted)
  --extract-infra         Extract API endpoints, external hosts, and IPs from recovered source files
  --full-history          Analyze the full file tree of ALL commits (slow; use with --show-diff)
  --show-diff             Download and render side-by-side code diffs in history (can be VERY slow)
  --full-scan             Run extended leak scan: SVN, Mercurial, .env, .DS_Store, Git hooks
  --bruteforce            Attempt recovery of common files via brute force
  --wordlist PATH         Path to a custom wordlist for brute-force (overrides built-in list)
  --report                Re-generate only the final unified dashboard (report.html) from existing data
  --serve                 Start a local HTTP server and open reports in the browser when done
  --sha1 HASH             Download and reconstruct a single Git object by its SHA-1 hash
  --scan FILE             Mass-scan mode: read a list of target URLs from a file
  --local PATH            Analyze a local .git folder instead of a remote target
  --proxy URL             Proxy URL (e.g. http://127.0.0.1:8080 for Burp/ZAP, socks5h://127.0.0.1:9150 for Tor)
  --no-random-agent       Disable User-Agent rotation (use a fixed agent)
  --workers N             Number of parallel download threads (default: 10)
  --max-commits N         Maximum number of commits to process (default: 200)
  --output-dir PATH       Root output directory (default: ./repo)
  --output-index FILE     Filename for the JSON index (default: dump.json)
  --serve-dir PATH        Specific directory to serve with --serve
  --ignore-missing        Silently skip missing objects instead of warning
  --strict                Abort on critical errors

All output files are stored under the provided output directory:
  HTML reports     → outdir/
  JSON/data files  → outdir/_files/
```

---

### Automatic Mode (Recommended)

Runs the full pipeline: downloads the index, checks hardening, detects packfiles, reconstructs history, runs stash recovery, and generates the final report.

```bash
python git_leak.py http://example.com
# or explicitly
python git_leak.py http://example.com/.git --default
```

---

### Local Analysis

Analyze a folder that already contains a `.git` directory, without making any network requests. Useful for post-extraction analysis or local testing.

```bash
python git_leak.py --local /path/to/project
# with a custom output directory and built-in server
python git_leak.py --local /path/to/project --serve --output-dir temp/output/
```

---

### Extended Leak Detection (`--full-scan`)

In addition to the standard pipeline, scans for SVN, Mercurial, `.env`, `.DS_Store`, Git hooks, and other artifacts.

```bash
python git_leak.py http://example.com/.git --full-scan
```

---

### Commit Diff View (`--show-diff`)

Fetches and renders side-by-side code diffs for each changed file in history. Can significantly increase runtime.

```bash
python git_leak.py http://example.com/.git --show-diff
```

---

### Full History Reconstruction (`--full-history`)

Traces and analyzes every commit reachable from HEAD, not just the main chain. Combine with `--show-diff` for a complete picture.

```bash
python git_leak.py http://example.com/.git --full-history
# with diffs
python git_leak.py http://example.com/.git --full-history --show-diff
```

---

### Secrets Scanning (`--secrets`)

Scans recovered files for credentials, API keys, tokens, and connection strings using a combination of pattern matching and Shannon entropy thresholds. Patterns include AWS, GitHub, GitLab, Stripe, Heroku, Twilio, Telegram, Slack, DigitalOcean, NPM, private keys, database connection strings, and generic API key assignments.

```bash
python git_leak.py http://example.com/.git --secrets
```

---

### SAST — Static Application Security Testing (`--sast-scan`)

Runs [Semgrep](https://semgrep.dev/) on all reconstructed source files to detect exploitable vulnerability patterns in the recovered code. This turns the tool into a **source-code auditing platform** during a pentest — leaked code may contain bugs that are actively exploitable on the live target.

> [!WARNING]
> SAST scanning may take **several minutes** depending on the number of recovered files and the rule set used. A warning message is printed when the scan begins.

**Detected vulnerability classes:**

| Pattern | OWASP Category | CWE |
|---|---|---|
| SQL Injection | A03 — Injection | CWE-89 |
| Cross-Site Scripting (XSS) | A03 — Injection | CWE-79 |
| Command Injection / `eval` | A03 — Injection | CWE-78 / CWE-94 |
| Path Traversal | A01 — Broken Access Control | CWE-22 |
| Insecure Deserialization | A08 — Insecure Deserialization | CWE-502 |
| Hardcoded Credentials | A07 — Identification Failures | CWE-798 |
| Weak / Broken Cryptography | A02 — Cryptographic Failures | CWE-327 |
| SSRF | A10 — SSRF | CWE-918 |
| Open Redirect | A01 — Broken Access Control | CWE-601 |
| XXE | A05 — Security Misconfiguration | CWE-611 |

With the default **`auto`** ruleset (requires internet on first run to fetch rules):
```bash
python git_leak.py http://example.com/.git --sast-scan
```

With a **custom local rule file** (fully offline, ideal for air-gapped environments):
```bash
python git_leak.py http://example.com/.git --sast-scan --sast-rules ./my_rules.yaml
```

Combined with secrets scanning for a **full code audit**:
```bash
python git_leak.py http://example.com/.git --secrets --sast-scan --serve
```

Results are saved to `_files/sast.json` and rendered as `sast_report.html` — a searchable, paginated report showing severity (ERROR / WARNING / INFO), CWE and OWASP labels, the offending code line in context, and one-click copy buttons for the file path and rule ID. A summary card also appears on the main dashboard with a direct link to the full report.

> [!NOTE]
> Install Semgrep separately before using this flag: `pip install semgrep`

---

### Infrastructure Mapping (`--extract-infra`)

Extracts API endpoint assignments, HTTP call sites, external hosts, and non-private IP addresses from recovered source and config files. Results are shown as an interactive network graph and a searchable table.

```bash
python git_leak.py http://example.com/.git --extract-infra
```

---

### Specific Commands

**Re-generate the report from already-downloaded data:**
```bash
python git_leak.py http://example.com/.git --report
```

**Start the built-in HTTP server to browse reports:**
```bash
python git_leak.py http://example.com/.git --serve
# serve a specific output directory
python git_leak.py --serve --output-dir temp/output/
```

**Download a single object by SHA-1:**
```bash
# Useful when you spot an interesting file in the listing and have its blob SHA
python git_leak.py http://example.com/.git --sha1 138605f2337271f004c5d18cf3158fce3f4a4b16
# with custom output directory
python git_leak.py http://example.com/.git --sha1 138605f2337271f004c5d18cf3158fce3f4a4b16 --output-dir temp/output/
```

**Manage packfiles:**
```bash
# List detected packfiles
python git_leak.py http://example.com/.git --packfile list
# Download and unpack (requires git)
python git_leak.py http://example.com/.git --packfile download-unpack
```

**Mass scan a list of targets:**
```bash
python git_leak.py --scan targets.txt
```

**Mass scan with brute-force and a custom wordlist:**
```bash
python git_leak.py --scan targets.txt --output-dir scan_results --full-scan --bruteforce --wordlist wordlist.txt --serve
```

---

### Brute-Force (`--bruteforce`)

Probes the target for common files and paths. Before scanning, the tool sends requests to two guaranteed-absent URLs to fingerprint the server's 404 response (content hash, size, similarity), then filters out any response that matches this baseline — preventing false positives from catch-all pages or homepage redirects.

When `--bruteforce` is used without `--wordlist`, the built-in list is used, covering:

```
# Environment & Secrets
.env, .env.local, .env.dev, .env.prod, .env.production, .env.example, .env.bak,
config.json, secrets.json, config.yaml, secrets.yaml, config.toml, config.php,
settings.py, database.yml

# Version Control & CI/CD
.git/config, .gitignore, .gitmodules,
.gitlab-ci.yml, .travis.yml, circle.yml, Jenkinsfile,
.github/workflows/main.yml, .github/workflows/deploy.yml

# JavaScript / Node.js
package.json, package-lock.json, yarn.lock, .npmrc,
webpack.config.js, next.config.js, nuxt.config.js, server.js, app.js

# PHP / CMS / Frameworks
wp-config.php, wp-config.php.bak, configuration.php,   # WordPress, Joomla
.htaccess, composer.json, composer.lock, artisan        # Laravel

# Python / Django / Flask
requirements.txt, Pipfile, manage.py, app.py, wsgi.py

# ASP.NET / C#
web.config, appsettings.json, appsettings.Development.json, Global.asax

# Docker / Kubernetes / Terraform / Serverless
Dockerfile, docker-compose.yml, kubeconfig, deployment.yaml,
main.tf, variables.tf, terraform.tfvars, serverless.yml

# Backups & Dumps
backup.zip, backup.sql, dump.sql, database.sql, www.zip, site.zip

# IDEs, SSH & Logs
.vscode/settings.json, .idea/workspace.xml,
id_rsa, id_rsa.pub, known_hosts, debug.log, access.log
```

**VERSIONED** files (those whose SHA-1 matches a known Git object on the server) can be previewed directly in the report browser with a single click.

---

### Proxy & Anonymity

```bash
# Through Burp Suite or OWASP ZAP
python git_leak.py example.com --proxy http://127.0.0.1:8080 --full-scan --bruteforce --serve

# Through Tor (SOCKS5)
python git_leak.py example.com --proxy socks5h://127.0.0.1:9150 --full-scan --bruteforce --serve

# Disable User-Agent rotation (use a fixed agent)
python git_leak.py example.com --no-random-agent --proxy http://127.0.0.1:8080 --serve
```

---

### Full Kitchen-Sink Command

```bash
# Scans every target in a text file with all features enabled:
# full-scan, Tor proxy, 250 workers, secrets detection, SAST (Semgrep),
# infrastructure mapping, brute-force, full history with diffs, packfile unpacking,
# served locally at the end.
python git_leak.py \
  --scan targets.txt \
  --full-scan \
  --output-dir MY_SCAN \
  --proxy socks5h://127.0.0.1:9150 \
  --workers 250 \
  --secrets \
  --sast-scan \
  --extract-infra \
  --bruteforce \
  --full-history \
  --show-diff \
  --packfile download-unpack \
  --serve
```

---

### Output Structure

After a run, the output directory will contain:

```
outdir/
├── report.html                 ← Main unified dashboard
├── listing.html                ← File listing from .git/index
├── history.html                ← Commit timeline with diffs and stash entries
├── users.html                  ← Identified authors (OSINT)
├── secrets.html                ← Detected credentials and API keys
├── sast_report.html            ← SAST findings (Semgrep) with OWASP/CWE mapping
├── hardening_report.html       ← Exposure risk report
├── infrastructure_report.html  ← Network graph + endpoint table
├── bruteforce_report.html      ← Brute-force / traversal results
├── <recovered source files>    ← Reconstructed files in their original paths
└── _files/
    ├── dump.json               ← Parsed .git/index entries
    ├── history.json            ← Reconstructed commit chain
    ├── secrets.json            ← Raw secrets findings
    ├── sast.json               ← Raw SAST findings (Semgrep output)
    ├── bruteforce.json         ← Brute-force results
    ├── hardening_report.json   ← Raw hardening data
    ├── users.json              ← Author list
    ├── stash.json              ← Stash metadata (if recovered)
    ├── infrastructure.json     ← Infrastructure findings
    ├── bruteforce/             ← Downloaded brute-force files
    ├── extracted_packs/        ← Unpacked packfile contents
    └── misc/                   ← .env, SVN, DS_Store dumps
```

> [!TIP]
> When reviewing recovered packfile contents, it is recommended to open the `extracted_packs/` folder in an IDE such as Visual Studio Code for easier navigation and syntax highlighting.

---

## :tophat: Thanks ♥

No contributors yet — be the first! 🙂

## :sparkling_heart: Support

<a href="https://www.buymeacoffee.com/rodrigoo" target="_blank"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-5C3317?style=for-the-badge&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me A Coffee" target="_blank"></a>
