#!/usr/bin/env python3
r"""
  _____ _ _   _            _    ______            _
 / ____(_) | | |          | |  |  ____|          | |
| |  __ _| |_| | ___  __ _| | _| |__  __  ___ __ | | ___  _ __ ___ _ __
| | |_ | | __| |/ _ \/ _` | |/ /  __| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|
| |__| | | |_| |  __/ (_| |   <| |____ >  <| |_) | | (_) | | |  __/ |
 \_____|_|\__|_|\___|\__,_|_|\_\______/_/\_\ .__/|_|\___/|_|  \___|_|
                                           | |
                                           |_|

git_leak.py — Git Leak Explorer
Advanced forensic recovery and analysis tool for exposed Git repositories.

Core Features:
 - Recovery via Index or Blind Mode (Crawling)
 - Intelligent file and directory structure reconstruction
 - Commit history analysis (Metadata + Files)
 - Hardening detection and other leak vectors (SVN, HG, Env, DS_Store)
 - Detailed technical reports and modern visual HTML interface

Usage: python git_leak.py <URL> [OPTIONS]
Example: python git_leak.py http://target.com --full-scan

Available flags:
 --parse-index         : Downloads .git/index and converts to JSON
 --blind               : Blind mode: trace commits/trees when .git/index is absent/403
 --reconstruct         : Downloads blobs from dump.json and rebuilds .git/objects locally
 --list                : Generates listing.html (simplified UI) of files found in the index
 --serve               : Opens an HTTP server for report viewing
 --sha1                : Downloads a single object by SHA
 --reconstruct-history : Rebuilds commit chain as UI only (history.json + history.html)
 --detect-hardening    : Exposure checks, generates hardening_report.json and .html
 --packfile [MODE]     : Packfile handling (modes: list, download, download-unpack)
 --scan                : Runs scan on multiple targets looking for .git/HEAD exposure
 --full-history        : Analyzes complete file tree of ALL commits (slow)
 --full-scan           : Runs full leak scan (SVN, HG, Env, DS_Store)
 --report              : Generates only the final report (report.html)
 --bruteforce          : Attempts common file recovery via brute force
 --wordlist            : Path to custom wordlist (Brute-Force)
 --proxy               : Proxy URL (e.g. http://127.0.0.1:8080 for Burp/ZAP or socks5h://127.0.0.1:9150 for Tor)
 --no-random-agent     : Disables User-Agent rotation (uses a fixed one)
 --secrets             : Runs regex/entropy scanner looking for credentials
 --show-diff           : Downloads and shows code diffs in history (can be VERY slow)
 --extract-infra       : Extracts IPs, URLs and infrastructure endpoints
 --local               : Full path to local project folder (e.g. /home/user/app)
 Options: --max-commits, --ignore-missing, --strict, --workers, --output-index, --output-dir, --serve-dir

 All output files are stored in the provided external directory:
   HTML files at the root, JSON/other files in outdir/_files.
"""

from __future__ import annotations

# ─── stdlib ───────────────────────────────────────────────────────────────────
import os
import sys
import re
import json
import glob
import zlib
import struct
import shutil
import random
import hashlib
import base64
import difflib
import argparse
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

# ─── third-party ──────────────────────────────────────────────────────────────
import requests
import urllib3

try:
    from ds_store import DSStore
    HAS_DS_STORE_LIB = True
except ImportError:
    HAS_DS_STORE_LIB = False

# ─── suppress TLS warnings ────────────────────────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — GLOBAL SESSION & CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT  = 15
USE_RANDOM_AGENT = True

# Pooled session for concurrent requests
SESSION = requests.Session()
_adapter = requests.adapters.HTTPAdapter(
    pool_connections=100, pool_maxsize=100, max_retries=1
)
SESSION.mount("http://",  _adapter)
SESSION.mount("https://", _adapter)

USER_AGENTS = [
    # Windows — Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Windows — Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Windows — Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # macOS — Chrome & Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # macOS — Firefox
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Legacy
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
]

# Secret detection patterns (regex)
SECRET_PATTERNS: Dict[str, str] = {
    "AWS Access Key ID":         r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
    "Google API Key":            r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth":              r"[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com",
    "Heroku API Key":            r"(?i)HEROKU_API_KEY\s*=\s*[0-9a-fA-F-]{36}",
    "DigitalOcean Token":        r"dop_v1_[a-f0-9]{64}",
    "GitHub Token":              r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "GitLab Token":              r"glpat-[0-9a-zA-Z\-\_]{20}",
    "NPM Access Token":          r"npm_[a-zA-Z0-9]{36}",
    # Slack: require the full token form (at least one dash-separated segment)
    "Slack Token":               r"xox[baprs]-[0-9]{8,13}-[0-9A-Za-z\-]{10,}",
    "Stripe Live Key":           r"(sk_live|rk_live)_[0-9a-zA-Z]{24,}",
    # Twilio: require context — must appear as an assignment/value, not a bare word
    "Twilio Account SID":        r"(?i)(?:account_sid|accountsid|twilio[_\-]?sid|TWILIO[_\-]?ACCOUNT[_\-]?SID)\s*[:=]\s*['\"]?(AC[a-zA-Z0-9]{32})['\"]?",
    "Telegram Bot Token":        r"(?<!\d)[0-9]{9,10}:[a-zA-Z0-9_-]{35}(?![a-zA-Z0-9_-])",
    "Private Key (RSA/DSA/EC)":  r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----",
    "Putty PPK":                 r"PuTTY-User-Key-File-[23]",
    "DB Connection String":      r"(postgres|mysql|mongodb|redis)://[^:\s'\"]{1,64}:[^@\s'\"]{1,64}@[a-zA-Z0-9\.\-]+(:\d+)?",
    "Generic API Key":           r"(?i)(?:api[_\-]?key|access[_\-]?token|secret[_\-]?key|auth[_\-]?token|client[_\-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9\-_\.]{32,})['\"]",
}

# Other-leak detection signatures
MISC_SIGNATURES: Dict[str, Dict] = {
    "svn":         {"path": "/.svn/wc.db",                    "magic": b"SQLite format 3",     "desc": "SVN Repository (wc.db)"},
    "hg":          {"path": "/.hg/store/00manifest.i",        "magic": b"\x00\x00\x00\x01",    "desc": "Mercurial Repository"},
    "ds_store":    {"path": "/.DS_Store",                     "magic": b"\x00\x00\x00\x01",    "desc": "macOS Metadata (.DS_Store)"},
    "env":         {"path": "/.env",                          "regex": br"^\s*[A-Z_0-9]+\s*=", "desc": "Environment Variables (.env)"},
    "exclude":     {"path": "/.git/info/exclude",             "regex": br"(?m)^#.*git ls-files","desc": "Local Git Ignore (info/exclude)"},
    "description": {"path": "/.git/description",              "min_len": 5,                     "desc": "GitWeb Description"},
    "commit_msg":  {"path": "/.git/COMMIT_EDITMSG",           "min_len": 1,                     "desc": "Last Commit Message"},
    "hook_sample": {"path": "/.git/hooks/pre-commit.sample",  "magic": b"#!",                   "desc": "Hook Sample (Directory Exposure)"},
    "hook_active": {"path": "/.git/hooks/pre-commit",         "magic": b"#!",                   "desc": "Active Hook (Potential RCE)"},
}

COMMON_FILES: List[str] = [
    # Environment & Secrets
    ".env", ".env.local", ".env.dev", ".env.development", ".env.prod", ".env.production",
    ".env.example", ".env.sample", ".env.save", ".env.bak", ".env.old",
    "config.json", "secrets.json", "config.yaml", "secrets.yaml", "config.toml", "config.php",
    "settings.py", "database.yml", "robots.txt", "README.md", "index.php", "index.html", "server.js",
    # Version Control & CI/CD
    ".git/config", ".gitignore", ".gitmodules",
    ".gitlab-ci.yml", ".travis.yml", "circle.yml", "jenkinsfile", "Jenkinsfile",
    ".github/workflows/main.yml", ".github/workflows/deploy.yml",
    # JavaScript / Node.js
    "package.json", "package-lock.json", "yarn.lock", ".npmrc",
    "webpack.config.js", "rollup.config.js", "next.config.js", "nuxt.config.js",
    "server.js", "app.js",
    # PHP / CMS / Frameworks
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "configuration.php", "configuration.php.bak",
    ".htaccess", "composer.json", "composer.lock", "auth.json",
    "artisan", "phpunit.xml",
    # Python / Django / Flask
    "requirements.txt", "Pipfile", "Pipfile.lock", "setup.py", "pyproject.toml",
    "manage.py", "app.py", "wsgi.py", "uwsgi.ini",
    # ASP.NET / C#
    "web.config", "Web.config", "appsettings.json", "appsettings.Development.json",
    "packages.config", "Global.asax",
    # Docker / Kubernetes / Cloud / Terraform
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore",
    "Makefile", "Vagrantfile",
    "k8s.yaml", "kubeconfig", "deployment.yaml",
    "main.tf", "variables.tf", "terraform.tfvars", ".terraform.lock.hcl",
    "serverless.yml", "serverless.yaml",
    # Backups & Dumps
    "backup.zip", "backup.tar.gz", "backup.sql",
    "dump.sql", "database.sql", "db_backup.sql", "users.sql",
    "www.zip", "site.zip", "public.zip", "html.tar.gz",
    # IDEs & Logs
    ".vscode/settings.json", ".idea/workspace.xml",
    "debug.log", "error_log", "access.log", "npm-debug.log",
    "id_rsa", "id_rsa.pub", "known_hosts",
]

INFRA_PATTERNS: Dict[str, str] = {
    # API endpoints explicitly assigned to variables in JS/TS/config files
    "API_ENDPOINT": (
        r"(?:baseURL|apiUrl|endpoint|API_URL|BASE_URL|base_url|api_base|apiBase"
        r"|api_endpoint|apiEndpoint|service_url|serviceUrl)"
        r"\s*[:=]\s*['\"`]"
        r"((?:https?://[a-zA-Z0-9._\-]+(?::\d+)?)?/[a-zA-Z0-9._\-/{}:?&=]+)"
        r"['\"`]"
    ),
    # fetch() / axios / XMLHttpRequest / $.ajax explicit call targets
    "HTTP_CALL": (
        r"(?:fetch|axios\.(?:get|post|put|delete|patch|request)"
        r"|XMLHttpRequest|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH)['\"]"
        r"|http\.(?:get|post|request)"
        r"|\$\.(?:ajax|get|post))"
        r"\s*\(\s*[`'\"]((?:https?://[^\s'\"`,)]+|/[a-zA-Z0-9._\-/{}:?&=]+))[`'\"]"
    ),
    # Hard-coded external host references (not CDN/font noise)
    "EXTERNAL_HOST": (
        r"(?:https?://|//)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"\.[a-zA-Z]{2,10})(?::\d+)?(?:/[^\s'\"<>]*)?"
    ),
    # Non-loopback, non-RFC-1918 IPv4 addresses
    "IP_ADDRESS": (
        r"(?<![.\d])"
        r"((?!(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|255\.)))"
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        r"(?![\d.])"
    ),
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — LOGGING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def info(msg: str)    -> None: print(f"[+] {msg}")
def success(msg: str) -> None: print(f"[✔] {msg}")
ok = success
def warn(msg: str)    -> None: print(f"[!] {msg}")
def fail(msg: str)    -> None: print(f"[❌] {msg}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — NETWORK LAYER
# ══════════════════════════════════════════════════════════════════════════════

class LocalResponse:
    """Simulates a requests.Response object for local file reading."""
    def __init__(self, content: bytes, status_code: int) -> None:
        self.content     = content
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code != 200:
            raise Exception(f"Local error: {self.status_code}")

    @property
    def text(self) -> str:
        return self.content.decode(errors="ignore") if self.content else ""


def _random_headers() -> Dict[str, str]:
    ua = random.choice(USER_AGENTS) if USE_RANDOM_AGENT else USER_AGENTS[0]
    return {
        "User-Agent":               ua,
        "Accept":                   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":          "en-US,en;q=0.9",
        "Accept-Encoding":          "gzip, deflate",
        "Connection":               "keep-alive",
        "Upgrade-Insecure-Requests":"1",
        "Cache-Control":            "max-age=0",
    }


def normalize_url(url: str, proxies: Optional[Dict] = None) -> str:
    url = url.strip()
    if url.startswith("local://"):
        return url
    if os.path.isdir(url):
        clean = os.path.abspath(url).replace("\\", "/")
        return f"local://{clean}"
    url = re.sub(r"/\.git(/.*)?$", "", url, flags=re.IGNORECASE).rstrip("/")
    if url.startswith(("http://", "https://")):
        return url
    print(f"[*] Detecting protocol for {url}...")
    try:
        requests.get(f"https://{url}", headers=_random_headers(), timeout=5,
                     verify=False, proxies=proxies)
        return f"https://{url}"
    except requests.RequestException:
        return f"http://{url}"


def http_get_bytes(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    proxies: Optional[Dict] = None,
) -> Tuple[bool, bytes | str]:
    if url.startswith("local://"):
        path = url.replace("local://", "")
        if os.path.isfile(path):
            try:
                return True, open(path, "rb").read()
            except Exception as e:
                return False, str(e)
        return False, "404 Not Found"
    try:
        r = SESSION.get(url, timeout=timeout, stream=True, verify=False,
                        headers=_random_headers(), proxies=proxies)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, r.content
    except Exception as e:
        return False, str(e)


def http_get_to_file(
    url: str,
    outpath: str,
    timeout: int = DEFAULT_TIMEOUT,
    proxies: Optional[Dict] = None,
) -> Tuple[bool, str]:
    if url.startswith("local://"):
        path = url.replace("local://", "")
        if os.path.isfile(path):
            try:
                os.makedirs(os.path.dirname(outpath), exist_ok=True)
                shutil.copy2(path, outpath)
                return True, "ok"
            except Exception as e:
                return False, str(e)
        return False, "404 Not Found"
    try:
        print(f"[!] Downloading {url} ...")
        r = SESSION.get(url, timeout=timeout, stream=True, verify=False,
                        headers=_random_headers(), proxies=proxies)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        with open(outpath, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
        return True, "ok"
    except Exception as e:
        return False, str(e)


def http_head_status(
    url: str,
    timeout: int = 6,
    proxies: Optional[Dict] = None,
) -> Tuple[bool, Optional[int], str]:
    if url.startswith("local://"):
        path = url.replace("local://", "")
        return (True, 200, "OK") if os.path.exists(path) else (False, 404, "Not Found")
    try:
        r = SESSION.head(url, timeout=timeout, allow_redirects=True, verify=False,
                         headers=_random_headers(), proxies=proxies)
        code = getattr(r, "status_code", None)
        if code and 200 <= code < 300:
            return True, code, "OK"
        return False, code, f"HTTP {code}"
    except Exception as e:
        return False, None, str(e)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — URL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def normalize_site_base(base_url: Optional[str]) -> str:
    if not base_url:
        return ""
    s = base_url.rstrip("/")
    if s.endswith("/.git/index"): s = s[:-12]
    if s.endswith("/.git"):       return s[:-5]
    if s.endswith(".git"):        return s[:-4]
    return s


def make_blob_url(base_git_url: str, sha: str) -> str:
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"):
        base += "/.git"
    return f"{base}/objects/{sha[:2]}/{sha[2:]}"


def public_url(site_base: str, path: str) -> str:
    return site_base.rstrip("/") + "/" + path.lstrip("/")

join_remote_file = public_url


def safe_folder_name(url: str) -> str:
    """Generates a filesystem-safe folder name from a URL."""
    if url.startswith("local://"):
        name = os.path.basename(url.replace("local://", "").rstrip("/"))
        return f"local_{name}"
    from urllib.parse import urlparse
    parsed = urlparse(url)
    name = parsed.netloc or parsed.path
    name = name.replace(":", "_").replace("/", "_").replace("\\", "_")
    if name.startswith("www_"):
        name = name[4:]
    return name or "unknown_target"


def sanitize_folder_name(url: str) -> str:
    s = re.sub(r"^https?://", "", url)
    s = re.sub(r"/\.git/?$", "", s, flags=re.IGNORECASE).rstrip("/")
    s = re.sub(r"[^a-zA-Z0-9]", "_", s)
    s = re.sub(r"_+", "_", s)
    return s[:60]

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — GIT OBJECT PARSING
# ══════════════════════════════════════════════════════════════════════════════

def parse_git_object(raw_bytes: bytes) -> Tuple[bool, Tuple[str, bytes] | str]:
    try:
        decompressed = zlib.decompress(raw_bytes)
    except Exception as e:
        return False, f"zlib error: {e}"
    try:
        header_end = decompressed.index(b"\x00")
    except ValueError:
        return False, "invalid object: missing header null"
    header   = decompressed[:header_end].decode(errors="ignore")
    parts    = header.split(" ")
    obj_type = parts[0] if parts else "unknown"
    content  = decompressed[header_end + 1:]
    return True, (obj_type, content)


def parse_commit_content(content_bytes: bytes) -> Dict[str, Any]:
    try:
        text = content_bytes.decode(errors="replace")
    except Exception:
        text = content_bytes.decode("latin1", errors="replace")
    lines  = text.splitlines()
    result = {"tree": None, "parents": [], "author": None,
              "committer": None, "message": "", "date": ""}
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            i += 1
            break
        if line.startswith("tree "):
            result["tree"] = line.split()[1].strip()
        elif line.startswith("parent "):
            result["parents"].append(line.split()[1].strip())
        elif line.startswith("author "):
            raw = line[7:].strip()
            last_gt = raw.rfind(">")
            if last_gt != -1:
                result["author"] = raw[:last_gt + 1]
                ts_part = raw[last_gt + 1:].strip().split(" ")[0]
                if ts_part.isdigit():
                    result["date"] = datetime.fromtimestamp(int(ts_part)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                result["author"] = raw
        elif line.startswith("committer "):
            result["committer"] = line[10:].strip()
        i += 1
    result["message"] = "\n".join(lines[i:]).strip()
    return result


def parse_tree(content_bytes: bytes) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    i, b, L = 0, content_bytes, len(content_bytes)
    while i < L:
        j = b.find(b" ", i)
        if j == -1:
            break
        mode = b[i:j].decode(errors="ignore")
        k = b.find(b"\x00", j + 1)
        if k == -1:
            break
        name    = b[j + 1:k].decode(errors="ignore")
        sha_raw = b[k + 1:k + 21]
        if len(sha_raw) != 20:
            break
        entries.append({"mode": mode, "name": name, "sha": sha_raw.hex()})
        i = k + 21
    return entries


def fetch_object_raw(base_git_url: str, sha: str,
                     proxies: Optional[Dict] = None) -> Tuple[bool, bytes | str]:
    return http_get_bytes(make_blob_url(base_git_url, sha), proxies=proxies)


def collect_files_from_tree(
    base_git_url: str,
    tree_sha: str,
    proxies: Optional[Dict] = None,
    ignore_missing: bool = True,
) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    stack: List[Tuple[str, str]] = [("", tree_sha)]
    while stack:
        prefix, sha = stack.pop()
        ok_, raw = fetch_object_raw(base_git_url, sha, proxies=proxies)
        if not ok_:
            if ignore_missing:
                warn(f"Tree object {sha} not found.")
                continue
            raise RuntimeError(f"Tree object {sha} not found.")
        ok2, parsed = parse_git_object(raw)
        if not ok2:
            continue
        obj_type, content = parsed
        if obj_type != "tree":
            continue
        for e in parse_tree(content):
            path = (prefix + "/" + e["name"]).lstrip("/")
            if e["mode"].startswith("4") or e["mode"] == "40000":
                stack.append((path, e["sha"]))
            else:
                files.append({
                    "path":     path,
                    "sha":      e["sha"],
                    "mode":     e["mode"],
                    "blob_url": make_blob_url(base_git_url, e["sha"]),
                })
    return files


def calculate_git_sha1(content: bytes) -> str:
    """Computes the Git SHA-1 of a blob: 'blob <size>\x00<content>'"""
    s = hashlib.sha1()
    s.update(f"blob {len(content)}\0".encode("utf-8"))
    s.update(content)
    return s.hexdigest()


def compute_diff(
    base_url: str,
    sha_old: Optional[str],
    sha_new: Optional[str],
    proxies: Optional[Dict] = None,
) -> str:
    MAX_SIZE = 100 * 1024  # 100 KB

    def _get_lines(sha: Optional[str]) -> Optional[List[str]]:
        if not sha:
            return []
        ok_, raw = fetch_object_raw(base_url, sha, proxies)
        if not ok_:
            return None
        ok2, parsed = parse_git_object(raw)
        if not ok2:
            return None
        _, content = parsed
        if len(content) > MAX_SIZE:
            return ["<File too large to show diff>"]
        for enc in ("utf-8", "latin-1"):
            try:
                return content.decode(enc).splitlines()
            except UnicodeDecodeError:
                continue
        return None  # binary

    lines_old = _get_lines(sha_old)
    lines_new = _get_lines(sha_new)
    if lines_old is None or lines_new is None:
        return "    (Unrecoverable) Binary file, unknown encoding, or missing data."
    if "<File too large" in (lines_old or [""]) or "<File too large" in (lines_new or [""]):
        return "    File exceeds size limit for viewing (100 KB)."
    try:
        diff = difflib.unified_diff(
            lines_old, lines_new,
            fromfile=f"a/{sha_old[:7] if sha_old else 'null'}",
            tofile=f"b/{sha_new[:7] if sha_new else 'null'}",
            lineterm="",
        )
        diff_text = "\n".join(diff)
        if len(diff_text) > MAX_SIZE:
            return diff_text[:MAX_SIZE] + "\n... [Diff truncated]"
        return diff_text or "No visible textual changes."
    except Exception as e:
        return f"Error computing diff: {e}"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — .GIT/INDEX PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_git_index(index_path: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        with open(index_path, "rb") as f:
            header = f.read(12)
            if len(header) < 12:
                return []
            signature, version, num_entries = struct.unpack("!4sLL", header)
            if signature != b"DIRC":
                print(f"[!] Invalid signature: {signature}")
                return []
            print(f"[*] Index version: {version} | Entries: {num_entries}")
            previous_path = b""
            for _ in range(num_entries):
                entry_data = f.read(62)
                if len(entry_data) < 62:
                    break
                fields     = struct.unpack("!10L20sH", entry_data)
                file_size  = fields[9]
                sha1_hex   = fields[10].hex()
                flags      = fields[11]
                name_length = flags & 0xFFF
                path_name   = b""
                if version == 4:
                    strip_len, shift = 0, 0
                    while True:
                        byte_read = f.read(1)
                        if not byte_read:
                            break
                        b_val = byte_read[0]
                        strip_len |= (b_val & 0x7F) << shift
                        if (b_val & 0x80) == 0:
                            break
                        shift += 7
                    suffix = b""
                    while True:
                        char = f.read(1)
                        if char == b"\x00":
                            break
                        suffix += char
                    path_name     = previous_path[: len(previous_path) - strip_len] + suffix
                    previous_path = path_name
                else:
                    if name_length < 0xFFF:
                        path_name = f.read(name_length)
                        f.read(1)
                        entry_len = 62 + name_length + 1
                        f.read((8 - (entry_len % 8)) % 8)
                    else:
                        while True:
                            char = f.read(1)
                            if char == b"\x00":
                                break
                            path_name += char
                        entry_len = 62 + len(path_name) + 1
                        f.read((8 - (entry_len % 8)) % 8)
                try:
                    decoded = path_name.decode("utf-8", "replace")
                    if decoded:
                        entries.append({"path": decoded, "sha1": sha1_hex, "size": file_size})
                except Exception:
                    pass
    except Exception as e:
        print(f"[!] Index parser error: {e}")
        import traceback
        traceback.print_exc()
    return entries


def index_to_json(index_path: str, json_out_path: str) -> None:
    data = parse_git_index(index_path)
    os.makedirs(os.path.dirname(json_out_path), exist_ok=True)
    with open(json_out_path, "w", encoding="utf-8") as f:
        json.dump({"entries": data}, f, indent=2)
    print(f"[+] Index converted: {len(data)} files found.")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — .DS_STORE PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_ds_store(filepath: str) -> List[str]:
    found: set = set()
    if not HAS_DS_STORE_LIB:
        try:
            data = open(filepath, "rb").read()
            text = data.decode("utf-16-be", errors="ignore")
            for c in re.findall(r"[\w\-\.]+\.[a-z0-9]{2,4}", text):
                found.add(c)
        except Exception:
            pass
        return list(found)
    try:
        with DSStore.open(filepath, "r") as d:
            for record in d:
                if record.filename:
                    found.add(record.filename)
    except Exception as e:
        print(f"[!] Error reading .DS_Store: {e}")
    return list(found)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — JSON / DUMP HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_dump_entries(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"JSON input file not found: {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if isinstance(data, dict) and "entries" in data:
        return data["entries"]
    if isinstance(data, list):
        return data
    raise ValueError("Invalid JSON format.")


def _safe_load_json(path: str, default_val: Any) -> Any:
    if not os.path.exists(path):
        return default_val
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading {os.path.basename(path)}: {e}")
        return default_val

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — OBJECT RECONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

def ensure_git_repo(outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    if not os.path.exists(os.path.join(outdir, ".git")):
        subprocess.run(["git", "init"], cwd=outdir,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.makedirs(os.path.join(outdir, ".git", "objects"), exist_ok=True)


def recover_one_sha(
    base_git_url: str,
    sha: str,
    outdir: str,
    original_path: Optional[str] = None,
    proxies: Optional[Dict] = None,
) -> bool:
    tmpdir  = os.path.join(outdir, "__tmp")
    os.makedirs(tmpdir, exist_ok=True)
    tmpfile = os.path.join(tmpdir, sha)
    blob_url = make_blob_url(base_git_url, sha)
    info(f"Recovering SHA1: {sha}")
    ok_, data = http_get_to_file(blob_url, tmpfile, proxies=proxies)
    if not ok_:
        warn(f"Download failed: {data}")
        return False
    try:
        ensure_git_repo(outdir)
        dest_dir       = os.path.join(outdir, ".git", "objects", sha[:2])
        os.makedirs(dest_dir, exist_ok=True)
        final_git_path = os.path.join(dest_dir, sha[2:])
        shutil.move(tmpfile, final_git_path)
        with open(final_git_path, "rb") as f:
            raw_data = f.read()
        parse_ok, parsed = parse_git_object(raw_data)
        if parse_ok:
            obj_type, content = parsed
            if original_path and original_path != sha:
                clean_path   = original_path.lstrip("/").lstrip("\\")
                decoded_path = os.path.join(outdir, clean_path)
                os.makedirs(os.path.dirname(decoded_path), exist_ok=True)
                info(f" -> Restoring original structure: {clean_path}")
            else:
                filename     = f"decoded_{sha}" + (".txt" if obj_type == "blob" else "")
                decoded_path = os.path.join(outdir, filename)
                info(f" -> Unknown path. Saving to root: {filename}")
            with open(decoded_path, "wb") as f:
                f.write(content)
            success("Object recovered successfully.")
            return True
        warn(f"Failed to decode Git object: {parsed}")
        return False
    except Exception as e:
        warn(f"Failed to move/process object: {e}")
        return False


def reconstruct_all(
    input_json: str,
    base_git_url: str,
    outdir: str,
    workers: int = 10,
) -> None:
    entries = load_dump_entries(input_json)
    info(f"Detected entries: {len(entries)} — starting downloads (workers={workers})")
    mapping = {e["sha1"]: e.get("path", "") for e in entries if e.get("sha1")}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(recover_one_sha, base_git_url, sha, outdir, path)
                   for sha, path in mapping.items()]
        for _ in as_completed(futures):
            pass
    info("Running git fsck --lost-found ...")
    try:
        subprocess.run(["git", "fsck", "--lost-found"], cwd=outdir, check=False)
    except Exception:
        warn("git fsck failed (git may not be available).")
    success("Reconstruction complete.")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — INTELLIGENCE GATHERING
# ══════════════════════════════════════════════════════════════════════════════

def _parse_git_log_file(file_path: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not os.path.exists(file_path):
        return entries
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                parts = line.strip().split("\t")
                if len(parts) < 2:
                    continue
                meta   = parts[0].split(" ")
                action = parts[1]
                if len(meta) >= 4:
                    old_sha     = meta[0]
                    new_sha     = meta[1]
                    ts          = meta[-2]
                    author_raw  = " ".join(meta[2:-2])
                    try:
                        dt = datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        dt = ts
                    entries.append({
                        "sha": new_sha, "old_sha": old_sha,
                        "author": author_raw, "date": dt,
                        "message": action, "source": "reflog",
                    })
    except Exception as e:
        print(f"[!] Error parsing reflog: {e}")
    return entries[::-1]


def _parse_git_config_remote(file_path: str) -> Optional[str]:
    if not os.path.exists(file_path):
        return None
    try:
        content = open(file_path, "r", encoding="utf-8", errors="ignore").read()
        m = re.search(r"url\s*=\s*(.*)", content)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None


def gather_intelligence(
    base_git_url: str,
    outdir: str,
    proxies: Optional[Dict] = None,
) -> Dict[str, Any]:
    info("Collecting intelligence (Config, Logs, Refs, Info/Refs)...")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"):
        base += "/.git"
    meta_dir = os.path.join(outdir, "_files", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    intel: Dict[str, Any] = {"remote_url": None, "logs": [],
                              "packed_refs": [], "info_refs": []}

    for filename, key in [("/config", "config"), ("/logs/HEAD", "logs_HEAD"),
                          ("/packed-refs", "packed_refs_raw"), ("/info/refs", "info_refs_raw")]:
        ok_, data = http_get_bytes(base + filename, proxies=proxies)
        if not ok_:
            continue
        dst = os.path.join(meta_dir, filename.lstrip("/").replace("/", "_"))
        with open(dst, "wb") as f:
            f.write(data)
        if filename == "/config":
            intel["remote_url"] = _parse_git_config_remote(dst)
            if intel["remote_url"]:
                success(f"Remote origin detected: {intel['remote_url']}")
        elif filename == "/logs/HEAD":
            intel["logs"] = _parse_git_log_file(dst)
            success(f"History logs recovered: {len(intel['logs'])} entries.")
        elif filename == "/packed-refs":
            refs = []
            for line in data.decode(errors="ignore").splitlines():
                if not line.startswith("#") and " " in line:
                    sha, ref = line.split(" ", 1)
                    refs.append({"sha": sha, "ref": ref.strip()})
            intel["packed_refs"] = refs
        elif filename == "/info/refs":
            matches = re.findall(r"([0-9a-f]{40})\s+([^\s]+)",
                                 data.decode(errors="ignore"))
            intel["info_refs"] = [{"sha": s, "ref": r} for s, r in matches]
            if intel["info_refs"]:
                success(f"Info/Refs recovered: {len(intel['info_refs'])} references.")

    with open(os.path.join(outdir, "_files", "intelligence.json"),
              "w", encoding="utf-8") as f:
        json.dump(intel, f, indent=2, ensure_ascii=False)
    return intel

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — BLIND MODE / SHA DISCOVERY
# ══════════════════════════════════════════════════════════════════════════════

def find_candidate_shas(
    base_git_url: str,
    proxies: Optional[Dict] = None,
) -> List[Dict[str, str]]:
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"):
        base += "/.git"
    candidates: Dict[str, Dict[str, str]] = {}

    # info/refs
    ok_, data = http_get_bytes(base + "/info/refs", proxies=proxies)
    if ok_:
        for sha, ref in re.findall(r"([0-9a-f]{40})\s+([^\s]+)",
                                   data.decode(errors="ignore")):
            if sha not in candidates:
                candidates[sha] = {"sha": sha, "ref": ref, "source": base + "/info/refs"}

    # HEAD
    ok_, data = http_get_bytes(base + "/HEAD", proxies=proxies)
    if ok_:
        text = data.decode(errors="ignore").strip()
        if all(c in "0123456789abcdef" for c in text.lower()) and len(text) == 40:
            candidates.setdefault(text, {"sha": text, "ref": "HEAD", "source": base + "/HEAD"})
        elif text.startswith("ref:"):
            ref = text.split(":", 1)[1].strip()
            ok2, data2 = http_get_bytes(base + "/" + ref, proxies=proxies)
            if ok2:
                sha2 = data2.decode(errors="ignore").strip().splitlines()[0].strip()
                if len(sha2) == 40:
                    candidates.setdefault(sha2, {"sha": sha2, "ref": ref,
                                                  "source": base + "/" + ref})

    # packed-refs
    ok_, data = http_get_bytes(base + "/packed-refs", proxies=proxies)
    if ok_:
        for line in data.decode(errors="ignore").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2:
                sha, ref = parts[0].strip(), parts[1].strip()
                if len(sha) == 40:
                    candidates.setdefault(sha, {"sha": sha, "ref": ref,
                                                 "source": base + "/packed-refs"})

    # Common branches
    for ref in ["refs/heads/master", "refs/heads/main", "refs/heads/develop",
                "refs/heads/staging", "refs/remotes/origin/master"]:
        ok_, data = http_get_bytes(base + "/" + ref, proxies=proxies)
        if ok_:
            sha = data.decode(errors="ignore").strip().splitlines()[0].strip()
            if len(sha) == 40:
                candidates.setdefault(sha, {"sha": sha, "ref": ref,
                                             "source": base + "/" + ref})
    return list(candidates.values())


def blind_recovery(
    base_git_url: str,
    outdir: str,
    output_index_name: str,
    proxies: Optional[Dict] = None,
) -> bool:
    info("Starting BLIND MODE (reconstruction without index)...")
    gather_intelligence(base_git_url, outdir, proxies=proxies)
    candidates = find_candidate_shas(base_git_url, proxies=proxies)
    if not candidates:
        fail("Blind mode failed: no initial SHA found.")
        return False
    start_sha = candidates[0]["sha"]
    info(f"Starting point found: {start_sha} ({candidates[0]['ref']})")
    ok_, raw = fetch_object_raw(base_git_url, start_sha, proxies)
    if not ok_:
        fail("Failed to download initial commit")
        return False
    ok2, parsed = parse_git_object(raw)
    if not ok2 or parsed[0] != "commit":
        fail("Invalid initial object")
        return False
    commit_meta  = parse_commit_content(parsed[1])
    root_tree_sha = commit_meta.get("tree")
    if not root_tree_sha:
        fail("No associated tree")
        return False
    info(f"Root tree found: {root_tree_sha}. Crawling...")
    all_files = collect_files_from_tree(base_git_url, root_tree_sha,
                                        proxies=proxies, ignore_missing=True)
    synthetic = {"entries": [{"path": f["path"], "sha1": f["sha"]} for f in all_files]}
    out_path = os.path.join(outdir, "_files", output_index_name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(synthetic, f, indent=2)
    success(f"Blind mode complete! Synthetic index: {len(all_files)} files.")
    return True

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — STASH RECOVERY
# ══════════════════════════════════════════════════════════════════════════════

def recover_stash_content(
    base_git_url: str,
    outdir: str,
    workers: int = 10,
    proxies: Optional[Dict] = None,
    show_diff: bool = False,
) -> Optional[str]:
    stash_url = base_git_url.rstrip("/") + "/.git/refs/stash"
    ok_, data = http_get_bytes(stash_url, proxies=proxies)
    if not ok_:
        return None
    stash_sha = data.decode(errors="ignore").strip()
    if len(stash_sha) != 40:
        return None
    info(f"[!] STASH DETECTED: {stash_sha}")
    ok_obj, raw_obj = fetch_object_raw(base_git_url, stash_sha, proxies=proxies)
    meta: Dict[str, Any] = {}
    if ok_obj:
        _, parsed = parse_git_object(raw_obj)
        meta = parse_commit_content(parsed[1])
    tree_sha = meta.get("tree")
    if not tree_sha:
        return None
    stash_files = collect_files_from_tree(base_git_url, tree_sha,
                                          proxies=proxies, ignore_missing=True)
    if not stash_files:
        return None

    def _fetch_stash_item(f_entry: Dict) -> Dict:
        if show_diff:
            try:
                diff_content = compute_diff(base_git_url, None, f_entry["sha"], proxies)
            except Exception:
                diff_content = "[!] Error processing stash content."
        else:
            diff_content = "[--show-diff not used: content omitted]"
        return {"path": f_entry["path"], "sha1": f_entry["sha"],
                "type": "STASHED", "diff": diff_content}

    enriched: List[Dict] = []
    if show_diff:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for fut in as_completed([ex.submit(_fetch_stash_item, f) for f in stash_files]):
                enriched.append(fut.result())
    else:
        enriched = [_fetch_stash_item(f) for f in stash_files]

    stash_json_path = os.path.join(outdir, "_files", "stash.json")
    output = {
        "metadata": {
            "sha":     stash_sha,
            "author":  meta.get("author", "Unknown"),
            "date":    meta.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "message": meta.get("message", "Git Stash Recovery"),
        },
        "entries": enriched,
    }
    with open(stash_json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    return stash_sha


def generate_stash_html(stash_json_path: str, outdir: str) -> None:
    """Generate stash_report.html from stash.json."""
    try:
        with open(stash_json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        warn(f"Could not load stash.json: {e}")
        return

    meta    = data.get("metadata", {})
    entries = data.get("entries", [])
    entries_json = json.dumps(entries, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")

    out_html = os.path.join(outdir, "stash_report.html")
    html = _html_head("Stash Recovery") + _topbar("Stashes", outdir) + f"""
<div class="container">
  <div class="card mb-3" style="border-color:var(--accent);background:var(--accent-dim)">
    <div class="card-body flex items-center gap-2" style="justify-content:space-between">
      <div>
        <div style="font-size:1rem;font-weight:700;color:var(--accent)">&#x1F4BE; Git Stash Recovered</div>
        <div class="muted" style="font-size:.8rem">
          SHA: <span class="mono">{meta.get('sha','N/A')}</span> &nbsp;&bull;&nbsp;
          Author: {meta.get('author','Unknown')} &nbsp;&bull;&nbsp;
          Date: {meta.get('date','Unknown')}
        </div>
        <div class="mono mt-1" style="font-size:.82rem;color:var(--text)">{meta.get('message','')}</div>
      </div>
      <div class="text-right">
        <div class="stat-num" style="color:var(--accent)">{len(entries)}</div>
        <div class="stat-lbl">Stashed Files</div>
      </div>
    </div>
  </div>
  <div class="flex gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">\u2190 Back</a>
    <div class="search-wrap" style="flex:1;max-width:500px">
      <span class="search-icon">\u2315</span>
      <input id="q" type="text" placeholder="Filter by filename\u2026">
    </div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th style="width:60%">File Path</th>
        <th style="width:15%">Type</th>
        <th style="width:25%">SHA-1</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="flex items-center mt-2" style="justify-content:space-between;color:var(--text-muted);font-size:.82rem">
    <span id="info"></span><div class="pgn" id="pgn"></div>
  </div>
</div>
<script>
const DATA={entries_json};
let filtered=DATA.slice(),cur=1;const PS=50;
const tb=document.getElementById('tb');
const info=document.getElementById('info');
const pgn=document.getElementById('pgn');
function esc(t){{if(!t)return'';return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  tb.innerHTML='';
  sl.forEach(r=>{{
    const tr=document.createElement('tr');
    const tc={{'STASHED':'badge-amber','ADDED':'badge-green','MODIFIED':'badge-blue','DELETED':'badge-red'}}[r.type]||'badge-muted';
    tr.innerHTML=`<td class="mono" style="font-size:.8rem;word-break:break-all">${{esc(r.path)}}</td>
      <td><span class="badge ${{tc}}">${{esc(r.type||'STASHED')}}</span></td>
      <td class="mono" style="font-size:.78rem;color:var(--purple)">${{esc(r.sha1||'')}}</td>`;
    tb.appendChild(tr);
  }});
  info.textContent=`Showing ${{tot?((cur-1)*PS+1):0}}\u2013${{Math.min(cur*PS,tot)}} of ${{tot}}`;
  pgn.innerHTML='';
  const pb=document.createElement('button');pb.textContent='\u2039';pb.disabled=cur===1;pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');nb.textContent='\u203a';nb.disabled=cur===tp;nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}
document.getElementById('q').addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  filtered=t?DATA.filter(r=>(r.path||'').toLowerCase().includes(t)):DATA.slice();
  cur=1;render();
}});
render();
</script>
""" + _html_foot()
    try:
        with open(out_html, "w", encoding="utf-8") as fh:
            fh.write(html)
        success(f"Stash report saved: {out_html}")
    except Exception as e:
        warn(f"Error saving stash_report.html: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — HARDENING DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_hardening(
    base_git_url: str,
    outdir: str,
    proxies: Optional[Dict] = None,
) -> Dict[str, Any]:
    info("Detecting .git exposure and hardening configuration...")
    base = base_git_url.rstrip("/")
    candidates = {
        "HEAD":         [base + "/HEAD",         base + "/.git/HEAD"],
        "refs_heads":   [base + "/refs/heads/",  base + "/.git/refs/heads/"],
        "packed_refs":  [base + "/packed-refs",  base + "/.git/packed-refs"],
        "index":        [base + "/index",         base + "/.git/index"],
        "objects_root": [base + "/objects/",      base + "/.git/objects/"],
        "logs":         [base + "/logs/HEAD",     base + "/.git/logs/HEAD"],
        "config":       [base + "/config",        base + "/.git/config"],
        "stash":        [base + "/refs/stash",    base + "/.git/refs/stash"],
        "info_refs":    [base + "/info/refs",     base + "/.git/info/refs"],
    }
    report = {
        "base": base_git_url,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "results": {},
    }
    for name, urls in candidates.items():
        status: Dict[str, Any] = {"exposed": False, "positive_urls": []}
        for u in urls:
            try:
                ok_status, code, _ = http_head_status(u, proxies=proxies)
                if ok_status:
                    status["exposed"] = True
                    status["positive_urls"].append({"url": u, "status_code": code, "method": "HEAD"})
                else:
                    ok_get, _ = http_get_bytes(u, proxies=proxies)
                    if ok_get:
                        status["exposed"] = True
                        status["positive_urls"].append({"url": u, "status_code": 200, "method": "GET"})
            except Exception:
                pass
        report["results"][name] = status
    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    out_json = os.path.join(outdir, "_files", "hardening_report.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    success(f"Report saved: {out_json}")
    generate_hardening_html(report, os.path.join(outdir, "hardening_report.html"))
    return report

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — MISC / FULL-SCAN LEAKS
# ══════════════════════════════════════════════════════════════════════════════

def check_ds_store_exposure(
    base_url: str,
    output_dir: str,
    proxies: Optional[Dict] = None,
) -> None:
    base = base_url.rstrip("/") + "/"
    ds_url = base + ".DS_Store"
    local_path = os.path.join(output_dir, "_files", "DS_Store_dump")
    print(f"[*] Checking .DS_Store exposure at: {ds_url}")
    ok_, _ = http_get_to_file(ds_url, local_path, proxies=proxies)
    if ok_:
        print("[+] .DS_Store found! Extracting files...")
        files = parse_ds_store(local_path)
        if files:
            full_urls = [base + fname for fname in files]
            print(f"[+] {len(files)} entries discovered in .DS_Store:")
            for u in full_urls:
                print(f"    -> {u}")
            ds_json = os.path.join(output_dir, "_files", "ds_store_leaks.json")
            with open(ds_json, "w") as f:
                json.dump(full_urls, f, indent=2)
        else:
            print("[-] .DS_Store was empty or contained no readable filenames.")


def detect_misc_leaks(
    base_url: str,
    outdir: str,
    proxies: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    info("Starting root-level scan (Full Scan) for other leaks...")
    base = base_url.rstrip("/")
    if base.endswith("/.git"):
        base = base[:-5]
    misc_dir = os.path.join(outdir, "_files", "misc")
    os.makedirs(misc_dir, exist_ok=True)
    findings: List[Dict[str, Any]] = []

    for key, sig in MISC_SIGNATURES.items():
        target_url = base + sig["path"]
        ok_, data  = http_get_bytes(target_url, proxies=proxies)
        if not ok_:
            continue
        is_valid = False
        if "magic" in sig:
            is_valid = data.startswith(sig["magic"])
            if key == "ds_store" and data.startswith(b"\x00\x00\x00\x01Bud1"):
                is_valid = True
        elif "regex" in sig:
            is_valid = bool(re.search(sig["regex"], data, re.MULTILINE))
        elif "min_len" in sig:
            is_valid = len(data) >= sig["min_len"]

        if not is_valid:
            continue
        success(f"Confirmed leak: {sig['desc']}")
        filename_map = {
            "env": ".env", "svn": "wc.db", "ds_store": "DS_Store_dump",
            "exclude": "info_exclude.txt", "description": "description.txt",
            "commit_msg": "COMMIT_EDITMSG.txt",
        }
        filename = filename_map.get(key, "hook_script.sh" if "hook" in key else f"{key}_dump")
        dump_path = os.path.join(misc_dir, filename)
        with open(dump_path, "wb") as f:
            f.write(data)

        text_keys = ["env", "exclude", "description", "commit_msg", "hook_sample", "hook_active"]
        is_text   = key in text_keys
        content_display = ""
        if is_text:
            try:
                content_display = data.decode("utf-8", "ignore")
            except Exception:
                is_text = False
        elif key == "ds_store":
            try:
                extracted  = parse_ds_store(dump_path)
                full_urls  = [f"{base}/{f}" for f in extracted]
                is_text    = True
                content_display = ("=== URLS EXTRACTED FROM .DS_Store ===\n\n" + "\n".join(full_urls)
                                   if extracted else "=== VALID .DS_Store FILE ===\n\nNo visible records.")
            except Exception as e:
                content_display = f"Error: {e}"

        html_name = f"{key}_report.html"
        generate_misc_html(os.path.join(outdir, html_name), sig["desc"], content_display, is_text)
        findings.append({
            "type": key, "desc": sig["desc"],
            "url": target_url, "report_file": html_name, "dump_file": filename,
        })

    with open(os.path.join(outdir, "_files", "misc_leaks.json"), "w") as f:
        json.dump(findings, f, indent=2)
    return findings

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — BRUTE FORCE
# ══════════════════════════════════════════════════════════════════════════════

def brute_force_scan(
    base_git_url: str,
    outdir: str,
    wordlist_path: Optional[str] = None,
    proxies: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    target_list  = COMMON_FILES
    source_type  = "Default List"

    if wordlist_path:
        if os.path.exists(wordlist_path):
            info(f"Loading custom wordlist: {wordlist_path}")
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    custom = [
                        l.replace("\ufeff", "").replace("\x00", "").strip()
                        for l in f
                        if l.strip() and not l.startswith("#")
                    ]
                if custom:
                    target_list = custom
                    source_type = "Custom"
                    success(f"Wordlist loaded: {len(target_list)} valid entries.")
                else:
                    warn("Provided wordlist appears empty. Reverting to default.")
            except Exception as e:
                warn(f"Error reading wordlist: {e}. Reverting to default.")
        else:
            warn(f"Wordlist not found: {wordlist_path}. Reverting to default.")

    info(f"Starting Brute-Force... Source: {source_type} ({len(target_list)} items)")
    site_root = base_git_url.rstrip("/")
    if site_root.endswith("/.git"):
        site_root = site_root[:-5]

    # ── Baseline fingerprint: fetch a guaranteed-absent URL to detect
    #    "catch-all" / custom 404 pages and home-page fallback responses.
    _baseline_hashes: set = set()
    _baseline_sizes:  set = set()
    _baseline_snippets: List[bytes] = []
    for _probe in [
        f"{site_root}/__probe_nonexistent_8x7z__.html",
        f"{site_root}/__probe2_4q9w__.txt",
    ]:
        _ok, _data = http_get_bytes(_probe, proxies=proxies)
        if _ok and _data:
            _baseline_hashes.add(hashlib.md5(_data).hexdigest())
            _baseline_sizes.add(len(_data))
            _baseline_snippets.append(_data[:512])
    info(f"Baseline fingerprint: {len(_baseline_hashes)} patterns collected.")

    def _is_false_positive(data: bytes) -> bool:
        """Return True if *data* looks like a 404/homepage false positive."""
        if not data:
            return True
        # Exact hash match against known-404 responses
        if hashlib.md5(data).hexdigest() in _baseline_hashes:
            return True
        # Same size as a baseline — very likely the same page
        if len(data) in _baseline_sizes and len(data) > 200:
            return True
        # Short HTML with error keywords → generic 404 page
        snip = data[:1024].lower()
        if b"<html" in snip:
            # Likely a hard 404 if it contains 404 text and is small
            if (b"404" in snip or b"not found" in snip or b"page not found" in snip) and len(data) < 8192:
                return True
            # Compare content similarity against baseline snippets (>85% similar = same page)
            for bl in _baseline_snippets:
                ratio = difflib.SequenceMatcher(None, data[:512], bl).ratio()
                if ratio > 0.85:
                    return True
        return False

    bf_dir   = os.path.join(outdir, "_files", "bruteforce")
    trav_dir = os.path.join(bf_dir, "traversal")
    os.makedirs(bf_dir, exist_ok=True)
    os.makedirs(trav_dir, exist_ok=True)
    found_files: List[Dict[str, Any]] = []

    for raw_path in target_list:
        url_path     = raw_path.replace("\\", "/")
        is_traversal = ".." in url_path

        if is_traversal:
            target_url     = f"{site_root}/{url_path}"
            safe_name      = url_path.replace("..", "UP").replace("/", "_").replace("\\", "_")
            local_full_path = os.path.join(trav_dir, f"TRAV_{safe_name}")
        else:
            url_path_clean  = url_path.lstrip("/")
            target_url      = f"{site_root}/{url_path_clean}"
            relative_path   = os.path.normpath(url_path_clean)
            local_full_path = os.path.join(bf_dir, relative_path)
            try:
                os.makedirs(os.path.dirname(local_full_path), exist_ok=True)
            except Exception as e:
                warn(f"Error creating local directory for {url_path}: {e}")
                continue

        ok_http, data = http_get_bytes(target_url, proxies=proxies)
        if not (ok_http and data):
            continue
        if _is_false_positive(data):
            continue

        try:
            with open(local_full_path, "wb") as f:
                f.write(data)
            if url_path.endswith(".DS_Store") or "/.DS_Store" in target_url:
                info("[+] .DS_Store detected in Brute-Force! Starting deep analysis...")
                parent_folder_url = target_url.rsplit(".DS_Store", 1)[0]
                check_ds_store_exposure(parent_folder_url, outdir, proxies=proxies)
            git_sha    = calculate_git_sha1(data)
            obj_url    = make_blob_url(base_git_url, git_sha)
            git_exists, _, _ = http_head_status(obj_url, proxies=proxies)
            log_prefix = "Traversal" if is_traversal else "Brute-Force"
            status_msg = f"(SHA: {git_sha[:8]} - Versioned)" if git_exists else "(Local Only)"
            if git_exists:
                success(f"{log_prefix}: {url_path} found! {status_msg}")
            else:
                warn(f"{log_prefix}: {url_path} found on site {status_msg}")
            found_files.append({
                "filename":   url_path,
                "local_path": local_full_path,
                "url":        target_url,
                "git_sha":    git_sha,
                "in_git":     git_exists,
                "type":       "traversal" if is_traversal else "DEFAULT LIST",
            })
        except Exception as e:
            warn(f"Error processing '{url_path}': {e}")
            continue

    try:
        with open(os.path.join(outdir, "_files", "bruteforce.json"), "w", encoding="utf-8") as f:
            json.dump(found_files, f, indent=2)
    except Exception as e:
        warn(f"Error saving JSON: {e}")
    return found_files

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 16 — SECRETS SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: str, charset: str) -> float:
    """Compute Shannon entropy of *data* over the given *charset* alphabet."""
    if not data:
        return 0.0
    freq = {c: 0 for c in charset}
    for ch in data:
        if ch in freq:
            freq[ch] += 1
    length = sum(freq.values())
    if length == 0:
        return 0.0
    import math
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values() if count
    )

# Minimum Shannon entropy thresholds for high-entropy secret detection
# (base64 alphabet and hex alphabet evaluated separately)
_BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEX_CHARS    = "0123456789abcdefABCDEF"
_MIN_ENTROPY_B64 = 4.5   # bits — genuine 32-char b64 secrets score ~5.8
_MIN_ENTROPY_HEX = 3.5   # bits — random hex scores ~4.0


def scan_for_secrets(outdir: str) -> None:
    info("Starting Secrets Scanner (Regex + calibrated entropy)...")

    # ── Files generated by this script — never scan ───────────────────────
    GENERATED_NAMES = {
        "report.html", "listing.html", "users.html", "secrets.html",
        "infrastructure_report.html", "hardening_report.html",
        "bruteforce_report.html", "history.html", "index.html",
        "stash_report.html", "sast_report.html",
        "packfiles.json", "misc_leaks.json", "hardening_report.json",
        "history.json", "users.json", "dump.json", "stash.json",
        "secrets.json", "intelligence.json", "infrastructure.json",
        "bruteforce.json", "sast.json",
    }
    IGNORED_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf",
        ".zip", ".gz", ".tar", ".exe", ".pack", ".idx",
        ".css", ".svg", ".woff", ".woff2", ".eot", ".ttf",
        ".mp4", ".mp3", ".lock", ".pyc", ".class",
    }

    findings: List[Dict[str, Any]] = []
    scanned_count = 0

    for root, dirs, files in os.walk(outdir):
        # Skip metadata folder except for reconstructed source sub-dirs
        dirs[:] = [d for d in dirs if d != "__tmp"]

        for filename in files:
            if filename in GENERATED_NAMES:
                continue
            ext_lower = os.path.splitext(filename)[1].lower()
            if ext_lower in IGNORED_EXTS:
                continue
            if filename.endswith((".min.js", ".min.css")):
                continue

            filepath = os.path.join(root, filename)
            try:
                if os.path.getsize(filepath) > 5 * 1024 * 1024:
                    continue
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            scanned_count += 1
            rel = os.path.relpath(filepath, outdir)

            for name, pattern in SECRET_PATTERNS.items():
                try:
                    for match in re.finditer(pattern, content, re.MULTILINE):
                        secret_val = match.group(0)

                        # ── Per-pattern post-match validation ──────────────
                        # Extract the "value" portion for entropy/quality checks.
                        # For patterns with a capture group, use group(1); otherwise
                        # use the full match.
                        try:
                            val_to_check = match.group(1) or secret_val
                        except IndexError:
                            val_to_check = secret_val

                        # --- Generic API Key ---
                        if "Generic" in name:
                            # group(1) is the value inside the quotes
                            try:
                                inner = match.group(1)
                            except IndexError:
                                inner = val_to_check
                            if not inner or " " in inner or "<" in inner or len(inner) < 24:
                                continue
                            # Must pass entropy threshold on base64 or hex alphabet
                            if (_shannon_entropy(inner, _BASE64_CHARS) < _MIN_ENTROPY_B64
                                    and _shannon_entropy(inner, _HEX_CHARS) < _MIN_ENTROPY_HEX):
                                continue
                            secret_val = match.group(0)

                        # --- AWS Key: must not be surrounded by word chars ---
                        elif name == "AWS Access Key ID":
                            # Already gated by lookbehind/lookahead in regex
                            pass

                        # --- Slack: require at least two segments (already in pattern) ---
                        elif name == "Slack Token":
                            if secret_val.count("-") < 1:
                                continue

                        # --- Telegram: guard against matching version strings ---
                        elif name == "Telegram Bot Token":
                            # Reject if the number part is a common version number (< 9 digits)
                            parts = secret_val.split(":")
                            if not parts[0].isdigit() or len(parts[0]) < 9:
                                continue
                            # Reject if token looks like a URL fragment
                            if any(kw in content[max(0,match.start()-20):match.start()].lower()
                                   for kw in ("http", "url", "href", "src")):
                                continue

                        # --- DB connection string: value part must not be a placeholder ---
                        elif name == "DB Connection String":
                            full = match.group(0)
                            placeholders = ("password", "passwd", "secret", "xxx",
                                            "your_", "<", ">", "{", "}", "example")
                            if any(p in full.lower() for p in placeholders):
                                continue

                        # --- GitHub / GitLab / DO / NPM / Stripe / Heroku ---
                        # These have highly specific prefixes — no extra check needed.

                        start   = max(0, match.start() - 50)
                        end     = min(len(content), match.end() + 50)
                        context = content[start:end].replace("\n", " ").strip()
                        findings.append({
                            "type":    name,
                            "file":    rel,
                            "match":   secret_val,
                            "context": context,
                        })
                        print(f"[!] SECRET: {name} in {filename}")
                except re.error:
                    pass

    info(f"Scan complete. {scanned_count} files analyzed.")
    if findings:
        success(f"TOTAL SECRETS FOUND: {len(findings)}")
    else:
        info("No high-confidence secrets found.")

    # Always write secrets.json and secrets.html so the pages are reachable
    # via the nav bar even when no secrets were detected.
    report_path = os.path.join(outdir, "_files", "secrets.json")
    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass
    generate_secrets_html(findings, os.path.join(outdir, "secrets.html"))

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 17 — INFRASTRUCTURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def extract_infrastructure(outdir: str, args: Any) -> List[Dict[str, Any]]:
    info("Running Infrastructure Extraction...")
    findings: List[Dict[str, Any]] = []

    # ── Files generated by this script — never scan these ─────────────────
    GENERATED_NAMES = {
        # HTML reports
        "report.html", "listing.html", "users.html", "secrets.html",
        "infrastructure_report.html", "hardening_report.html",
        "bruteforce_report.html", "history.html", "index.html",
        "sast_report.html",
        # JSON data files
        "hardening_report.json", "misc_leaks.json", "packfiles.json",
        "bruteforce.json", "users.json", "secrets.json",
        "infrastructure.json", "dump.json", "intelligence.json",
        "history.json", "stash.json", "sast.json",
    }

    # ── Extensions that are primarily noise, not source code ──────────────
    SKIP_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
        ".woff", ".woff2", ".eot", ".ttf", ".otf",
        ".zip", ".gz", ".tar", ".pack", ".idx",
        ".mp4", ".mp3", ".avi", ".webm",
        ".pyc", ".class", ".o", ".so", ".dll", ".exe",
        ".min.css",
    }

    # ── Source / config extensions worth scanning ─────────────────────────
    SOURCE_EXTS = {
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".env",
        ".php", ".py", ".rb", ".go", ".java", ".cs", ".cpp", ".c",
        ".sh", ".bash", ".zsh", ".ps1",
        ".html",  # app source HTML is fine; we skip *generated* ones by name
        ".vue", ".svelte",
        ".conf", ".cfg", ".config",
        ".xml",
    }

    # CDN / known noise hosts to suppress from EXTERNAL_HOST results
    NOISE_HOSTS = {
        "fonts.googleapis.com", "fonts.gstatic.com",
        "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
        "unpkg.com", "ajax.googleapis.com",
        "www.google-analytics.com", "www.googletagmanager.com",
        "connect.facebook.net", "platform.twitter.com",
        "schemas.xmlsoap.org", "www.w3.org",
    }

    # Deduplicate (category, value, file) triples
    seen: set = set()

    for root, dirs, files in os.walk(outdir):
        # Skip the metadata sub-folder entirely
        dirs[:] = [d for d in dirs if d not in ("__tmp",)]

        for filename in files:
            # Skip this script's own generated outputs
            if filename in GENERATED_NAMES:
                continue

            ext = os.path.splitext(filename)[1].lower()
            # Skip binary/media/noise extensions
            if ext in SKIP_EXTS or filename.endswith(".min.js"):
                continue
            # Only scan source/config files
            if ext and ext not in SOURCE_EXTS:
                continue

            filepath = os.path.join(root, filename)
            try:
                if os.path.getsize(filepath) > 2 * 1024 * 1024:
                    continue
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            for name, pat in INFRA_PATTERNS.items():
                try:
                    for m in re.finditer(pat, content, re.IGNORECASE | re.MULTILINE):
                        # Determine the captured value
                        try:
                            val = m.group(1)
                        except IndexError:
                            val = m.group(0)
                        if not val:
                            continue
                        val = val.strip().strip("'\"` ")

                        # Suppress loopback / unspecified
                        if val in ("127.0.0.1", "0.0.0.0", "localhost"):
                            continue
                        # Suppress CDN/font noise for EXTERNAL_HOST
                        if name == "EXTERNAL_HOST" and val.lower() in NOISE_HOSTS:
                            continue
                        # Skip image/font URLs
                        if any(val.lower().endswith(x) for x in (
                            ".png", ".jpg", ".gif", ".svg", ".ico",
                            ".woff", ".woff2", ".eot", ".ttf",
                        )):
                            continue

                        rel = os.path.relpath(filepath, outdir)
                        key = (name, val, rel)
                        if key in seen:
                            continue
                        seen.add(key)

                        start = max(0, m.start() - 60)
                        end   = min(len(content), m.end() + 60)
                        snippet = content[start:end].strip()
                        findings.append({
                            "category": name,
                            "value":    val,
                            "file":     rel,
                            "context":  base64.b64encode(
                                snippet.encode("utf-8", errors="replace")
                            ).decode(),
                        })
                except re.error:
                    pass

    infra_json_path = os.path.join(outdir, "_files", "infrastructure.json")
    os.makedirs(os.path.dirname(infra_json_path), exist_ok=True)
    with open(infra_json_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False)
    generate_infrastructure_html(findings, os.path.join(outdir, "infrastructure_report.html"))
    info(f"Infrastructure extraction complete: {len(findings)} unique findings.")
    return findings

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 18 — PACKFILE HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def handle_packfiles(
    mode: str,
    base_git_url: str,
    outdir: str,
    proxies: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    info(f"Starting packfile handling in mode: {mode}")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"):
        base += "/.git"
    ok_, data   = http_get_bytes(base + "/objects/info/packs", proxies=proxies)
    found_packs = []
    if ok_:
        try:
            found_packs = list(set(
                p for p in data.decode(errors="ignore").split() if p.endswith(".pack")
            ))
        except Exception:
            pass
    results: List[Dict[str, Any]] = []
    extended_map: Dict[str, str] = {}
    pack_dir = os.path.join(outdir, ".git", "objects", "pack")

    for pname in found_packs:
        url_pack = f"{base}/objects/pack/{pname}"
        local_p  = os.path.join(pack_dir, pname)
        local_idx = local_p.replace(".pack", ".idx")
        status = "Listed"
        count  = 0
        if mode in ("download", "download-unpack"):
            ensure_git_repo(outdir)
            os.makedirs(pack_dir, exist_ok=True)
            ok_p, err = http_get_to_file(url_pack, local_p, proxies=proxies)
            if not ok_p:
                fail(f"[!] DOWNLOAD ERROR: {pname} -> {err}")
                status = "Download Failed"
                continue
            http_get_to_file(url_pack.replace(".pack", ".idx"), local_idx, proxies=proxies)
            status = "Downloaded"
            if mode == "download-unpack":
                with open(local_p, "rb") as f_in:
                    subprocess.run(["git", "unpack-objects"], cwd=outdir,
                                   stdin=f_in, capture_output=True)
                try:
                    v_proc = subprocess.run(["git", "verify-pack", "-v", local_idx],
                                            capture_output=True, text=True)
                    trees = re.findall(r"([0-9a-f]{40}) tree", v_proc.stdout)
                    for t_sha in trees:
                        ls = subprocess.run(["git", "ls-tree", "-r", t_sha],
                                            cwd=outdir, capture_output=True, text=True)
                        for line in ls.stdout.splitlines():
                            p = line.split(None, 3)
                            if len(p) >= 4:
                                extended_map[p[2]] = p[3]
                except Exception:
                    pass
                extract_root = os.path.join(
                    outdir, "_files", "extracted_packs", pname.replace(".pack", "")
                )
                blobs = re.findall(r"([0-9a-f]{40}) blob", v_proc.stdout)
                for s in blobs:
                    c_proc = subprocess.run(["git", "cat-file", "-p", s],
                                            cwd=outdir, capture_output=True)
                    if c_proc.returncode == 0:
                        try:
                            if s in extended_map:
                                fpath = os.path.join(extract_root, "named_restore", extended_map[s])
                            else:
                                fpath = os.path.join(extract_root, "no_name_restore",
                                                     f"recovered_{s[:8]}")
                            os.makedirs(os.path.dirname(fpath), exist_ok=True)
                            with open(fpath, "wb") as bf:
                                bf.write(c_proc.stdout)
                            count += 1
                        except OSError as e:
                            warn(f"SKIPPED: Write error for {s[:8]} ({e})")
                        except Exception as e:
                            warn(f"SKIPPED: Unexpected error restoring {s[:8]}: {e}")
                if count > 0:
                    success(f"Pack {pname}: {count} files physically restored.")
                    status = "Extracted and Restored"
                else:
                    fail(f"[!] ALERT: Pack {pname} processed but no files extracted.")
                    status = "Extraction Failed"

        pname_clean = pname.replace(".pack", "")
        if "unpack" in mode and count > 0:
            rel_folder = f"_files/extracted_packs/{pname_clean}"
        else:
            rel_folder = ".git/objects/pack"

        results.append({
            "name":             pname,
            "url_pack":         url_pack,
            "status":           status,
            "count":            count,
            "mode":             mode,
            "local_folder_rel": rel_folder,
            "local_url":        f"file://{os.path.abspath(local_p)}" if os.path.exists(local_p) else None,
        })

    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    with open(os.path.join(outdir, "_files", "packfiles.json"), "w") as f:
        json.dump(results, f, indent=2)
    return results

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 19 — HISTORY RECONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

def reconstruct_history(
    input_json: str,
    base_git_url: str,
    outdir: str,
    max_commits: int = 200,
    ignore_missing: bool = True,
    strict: bool = False,
    full_history: bool = False,
    show_diff: bool = False,
    workers: int = 50,
    proxies: Optional[Dict] = None,
) -> int:
    info(f"Reconstructing history. Max: {max_commits} | Full: {full_history} | Diffs: {show_diff}")
    os.makedirs(outdir, exist_ok=True)
    site_base = normalize_site_base(base_git_url)
    tree_cache: Dict[str, Dict[str, str]] = {}

    intel_path = os.path.join(outdir, "_files", "intelligence.json")
    intel_logs: List[Dict] = []
    remote_url_found = ""
    if os.path.exists(intel_path):
        try:
            with open(intel_path, "r", encoding="utf-8") as f:
                data_intel = json.load(f)
            intel_logs       = data_intel.get("logs", [])
            remote_url_found = data_intel.get("remote_url", "")
            info(f"Logs loaded: {len(intel_logs)} commits available.")
        except Exception:
            pass

    def _get_tree_files(tree_sha: Optional[str]) -> Dict[str, str]:
        if not tree_sha:
            return {}
        if tree_sha in tree_cache:
            return tree_cache[tree_sha]
        try:
            files = collect_files_from_tree(base_git_url, tree_sha,
                                            proxies=proxies, ignore_missing=True)
            f_map = {f["path"]: f["sha"] for f in files}
            tree_cache[tree_sha] = f_map
            return f_map
        except Exception:
            return {}

    def _process_log_entry(log_entry: Dict, index: int) -> Optional[Dict]:
        try:
            sha = log_entry.get("sha")
            if not sha:
                return None
            commit_data: Dict[str, Any] = {
                "sha":               sha,
                "ok":                True,
                "author":            log_entry.get("author"),
                "date":              log_entry.get("date"),
                "message":           log_entry.get("message"),
                "source":            "log",
                "parents":           ([log_entry["old_sha"]]
                                      if log_entry.get("old_sha") and
                                      log_entry["old_sha"] != "0" * 40 else []),
                "files":             [],
                "changes":           [],
                "file_count":        0,
                "fast_mode_skipped": False,
            }
            heavy = full_history or index < 20
            if not heavy:
                commit_data["fast_mode_skipped"] = True
                return commit_data

            ok_, raw = fetch_object_raw(base_git_url, sha, proxies=proxies)
            if ok_:
                is_valid, parsed_data = parse_git_object(raw)
                if is_valid and parsed_data[0] == "commit":
                    meta = parse_commit_content(parsed_data[1])
                    commit_data["tree"] = meta.get("tree")
                    if meta.get("date"):
                        commit_data["date"] = meta["date"]
                    if meta.get("tree"):
                        current_map = _get_tree_files(meta["tree"])
                        parent_map: Dict[str, str] = {}
                        parents = meta.get("parents", []) or (
                            [log_entry["old_sha"]]
                            if log_entry.get("old_sha") != "0" * 40 else []
                        )
                        if parents:
                            p_ok, p_raw = fetch_object_raw(base_git_url, parents[0], proxies)
                            if p_ok:
                                p_valid, p_parsed = parse_git_object(p_raw)
                                if p_valid:
                                    p_meta   = parse_commit_content(p_parsed[1])
                                    parent_map = _get_tree_files(p_meta.get("tree"))
                        commit_data["files"]      = [{"path": p, "sha": s} for p, s in current_map.items()]
                        commit_data["file_count"] = len(commit_data["files"])
                        for path, sha_now in current_map.items():
                            sha_old = parent_map.get(path)
                            diff_text = None
                            if not sha_old:
                                change_type = "ADDED"
                                if show_diff:
                                    diff_text = compute_diff(base_git_url, None, sha_now, proxies)
                            elif sha_old != sha_now:
                                change_type = "MODIFIED"
                                if show_diff:
                                    diff_text = compute_diff(base_git_url, sha_old, sha_now, proxies)
                            else:
                                continue
                            commit_data["changes"].append({
                                "path": path, "type": change_type, "diff": diff_text
                            })
                        for path in parent_map:
                            if path not in current_map:
                                commit_data["changes"].append({
                                    "path": path, "type": "DELETED", "diff": None
                                })
            return commit_data
        except Exception:
            return None

    all_commits: List[Dict] = []
    processed_shas: set = set()

    if intel_logs:
        limit = min(len(intel_logs), max_commits)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_process_log_entry, e, i)
                       for i, e in enumerate(intel_logs[:limit])]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    all_commits.append(res)
                    processed_shas.add(res["sha"])

    def _parse_dt(c: Dict) -> datetime:
        try:
            return datetime.strptime(c.get("date", ""), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.min

    all_commits.sort(key=_parse_dt, reverse=True)

    # Inject orphaned reflog entries
    if intel_logs:
        orphan_count = 0
        info("Analyzing reflog for suppressed evidence...")
        for entry in intel_logs:
            sha = entry.get("sha")
            if sha and sha not in processed_shas:
                try:
                    orphan_data = _process_log_entry(entry, 0)
                    if orphan_data and orphan_data.get("ok"):
                        orphan_data["is_orphan"] = True
                        orphan_data["message"]   = f"🕵️ REFLOG: {orphan_data['message']}"
                        all_commits.append(orphan_data)
                        processed_shas.add(sha)
                        orphan_count += 1
                except Exception:
                    pass
        if orphan_count > 0:
            success(f"Recovered {orphan_count} orphaned/suppressed commits.")
            all_commits.sort(key=_parse_dt, reverse=True)

    # Inject stash at top
    stash_json_path = os.path.join(outdir, "_files", "stash.json")
    if os.path.exists(stash_json_path):
        try:
            with open(stash_json_path, "r", encoding="utf-8") as f:
                s_data = json.load(f)
            s_meta    = s_data.get("metadata", {})
            s_entries = s_data.get("entries", [])
            if s_entries:
                real_msg = s_meta.get("message", "").strip()
                display_msg = real_msg or "Work In Progress (No stash description)"
                stash_commit = {
                    "sha":               s_meta.get("sha", "STASH_REF"),
                    "ok":                True,
                    "is_stash":          True,
                    "author":            s_meta.get("author", "Git Stash"),
                    "date":              s_meta.get("date", ""),
                    "message":           f"STASH: {display_msg}",
                    "changes":           s_entries,
                    "source":            "stash",
                    "fast_mode_skipped": False,
                }
                all_commits.insert(0, stash_commit)
                info("Stash successfully injected at the top of the timeline.")
        except Exception as e:
            warn(f"Error injecting stash into history: {e}")

    # Authors / OSINT
    author_stats: Dict[str, int] = {}
    for c in all_commits:
        auth = c.get("author")
        if auth:
            auth = auth.strip()
            author_stats[auth] = author_stats.get(auth, 0) + 1
    generate_users_report(outdir, author_stats)

    # Persist history.json and generate HTML
    hist_json = os.path.join(outdir, "_files", "history.json")
    try:
        head_sha = all_commits[0]["sha"] if all_commits else "N/A"
        with open(hist_json, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "base":       base_git_url,
                    "site_base":  site_base,
                    "head":       head_sha,
                    "remote_url": remote_url_found,
                    "commits":    all_commits,
                },
                f, indent=2, ensure_ascii=False, default=str
            )
        generate_history_html(hist_json, os.path.join(outdir, "history.html"),
                              site_base, base_git_url)
        success(f"History timeline generated with {len(all_commits)} entries.")
    except Exception as e:
        fail(f"Error persisting history.json: {e}")

    return len(all_commits)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 20 — URL / MULTI-TARGET SCAN
# ══════════════════════════════════════════════════════════════════════════════

def scan_urls(file_path: str) -> None:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    except Exception as e:
        fail(f"Error reading file: {e}")
        return
    info(f"Scanning {len(urls)} targets...")
    for u in urls:
        base = u.rstrip("/")
        if not base.endswith(".git"):
            base += "/.git"
        test = base + "/HEAD"
        try:
            ok_, data = http_get_bytes(test, timeout=5)
            if ok_ and b"ref:" in data.lower():
                print(f"[!] VULNERABLE: {u}")
            else:
                print(f"[.] Secure/Inaccessible: {u}")
        except Exception:
            print(f"[X] Error: {u}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 21 — HTTP SERVER
# ══════════════════════════════════════════════════════════════════════════════

def serve_dir(directory: str, port: int = 8000, open_file: str = "index.html") -> None:
    import socketserver
    import webbrowser

    os.chdir(directory)

    class SmartHandler(SimpleHTTPRequestHandler):
        def send_head(self):
            if self.path in ("/", "/index.html"):
                self.index_pages = ["index.html"]
            else:
                self.index_pages = []
            return super().send_head()

        def log_message(self, fmt, *args):
            pass  # suppress access logs

    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", port), SmartHandler) as httpd:
            url = f"http://localhost:{port}/{open_file}"
            success(f"Server running at: http://localhost:{port}")
            info("Press Ctrl+C to stop.")
            webbrowser.open(url)
            httpd.serve_forever()
    except Exception as e:
        fail(f"Error starting server: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 22 — SHARED HTML DESIGN SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

# This CSS block is injected into every generated HTML page.
# It implements the unified "Git Leak Explorer" dark theme with
# a consistent design language: terminal-noir aesthetic, amber accents.

_CSS_VARS = """
:root {
  --bg:         #0c0e14;
  --bg-card:    #12151f;
  --bg-hover:   #1a1e2d;
  --bg-inset:   #090b10;
  --border:     #1e2535;
  --border-hl:  #2e3a50;
  --text:       #c9d1e0;
  --text-muted: #5a6a88;
  --text-dim:   #7a8aaa;
  --accent:     #e8a020;
  --accent-dim: rgba(232,160,32,0.12);
  --green:      #22c55e;
  --green-dim:  rgba(34,197,94,0.12);
  --red:        #ef4444;
  --red-dim:    rgba(239,68,68,0.12);
  --blue:       #3b82f6;
  --blue-dim:   rgba(59,130,246,0.12);
  --purple:     #a78bfa;
  --purple-dim: rgba(167,139,250,0.12);
  --mono:       'Berkeley Mono','JetBrains Mono','Fira Code',monospace;
  --sans:       'Geist','Syne','DM Sans',sans-serif;
  --radius:     6px;
  --shadow:     0 4px 24px rgba(0,0,0,0.6);
}
[data-theme="light"] {
  --bg:         #f8f9fc;
  --bg-card:    #ffffff;
  --bg-hover:   #f1f3f8;
  --bg-inset:   #e8eaf0;
  --border:     #d1d9e6;
  --border-hl:  #b8c4d8;
  --text:       #1a2035;
  --text-muted: #7a8aaa;
  --text-dim:   #5a6a88;
  --accent:     #c47a00;
  --accent-dim: rgba(196,122,0,0.10);
  --green:      #16a34a;
  --green-dim:  rgba(22,163,74,0.10);
  --red:        #dc2626;
  --red-dim:    rgba(220,38,38,0.10);
  --blue:       #2563eb;
  --blue-dim:   rgba(37,99,235,0.10);
  --purple:     #7c3aed;
  --purple-dim: rgba(124,58,237,0.10);
  --shadow:     0 4px 24px rgba(0,0,0,0.12);
}
"""

_CSS_BASE = """
*{margin:0;padding:0;box-sizing:border-box}
html{font-size:15px}
body{
  background:var(--bg);color:var(--text);
  font-family:var(--sans);min-height:100vh;
  line-height:1.6;
  transition:background .2s,color .2s;
}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.mono{font-family:var(--mono);font-size:.82rem;letter-spacing:.02em}
.muted{color:var(--text-muted)}
.dim{color:var(--text-dim)}
code{font-family:var(--mono);font-size:.82rem;background:var(--bg-inset);
     padding:2px 6px;border-radius:3px;color:var(--accent)}

/* ── layout ── */
.container{max-width:1300px;margin:0 auto;padding:2rem}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
@media(max-width:768px){.grid-2{grid-template-columns:1fr}}

/* ── cards ── */
.card{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;
}
.card-header{
  padding:.8rem 1.1rem;background:rgba(255,255,255,.02);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
  font-weight:600;font-size:.9rem;
}
.card-body{padding:1.1rem}

/* ── badges ── */
.badge{
  display:inline-flex;align-items:center;
  padding:3px 8px;border-radius:99px;
  font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
}
.badge-red   {background:var(--red-dim);   color:var(--red);   border:1px solid var(--red)}
.badge-green {background:var(--green-dim); color:var(--green); border:1px solid var(--green)}
.badge-blue  {background:var(--blue-dim);  color:var(--blue);  border:1px solid var(--blue)}
.badge-amber {background:var(--accent-dim);color:var(--accent);border:1px solid var(--accent)}
.badge-purple{background:var(--purple-dim);color:var(--purple);border:1px solid var(--purple)}
.badge-muted {background:var(--bg-hover);  color:var(--text-muted);border:1px solid var(--border)}

/* ── buttons ── */
.btn{
  display:inline-flex;align-items:center;gap:.4rem;
  padding:.5rem 1rem;border-radius:var(--radius);
  font-size:.85rem;cursor:pointer;transition:all .15s;
  text-decoration:none;border:1px solid transparent;font-weight:500;
}
.btn-primary{background:var(--accent);color:#000;border-color:var(--accent)}
.btn-primary:hover{filter:brightness(1.1)}
.btn-ghost{background:transparent;color:var(--text-dim);border-color:var(--border)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}

/* ── table ── */
.tbl-wrap{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{padding:.75rem 1rem;text-align:left;color:var(--text-muted);font-weight:500;
   background:rgba(255,255,255,.02);border-bottom:1px solid var(--border)}
td{padding:.7rem 1rem;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:hover{background:var(--bg-hover)}
tbody tr:last-child td{border-bottom:none}

/* ── search ── */
.search-wrap{position:relative}
.search-wrap input{
  width:100%;padding:.6rem 1rem .6rem 2.4rem;
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);color:var(--text);font-size:.88rem;
  font-family:var(--sans);
}
.search-wrap input:focus{outline:none;border-color:var(--accent)}
.search-icon{position:absolute;left:.75rem;top:50%;transform:translateY(-50%);
  color:var(--text-muted);pointer-events:none;font-size:.85rem}

/* ── pagination ── */
.pgn{display:flex;gap:.35rem}
.pgn button{
  width:30px;height:30px;border-radius:var(--radius);
  background:var(--bg-card);border:1px solid var(--border);
  color:var(--text);cursor:pointer;font-size:.85rem;
}
.pgn button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.pgn button.active{background:var(--accent);border-color:var(--accent);color:#000}
.pgn button:disabled{opacity:.35;cursor:not-allowed}

/* ── top-bar ── */
.topbar{
  background:var(--bg-card);border-bottom:1px solid var(--border);
  padding:.75rem 1.5rem;
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:100;
}
.topbar-brand{display:flex;align-items:center;gap:.75rem;font-weight:700;font-size:1rem}
.topbar-logo{
  width:28px;height:28px;background:var(--accent);color:#000;
  border-radius:5px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:.85rem;letter-spacing:-.05em;
}
.topbar-nav{display:flex;align-items:center;gap:.75rem}

/* ── dark-mode toggle ── */
.theme-toggle{
  width:36px;height:20px;background:var(--bg-hover);border:1px solid var(--border);
  border-radius:99px;cursor:pointer;position:relative;transition:background .2s;
}
.theme-toggle::after{
  content:'';position:absolute;top:2px;left:2px;
  width:14px;height:14px;background:var(--text-muted);border-radius:50%;
  transition:transform .2s,background .2s;
}
[data-theme="light"] .theme-toggle{background:var(--accent-dim)}
[data-theme="light"] .theme-toggle::after{
  transform:translateX(16px);background:var(--accent);
}

/* ── code block ── */
.code-block{
  background:var(--bg-inset);border:1px solid var(--border);
  border-radius:var(--radius);padding:1rem;
  font-family:var(--mono);font-size:.8rem;
  color:#7ee787;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
}

/* ── diff ── */
.diff-table{width:100%;border-collapse:collapse;table-layout:fixed;
  font-family:var(--mono);font-size:.75rem}
.diff-table td{padding:2px 6px;white-space:pre-wrap;word-break:break-all;border-bottom:none}
.diff-num{width:36px;text-align:right;color:var(--text-muted);opacity:.5;
  border-right:1px solid var(--border);user-select:none}
.diff-add{background:rgba(34,197,94,.12);color:#4ade80}
.diff-del{background:rgba(239,68,68,.12);color:#f87171}
.diff-empty{background:var(--bg-inset)}

/* ── misc ── */
.stat-num{font-size:2.2rem;font-weight:800;line-height:1;color:var(--text)}
.stat-lbl{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-top:.2rem}
hr{border:none;border-top:1px solid var(--border);margin:1rem 0}
.mb-1{margin-bottom:.5rem}.mb-2{margin-bottom:1rem}.mb-3{margin-bottom:1.5rem}
.mt-1{margin-top:.5rem}.mt-2{margin-top:1rem}.mt-3{margin-top:1.5rem}
.flex{display:flex}.items-center{align-items:center}.gap-1{gap:.5rem}.gap-2{gap:1rem}
.w-full{width:100%}.text-right{text-align:right}
"""

_JS_THEME = """
(function(){
  const saved = localStorage.getItem('gle-theme') || 'dark';
  document.documentElement.dataset.theme = saved;
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.theme-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = next;
        localStorage.setItem('gle-theme', next);
      });
    });
  });
})();
"""

_FONTS = '<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:ital,wght@0,400;0,500;0,600;1,400&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">'

def _html_head(title: str, extra_css: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} \u2014 Git Leak Explorer</title>
{_FONTS}
<style>
{_CSS_VARS}
{_CSS_BASE}
{extra_css}
</style>
<script>{_JS_THEME}</script>
</head>
<body>
"""

def _topbar(active: str = "", outdir: str = "") -> str:
    """Build the top navigation bar.

    All report links are always emitted — by the time the user views the HTML
    in a browser every file will have been generated.  The *outdir* parameter
    is kept for API compatibility but is no longer used to gate link rendering.
    """
    ALL_LINKS = [
        ("report.html",                "Dashboard"),
        ("listing.html",               "Files"),
        ("history.html",               "History"),
        ("hardening_report.html",      "Hardening"),
        ("users.html",                 "Users"),
        ("secrets.html",               "Secrets"),
        ("sast_report.html",           "SAST"),
        ("infrastructure_report.html", "Infra Map"),
        ("bruteforce_report.html",     "Brute-Force"),
    ]
    nav_items = ""
    for href, name in ALL_LINKS:
        color = "var(--accent)" if name == active else "var(--text-dim)"
        nav_items += f'<a href="{href}" style="font-size:.82rem;color:{color};">{name}</a>'
    return f"""
<div class="topbar">
  <div class="topbar-brand">
    <div class="topbar-logo">GL</div>
    <span>Git Leak Explorer</span>
  </div>
  <nav class="topbar-nav">
    {nav_items}
    <div class="theme-toggle" title="Toggle dark/light mode"></div>
  </nav>
</div>
"""

def _html_foot() -> str:
    return f"""
<footer style="text-align:center;padding:2rem;color:var(--text-muted);font-size:.78rem;
  border-top:1px solid var(--border);margin-top:3rem">
  Git Leak Explorer &bull; Forensic &amp; Pentest Toolkit &bull;
  Generated {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
</footer>
</body></html>
"""

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 23 — HTML REPORT GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

def generate_hardening_html(report: Dict[str, Any], out_html: str) -> None:
    descr_map = {
        "HEAD":         ".git/HEAD accessible",
        "refs_heads":   ".git/refs/heads/ accessible",
        "packed_refs":  ".git/packed-refs accessible",
        "index":        ".git/index accessible",
        "objects_root": ".git/objects/ accessible",
        "logs":         ".git/logs/ accessible",
        "config":       ".git/config accessible",
        "stash":        ".git/refs/stash",
        "info_refs":    ".git/info/refs (Smart HTTP map)",
    }
    rows: List[Dict] = []
    total_score = 0
    for k, v in report.get("results", {}).items():
        exposed = v.get("exposed", False)
        evidence = "; ".join(
            f"{p.get('method','?')} {p.get('url')} ({p.get('status_code','?')})"
            for p in v.get("positive_urls", [])
        ) or "—"
        if exposed:
            if k in ("index", "objects_root", "config", "stash", "info_refs"):
                status = "CRITICAL"; total_score += 5
                action = "Block access immediately (HTTP 403) via .htaccess or server rules."
            else:
                status = "WARNING"; total_score += 2
                action = "Restrict access. File may reveal internal structure."
        else:
            status = "OK"; action = "No action required."
        rows.append({
            "category":    k,
            "description": descr_map.get(k, k),
            "status":      status,
            "evidence":    evidence,
            "action":      action,
        })

    risk_label = "SECURE"
    risk_cls   = "badge-green"
    if total_score >= 10:
        risk_label = "CRITICAL"; risk_cls = "badge-red"
    elif total_score > 0:
        risk_label = "MODERATE"; risk_cls = "badge-amber"

    data_json = json.dumps(rows, ensure_ascii=False)
    extra_css = """
    .hd-score{text-align:center;padding:1rem 1.5rem;border-left:1px solid var(--border)}
    .hd-score .num{font-size:1.8rem;font-weight:800}
    """
    html = _html_head("Hardening Report", extra_css) + _topbar("Hardening", os.path.dirname(out_html)) + f"""
<div class="container">
  <div class="card mb-3">
    <div class="card-header">
      <div>
        <div style="font-size:1.2rem;font-weight:700">🛡 Hardening Audit</div>
        <div class="muted" style="font-size:.82rem">Git directory and configuration file exposure check</div>
      </div>
      <div class="hd-score">
        <div class="num"><span class="badge {risk_cls}">{risk_label}</span></div>
        <div class="stat-lbl">Risk score: {total_score}</div>
      </div>
    </div>
  </div>
  <div class="flex gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">← Back to Dashboard</a>
    <div class="search-wrap" style="flex:1;max-width:500px">
      <span class="search-icon">⌕</span>
      <input id="q" type="text" placeholder="Filter by category, status or evidence…">
    </div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th style="width:22%">Category</th>
        <th style="width:15%">Status</th>
        <th style="width:30%">Technical Evidence</th>
        <th>Recommended Action</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
</div>
<script>
const ROWS={data_json};
const tbody=document.getElementById('tbody');
const q=document.getElementById('q');
function render(data){{
  tbody.innerHTML='';
  data.forEach(r=>{{
    const cls=r.status==='CRITICAL'?'badge-red':r.status==='WARNING'?'badge-amber':'badge-green';
    const tr=document.createElement('tr');
    if(r.status!=='OK') tr.style.background='rgba(var(--red-rgb),.02)';
    tr.innerHTML=`
      <td><div style="font-weight:600;color:var(--text)">${{r.category}}</div>
          <div class="dim" style="font-size:.78rem">${{r.description}}</div></td>
      <td><span class="badge ${{cls}}">${{r.status}}</span></td>
      <td class="mono" style="word-break:break-all;font-size:.75rem">${{r.evidence}}</td>
      <td class="dim" style="font-size:.82rem;font-style:italic">${{r.action}}</td>`;
    tbody.appendChild(tr);
  }});
}}
q.addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  render(ROWS.filter(r=>r.category.toLowerCase().includes(t)||r.status.toLowerCase().includes(t)||r.evidence.toLowerCase().includes(t)));
}});
render(ROWS);
</script>
""" + _html_foot()
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


def generate_secrets_html(findings: List[Dict], outpath: str) -> None:
    data_json = json.dumps(
        [{"type": f.get("type",""), "file": f.get("file",""),
          "context": f.get("context",""), "match": f.get("match","")}
         for f in findings],
        ensure_ascii=False
    )
    extra_css = """
    .pulse{width:10px;height:10px;background:var(--red);border-radius:50%;
      animation:pulse 2s infinite}
    @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,.7)}
      70%{box-shadow:0 0 0 10px transparent}100%{box-shadow:0 0 0 0 transparent}}
    .secret-card{background:var(--bg-card);border:1px solid var(--border);
      border-radius:var(--radius);overflow:hidden;margin-bottom:.75rem}
    .secret-card:hover{border-color:var(--red)}
    .secret-card-header{padding:.6rem 1rem;background:rgba(255,255,255,.02);
      border-bottom:1px solid var(--border);display:flex;
      justify-content:space-between;align-items:center}
    .hl{background:rgba(239,68,68,.2);color:var(--red);font-weight:700;
       border-bottom:1px dashed var(--red);padding:0 2px;cursor:pointer}
    .hl:hover{background:var(--red);color:#000}
    """
    html = _html_head("Secrets Detected", extra_css) + _topbar("Secrets", os.path.dirname(outpath)) + f"""
<div class="container">
  <div class="card mb-3" style="border-color:rgba(239,68,68,.3);background:var(--red-dim)">
    <div class="card-body flex items-center gap-2" style="justify-content:space-between">
      <div class="flex items-center gap-2">
        <div class="pulse"></div>
        <div>
          <div style="font-size:1rem;font-weight:700;color:var(--red)">Secrets Detected</div>
          <div class="muted" style="font-size:.8rem">Potential credentials, API keys and tokens found in the codebase</div>
        </div>
      </div>
      <div class="text-right">
        <div class="stat-num" style="color:var(--red)">{len(findings)}</div>
        <div class="stat-lbl">Incidents</div>
      </div>
    </div>
  </div>
  <div class="flex gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">← Back</a>
    <div class="search-wrap" style="flex:1;max-width:600px">
      <span class="search-icon">⌕</span>
      <input id="q" type="text" placeholder="Filter by type, file or content…">
    </div>
  </div>
  <div id="container"></div>
  <div class="flex items-center" style="justify-content:space-between;padding:.75rem 0;color:var(--text-muted);font-size:.82rem">
    <span id="info">Loading…</span>
    <div class="pgn" id="pgn"></div>
  </div>
</div>
<script>
const DATA={data_json};
let filtered=DATA.slice(),cur=1;const PS=20;
const container=document.getElementById('container');
const info=document.getElementById('info');
const pgn=document.getElementById('pgn');
function esc(t){{if(!t)return'';return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}}
function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  container.innerHTML='';
  sl.forEach(item=>{{
    let ctx=esc(item.context);const sm=esc(item.match);
    try{{if(sm)ctx=ctx.split(sm).join(`<span class="hl" onclick="navigator.clipboard.writeText('${{sm}}')" title="Click to copy">${{sm}}</span>`);}}catch(e){{}}
    const el=document.createElement('div');el.className='secret-card';
    el.innerHTML=`<div class="secret-card-header">
      <span class="mono" style="font-size:.8rem;color:var(--text)">${{esc(item.file)}}</span>
      <span class="badge badge-red">${{esc(item.type)}}</span></div>
      <div style="padding:.75rem 1rem">
        <div class="code-block" style="margin-bottom:.5rem">${{ctx}}</div>
        <div class="flex gap-1">
          <button class="btn btn-ghost" style="font-size:.75rem;padding:3px 8px"
            onclick="navigator.clipboard.writeText('${{esc(item.match)}}')">📋 Copy match</button>
          <button class="btn btn-ghost" style="font-size:.75rem;padding:3px 8px"
            onclick="navigator.clipboard.writeText('${{esc(item.file)}}')">📂 Copy path</button>
        </div></div>`;
    container.appendChild(el);
  }});
  info.textContent=`Showing ${{(cur-1)*PS+1}}–${{Math.min(cur*PS,tot)}} of ${{tot}}`;
  pgn.innerHTML='';
  const pb=document.createElement('button');pb.textContent='‹';pb.disabled=cur===1;
  pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');nb.textContent='›';nb.disabled=cur===tp;
  nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}
document.getElementById('q').addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  filtered=DATA.filter(i=>(i.type||'').toLowerCase().includes(t)||(i.file||'').toLowerCase().includes(t)||(i.context||'').toLowerCase().includes(t));
  cur=1;render();
}});
render();
</script>
""" + _html_foot()
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        print(f"Error generating secrets HTML: {e}")


def generate_misc_html(out_html: str, title: str, content_data: str, is_text: bool) -> None:
    import html as html_lib
    is_ds = "DS_Store" in title
    if is_text:
        if is_ds:
            lines = content_data.strip().split("\n")
            rows  = "".join(
                f'<tr><td class="mono"><a href="{l.strip()}" target="_blank">{l.strip()}</a></td>'
                f'<td class="text-right"><a href="{l.strip()}" target="_blank" style="font-size:1rem">🔗</a></td></tr>'
                for l in lines if l.strip() and not l.startswith("===")
            )
            content_block = f"""
<div class="search-wrap mb-2" style="max-width:500px">
  <span class="search-icon">⌕</span>
  <input id="q" type="text" placeholder="Filter files…">
</div>
<div class="tbl-wrap">
  <table id="t"><thead><tr><th>Recovered URL</th><th style="width:50px">Action</th></tr></thead>
  <tbody id="tb">{rows}</tbody></table>
</div>"""
        else:
            safe = html_lib.escape(content_data)
            content_block = f"""
<div class="card">
  <div class="card-header">
    <span class="badge badge-muted">TEXT / CONFIG</span>
    <button class="btn btn-ghost" style="font-size:.8rem" onclick="navigator.clipboard.writeText(document.getElementById('fc').innerText)">📋 Copy</button>
  </div>
  <div class="card-body">
    <div class="code-block" id="fc">{safe}</div>
  </div>
</div>"""
    else:
        content_block = """
<div class="card" style="text-align:center">
  <div class="card-body" style="padding:3rem">
    <div style="font-size:3rem;margin-bottom:1rem">📦</div>
    <h3 class="mb-1">Binary File Captured</h3>
    <p class="muted mb-2">This file cannot be displayed in the browser.</p>
    <code>_files/misc/</code>
    <div class="card mb-2 mt-2" style="background:var(--accent-dim);border-color:var(--accent);display:inline-block;padding:.75rem 1rem;font-size:.85rem">
      <strong>Recommended analysis:</strong> Use <code>sqlite3</code> (for .db),
      <code>strings</code> or a hex viewer.
    </div>
  </div>
</div>"""

    html = _html_head(f"Leak: {title}") + _topbar("", os.path.dirname(out_html)) + f"""
<div class="container">
  <div class="flex items-center gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">← Back</a>
    <span class="badge badge-amber">⚠ {html_lib.escape(title)}</span>
  </div>
  {content_block}
</div>
<script>
const q=document.getElementById('q');
if(q){{q.addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  document.querySelectorAll('#tb tr').forEach(r=>{{
    r.style.display=r.innerText.toLowerCase().includes(t)?'':'none';
  }});
}});}}
</script>
""" + _html_foot()
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


def generate_bruteforce_report(findings: List[Dict], outpath: str) -> None:
    # Build JSON data for the JS renderer
    rows_data = []
    for f in findings:
        source   = f.get("type", f.get("list_source", "DEFAULT LIST"))
        fname    = f.get("filename", "unknown")
        furl     = f.get("url", "#")
        git_sha  = f.get("git_sha", "")
        in_git   = bool(f.get("in_git"))
        # local_path may be absolute; compute a relative URL for the preview
        local_abs = f.get("local_path", "")
        # We store the relative path from outpath's folder so the viewer can fetch it
        outdir = os.path.dirname(outpath)
        local_rel = ""
        if local_abs and os.path.isfile(local_abs):
            try:
                local_rel = os.path.relpath(local_abs, outdir).replace("\\", "/")
            except ValueError:
                local_rel = ""
        rows_data.append({
            "source":    source,
            "filename":  fname,
            "url":       furl,
            "git_sha":   git_sha,
            "in_git":    in_git,
            "local_rel": local_rel,
        })

    data_json = json.dumps(rows_data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")

    html = _html_head("Brute-Force Report") + _topbar("Brute-Force", os.path.dirname(outpath)) + f"""
<div class="container">
  <div class="flex items-center gap-2 mb-3" style="justify-content:space-between">
    <div>
      <h2 style="font-weight:700">&#x1F528; Brute-Force / Traversal</h2>
      <p class="muted" style="font-size:.82rem">Results via Brute-Force &amp; Path Traversal</p>
    </div>
    <span class="badge badge-blue" style="font-size:.85rem">{len(findings)} found</span>
  </div>
  <div class="flex gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">&#x2190; Back</a>
    <div class="search-wrap" style="flex:1;max-width:450px">
      <span class="search-icon">&#x2315;</span>
      <input id="q" type="text" placeholder="Filter by name, URL or status&#x2026;">
    </div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th style="width:12%">Source</th>
        <th style="width:28%">File</th>
        <th style="width:30%">URL</th>
        <th style="width:13%">Status</th>
        <th style="width:17%">SHA-1 / Preview</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="flex items-center mt-2" style="justify-content:space-between;color:var(--text-muted);font-size:.82rem">
    <span id="info"></span><div class="pgn" id="pgn"></div>
  </div>
</div>

<!-- File preview overlay (same design as listing.html) -->
<div id="fv" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:999;padding:1.5rem">
  <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
    height:100%;display:flex;flex-direction:column">
    <div style="padding:.75rem 1rem;border-bottom:1px solid var(--border);
      display:flex;justify-content:space-between;align-items:center">
      <span id="fv-title" class="mono" style="font-size:.85rem"></span>
      <button onclick="closeFv()" class="btn btn-ghost" style="padding:4px 10px">&#x2715;</button>
    </div>
    <div style="flex:1;overflow:auto;padding:1rem;background:var(--bg-inset)">
      <img id="fv-img" style="display:none;max-width:100%;height:auto;border-radius:4px">
      <pre id="fv-code" class="code-block" style="display:none;height:100%;margin:0"></pre>
      <div id="fv-binary" style="display:none;text-align:center;padding:3rem">
        <div style="font-size:3rem;margin-bottom:1rem">&#x1F4E6;</div>
        <p style="color:var(--text-muted)">The binary file cannot be viewed in this window.</p>
      </div>
    </div>
  </div>
</div>

<script>
const DATA={data_json};
let filtered=DATA.slice(),cur=1;const PS=20;
const tb=document.getElementById('tb');
const info=document.getElementById('info');
const pgn=document.getElementById('pgn');

function esc(s){{return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}

/* ── Binary detection ── */
const BIN_EXTS=new Set(['exe','dll','so','bin','obj','class','pyc','pyd',
  'zip','gz','tar','7z','rar','bz2','xz','pack','idx',
  'png','jpg','jpeg','gif','bmp','ico','tiff','webp',
  'mp3','mp4','avi','mov','mkv','flac','ogg',
  'pdf','doc','docx','xls','xlsx','ppt','pptx',
  'woff','woff2','eot','ttf','otf']);
const IMG_EXTS=new Set(['png','jpg','jpeg','gif','bmp','svg','webp','ico']);

function isBinary(fname){{
  const ext=(fname.split('.').pop()||'').toLowerCase();
  return BIN_EXTS.has(ext);
}}
function isImage(fname){{
  const ext=(fname.split('.').pop()||'').toLowerCase();
  return IMG_EXTS.has(ext);
}}

/* ── Overlay helpers ── */
function closeFv(){{
  document.getElementById('fv').style.display='none';
  document.getElementById('fv-img').style.display='none';
  document.getElementById('fv-code').style.display='none';
  document.getElementById('fv-binary').style.display='none';
}}
async function viewFile(localRel, filename){{
  const fv=document.getElementById('fv');
  const img=document.getElementById('fv-img');
  const code=document.getElementById('fv-code');
  const binMsg=document.getElementById('fv-binary');
  document.getElementById('fv-title').textContent=filename;
  fv.style.display='block';
  img.style.display='none';code.style.display='none';binMsg.style.display='none';

  if(isBinary(filename)&&!isImage(filename)){{
    binMsg.style.display='block';
    return;
  }}
  if(isImage(filename)){{
    img.src=localRel;img.style.display='block';
    return;
  }}
  code.style.display='block';code.textContent='Loading\u2026';
  try{{
    const r=await fetch(localRel);
    if(!r.ok)throw new Error('HTTP '+r.status);
    const text=await r.text();
    /* Heuristic binary check on fetched content */
    const hasBin=/[\\x00-\\x08\\x0e-\\x1f\\x7f]/.test(text.slice(0,512));
    if(hasBin){{
      code.style.display='none';binMsg.style.display='block';
    }}else{{
      code.textContent=text;
    }}
  }}catch(e){{
    code.textContent='Error loading file: '+e.message;
  }}
}}

function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  tb.innerHTML='';
  sl.forEach(r=>{{
    const tr=document.createElement('tr');
    const sCls=r.source==='traversal'?'badge-amber':r.source==='Custom'?'badge-blue':'badge-muted';
    const stCls=r.in_git?'badge-green':'badge-amber';
    const stLbl=r.in_git?'VERSIONED':'LOCAL ONLY';
    /* VERSIONED: single button that IS the status AND opens the preview */
    const statusCell=r.in_git&&r.local_rel
      ?`<button onclick="viewFile('${{esc(r.local_rel)}}','${{esc(r.filename)}}')"
          class="badge badge-green" style="cursor:pointer;border:none;padding:3px 8px">
          &#x1F441;&nbsp;VERSIONED</button>`
      :`<span class="badge ${{stCls}}">${{stLbl}}</span>`;
    const shaLabel=r.git_sha?r.git_sha.slice(0,8):'&#x2014;';
    tr.innerHTML=`
      <td><span class="badge ${{sCls}}">${{esc(r.source)}}</span></td>
      <td class="mono" style="word-break:break-all;font-size:.8rem">${{esc(r.filename)}}</td>
      <td class="mono" style="font-size:.75rem;word-break:break-all">
        <a href="${{esc(r.url)}}" target="_blank" class="dim">${{esc(r.url)}}</a></td>
      <td>${{statusCell}}</td>
      <td class="mono" style="font-size:.78rem;color:var(--purple)">${{shaLabel}}</td>`;
    tb.appendChild(tr);
  }});
  info.textContent=`${{tot?((cur-1)*PS+1):0}}\u2013${{Math.min(cur*PS,tot)}} of ${{tot}} files`;
  pgn.innerHTML='';
  const pb=document.createElement('button');pb.textContent='\u2039';pb.disabled=cur===1;
  pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');nb.textContent='\u203a';nb.disabled=cur===tp;
  nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}
document.getElementById('q').addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  filtered=t?DATA.filter(r=>
    (r.filename||'').toLowerCase().includes(t)||
    (r.url||'').toLowerCase().includes(t)||
    (r.in_git?'versioned':'local only').includes(t)
  ):DATA.slice();
  cur=1;render();
}});
render();
</script>
""" + _html_foot()
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)
        success(f"Brute-force report generated: {outpath}")
    except Exception as e:
        warn(f"Error generating brute-force HTML: {e}")


def generate_infrastructure_html(findings: List[Dict], outpath: str) -> None:
    data_js = json.dumps(findings)
    nodes = [{"id": "root", "label": "TARGET", "shape": "diamond", "color": "#e8a020", "size": 30}]
    edges = []
    seen: set = set()
    for f in findings[:200]:
        val = f["value"]
        if val not in seen:
            color = {"API_ENDPOINT": "#22c55e", "IP_ADDRESS": "#ef4444"}.get(f["category"], "#a78bfa")
            nodes.append({"id": val, "label": val, "color": color, "font": {"color": "#fff"}})
            edges.append({"from": "root", "to": val})
            seen.add(val)

    html = _html_head("Infrastructure Map") + _topbar("Infra Map", os.path.dirname(outpath)) + f"""
<div class="container">
  <div class="flex items-center gap-2 mb-3" style="justify-content:space-between">
    <h2 style="font-weight:700">🌐 Infrastructure Map</h2>
    <a href="report.html" class="btn btn-ghost">← Back</a>
  </div>
  <div id="graph" style="height:400px;background:var(--bg-inset);border:1px solid var(--border);
    border-radius:var(--radius);margin-bottom:1.5rem"></div>
  <div class="search-wrap mb-2" style="max-width:500px">
    <span class="search-icon">⌕</span>
    <input id="gs" type="text" placeholder="Search host, IP, endpoint, file…">
  </div>
  <div id="dt-wrap" class="tbl-wrap">
    <table id="infra">
      <thead><tr>
        <th style="width:13%">Category</th>
        <th style="width:28%">Asset Detected</th>
        <th style="width:25%">Source File</th>
        <th>Code Context</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="flex items-center mt-2" style="justify-content:space-between;color:var(--text-muted);font-size:.82rem">
    <span id="pg-info"></span><div class="pgn" id="pgn"></div>
  </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<script>
const DATA={data_js};
const decoded=DATA.map(d=>({{...d,context:atob(d.context)}}));
function esc(s){{return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
// graph
const net=new vis.Network(document.getElementById('graph'),
  {{nodes:{json.dumps(nodes)},edges:{json.dumps(edges)}}},
  {{physics:{{solver:'forceAtlas2Based',stabilization:{{iterations:80}}}},
    edges:{{color:'#2e3a50'}}}});

// table
const tb=document.getElementById('tb');
const pgInfo=document.getElementById('pg-info');
const pgn=document.getElementById('pgn');
let filtered=decoded,cur=1;const PS=25;
function catCls(c){{return c==='IP_ADDRESS'?'badge-red':c==='API_ENDPOINT'?'badge-green':'badge-purple'}}
function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  tb.innerHTML='';
  sl.forEach(r=>{{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td><span class="badge ${{catCls(r.category)}}">${{r.category.replace('_',' ')}}</span></td>
      <td class="mono" style="word-break:break-all;color:var(--text)">${{esc(r.value)}}</td>
      <td class="dim" style="font-size:.78rem">${{esc(r.file)}}</td>
      <td><div class="code-block" style="font-size:.72rem;padding:.4rem .6rem">${{esc(r.context)}}</div></td>`;
    tb.appendChild(tr);
  }});
  pgInfo.textContent=`${{(cur-1)*PS+1}}–${{Math.min(cur*PS,tot)}} of ${{tot}} assets`;
  pgn.innerHTML='';
  const pb=document.createElement('button');pb.textContent='‹';pb.disabled=cur===1;
  pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');nb.textContent='›';nb.disabled=cur===tp;
  nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}
document.getElementById('gs').addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  filtered=decoded.filter(r=>(r.value||'').toLowerCase().includes(t)||(r.file||'').toLowerCase().includes(t));
  cur=1;render();
}});
net.on('click',p=>{{if(p.nodes.length){{
  const id=p.nodes[0];
  document.getElementById('gs').value=id==='root'?'':id;
  filtered=id==='root'?decoded:decoded.filter(r=>r.value===id);
  cur=1;render();
}}
}});
render();
</script>
""" + _html_foot()
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)


def generate_users_report(outdir: str, authors_stats: Dict[str, int]) -> None:
    info("Generating user identities report (OSINT)...")
    users_data: List[Dict] = []
    for raw_author, count in sorted(authors_stats.items(), key=lambda x: x[1], reverse=True):
        name = raw_author
        email = ""
        m = re.search(r"(.*)\s+<(.*)>", raw_author)
        if m:
            name  = m.group(1).strip()
            email = m.group(2).strip()
        users_data.append({"raw": raw_author, "name": name, "email": email, "commits": count})

    files_dir = os.path.join(outdir, "_files")
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, "users.json"), "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

    total_commits = sum(u["commits"] for u in users_data)
    users_json    = json.dumps(users_data, ensure_ascii=False)

    html = _html_head("Identities (OSINT)") + _topbar("Users", outdir) + f"""
<div class="container">
  <div class="flex items-center gap-2 mb-3" style="justify-content:space-between">
    <div>
      <h2 style="font-weight:700">👤 Developer Identities</h2>
      <p class="muted" style="font-size:.82rem">Developers and emails extracted from commit history</p>
    </div>
    <div class="flex gap-2">
      <span class="badge badge-blue">{len(users_data)} authors</span>
      <span class="badge badge-muted">{total_commits} commits</span>
    </div>
  </div>
  <div class="flex gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">← Back</a>
    <div class="search-wrap" style="flex:1;max-width:450px">
      <span class="search-icon">⌕</span>
      <input id="q" type="text" placeholder="Filter by name, email or domain…">
    </div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th style="width:28%">Author Name</th>
        <th style="width:33%">Email</th>
        <th style="width:14%">Commits</th>
        <th>Raw Git Signature</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="flex items-center mt-2" style="justify-content:space-between;color:var(--text-muted);font-size:.82rem">
    <span id="info">Loading…</span><div class="pgn" id="pgn"></div>
  </div>
</div>
<script>
const USERS={users_json};
let filtered=USERS,cur=1;const PS=15;
const tb=document.getElementById('tb');
const info=document.getElementById('info');
const pgn=document.getElementById('pgn');
function esc(s){{return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  tb.innerHTML='';
  sl.forEach(u=>{{
    const initial=(u.name||'?').charAt(0).toUpperCase();
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td><div class="flex items-center gap-1">
        <div style="width:26px;height:26px;background:var(--accent-dim);color:var(--accent);
          border-radius:50%;display:flex;align-items:center;justify-content:center;
          font-weight:700;font-size:.78rem">${{initial}}</div>
        <span style="font-weight:600;color:var(--text)">${{esc(u.name)||'<span class="muted">Unknown</span>'}}</span>
      </div></td>
      <td>${{u.email?`<a href="mailto:${{esc(u.email)}}" class="mono" style="font-size:.82rem">${{esc(u.email)}}</a>`:'<span class="muted">—</span>'}}</td>
      <td><span class="badge badge-green">${{u.commits}}</span></td>
      <td class="mono dim" style="font-size:.78rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${{esc(u.raw)}}">${{esc(u.raw)}}</td>`;
    tb.appendChild(tr);
  }});
  info.textContent=`Showing ${{(cur-1)*PS+1}}–${{Math.min(cur*PS,tot)}} of ${{tot}} authors`;
  pgn.innerHTML='';
  const pb=document.createElement('button');pb.textContent='‹';pb.disabled=cur===1;
  pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');nb.textContent='›';nb.disabled=cur===tp;
  nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}
document.getElementById('q').addEventListener('input',e=>{{
  const t=e.target.value.toLowerCase();
  filtered=USERS.filter(u=>(u.name||'').toLowerCase().includes(t)||(u.email||'').toLowerCase().includes(t)||(u.raw||'').toLowerCase().includes(t));
  cur=1;render();
}});
render();
</script>
""" + _html_foot()
    out_html = os.path.join(outdir, "users.html")
    try:
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html)
        success(f"Users report saved: {out_html}")
    except Exception as e:
        warn(f"Error saving users.html: {e}")


def make_listing_modern(json_file: str, base_git_url: str, outdir: str) -> None:
    info(f"Generating listing dashboard for {json_file}")
    try:
        entries = load_dump_entries(json_file)
    except Exception as e:
        warn(f"Could not load index ({e}). Generating empty HTML.")
        entries = []
    site_base = normalize_site_base(base_git_url)
    rows: List[Dict] = []

    for e in entries:
        path = e.get("path", "")
        sha  = e.get("sha1", "")
        if not sha:
            continue
        local_path_rel  = path.lstrip("/")
        local_full_path = os.path.join(outdir, local_path_rel)
        pack_matches    = glob.glob(
            os.path.join(outdir, "_files", "extracted_packs", "*", "named_restore", local_path_rel)
        )
        local_exists = False
        final_url    = ""
        if os.path.isfile(local_full_path):
            local_exists = True
            final_url    = local_path_rel
        elif pack_matches:
            local_exists = True
            final_url    = os.path.relpath(pack_matches[0], outdir).replace("\\", "/")
        rows.append({
            "path":       path,
            "remote_url": public_url(site_base, path),
            "blob_url":   make_blob_url(base_git_url, sha),
            "sha":        sha,
            "local_exists": local_exists,
            "local_url":  final_url,
        })

    data_json = json.dumps(rows, ensure_ascii=False)
    html = _html_head("File Listing") + _topbar("Files", outdir) + f"""
<div class="container">
  <div class="flex items-center gap-2 mb-3" style="justify-content:space-between">
    <div>
      <h2 style="font-weight:700">📂 Recovered Files</h2>
      <p class="muted" style="font-size:.82rem">Complete repository index (.git/index)</p>
    </div>
    <span class="badge badge-amber">{len(rows)} files</span>
  </div>
  <div class="flex gap-2 mb-3">
    <a href="report.html" class="btn btn-ghost">← Back</a>
    <div class="search-wrap" style="flex:1;max-width:500px">
      <span class="search-icon">⌕</span>
      <input id="q" type="text" placeholder="Search by name, extension or SHA…">
    </div>
    <select id="ps" class="btn btn-ghost" style="cursor:pointer">
      <option value="25">25 / page</option>
      <option value="100" selected>100 / page</option>
      <option value="500">500 / page</option>
    </select>
    <button id="reset" class="btn btn-ghost">✕ Clear</button>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th style="width:48%" class="sortable" data-k="path" style="cursor:pointer">Filename ↕</th>
        <th style="width:18%">Local Status</th>
        <th style="width:10%">Remote</th>
        <th style="width:24%" class="sortable" data-k="sha" style="cursor:pointer">Blob SHA-1 ↕</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="flex items-center mt-2" style="justify-content:space-between;color:var(--text-muted);font-size:.82rem">
    <span id="info">Loading…</span>
    <div class="flex items-center gap-1">
      <button id="prev" class="pgn-btn btn btn-ghost" style="padding:4px 10px">‹</button>
      <span id="pd" style="font-size:.8rem"></span>
      <button id="next" class="pgn-btn btn btn-ghost" style="padding:4px 10px">›</button>
    </div>
  </div>
</div>
<!-- File viewer overlay -->
<div id="fv" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:999;padding:1.5rem">
  <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
    height:100%;display:flex;flex-direction:column">
    <div style="padding:.75rem 1rem;border-bottom:1px solid var(--border);
      display:flex;justify-content:space-between;align-items:center">
      <span id="fv-title" class="mono" style="font-size:.85rem"></span>
      <button onclick="document.getElementById('fv').style.display='none'"
        class="btn btn-ghost" style="padding:4px 10px">✕</button>
    </div>
    <div style="flex:1;overflow:auto;padding:1rem;background:var(--bg-inset)">
      <img id="fv-img" style="display:none;max-width:100%;height:auto">
      <pre id="fv-code" class="code-block" style="display:none;height:100%"></pre>
    </div>
  </div>
</div>
<script>
const DATA={data_json};
let filtered=DATA.slice(),sortK=null,sortD=1,pageSize=100,cur=1;
const tb=document.getElementById('tb');
const info=document.getElementById('info');
const pd=document.getElementById('pd');
const prev=document.getElementById('prev');
const next=document.getElementById('next');
function esc(s){{return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function render(){{
  pageSize=parseInt(document.getElementById('ps').value,10);
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/pageSize));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*pageSize,cur*pageSize);
  tb.innerHTML='';
  sl.forEach(r=>{{
    const tr=document.createElement('tr');
    const localHtml=r.local_exists
      ?`<button onclick="viewFile('${{r.local_url}}','${{esc(r.path)}}')"
          class="badge badge-green" style="cursor:pointer;border:none">✓ Restored Local</button>`
      :`<span class="badge badge-muted">Remote Only</span>`;
    tr.innerHTML=`
      <td class="mono" style="word-break:break-all;font-size:.8rem;color:var(--text)">${{esc(r.path)}}</td>
      <td>${{localHtml}}</td>
      <td><a href="${{r.remote_url}}" target="_blank" class="dim" style="font-size:.85rem">Open ↗</a></td>
      <td><a href="${{r.blob_url}}" target="_blank" class="mono" style="color:var(--purple);font-size:.8rem">${{r.sha}}</a></td>`;
    tb.appendChild(tr);
  }});
  const s=(cur-1)*pageSize+1,e=Math.min(cur*pageSize,tot);
  info.textContent=`Showing ${{tot?s:0}}–${{e}} of ${{tot}} files`;
  pd.textContent=`Page ${{cur}} / ${{tp}}`;
  prev.disabled=cur===1;next.disabled=cur===tp;
}}
function applyFilter(){{
  const term=document.getElementById('q').value.trim().toLowerCase();
  filtered=term?DATA.filter(r=>(r.path||'').toLowerCase().includes(term)||(r.sha||'').toLowerCase().includes(term)):DATA.slice();
  if(sortK){{filtered.sort((a,b)=>{{const A=(a[sortK]||'').toLowerCase(),B=(b[sortK]||'').toLowerCase();return A<B?-sortD:A>B?sortD:0}})}}
  cur=1;render();
}}
document.getElementById('q').addEventListener('input',applyFilter);
document.getElementById('ps').addEventListener('change',()=>{{cur=1;render()}});
document.getElementById('reset').addEventListener('click',()=>{{
  document.getElementById('q').value='';
  document.getElementById('ps').value='100';
  sortK=null;sortD=1;filtered=DATA.slice();cur=1;render();
}});
prev.addEventListener('click',()=>{{if(cur>1){{cur--;render()}}}});
next.addEventListener('click',()=>{{const tp=Math.ceil(filtered.length/pageSize);if(cur<tp){{cur++;render()}}}});
document.querySelectorAll('th.sortable').forEach(th=>{{
  th.style.cursor='pointer';
  th.addEventListener('click',()=>{{
    const k=th.dataset.k;sortD=sortK===k?-sortD:1;sortK=k;applyFilter();
  }});
}});
async function viewFile(url,filename){{
  const fv=document.getElementById('fv');
  const img=document.getElementById('fv-img');
  const code=document.getElementById('fv-code');
  document.getElementById('fv-title').textContent=filename;
  fv.style.display='block';img.style.display='none';code.style.display='none';code.textContent='Loading…';
  const ext=filename.split('.').pop().toLowerCase();
  const imgs=['png','jpg','jpeg','gif','svg','webp','ico'];
  if(imgs.includes(ext)){{img.src=url;img.style.display='block'}}
  else{{
    code.style.display='block';
    try{{const r=await fetch(url);if(!r.ok)throw new Error('Failed');code.textContent=await r.text()}}
    catch(e){{code.textContent='Error loading file: '+e.message}}
  }}
}}
render();
</script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
""" + _html_foot()
    outpath = os.path.join(outdir, "listing.html")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    success(f"Listing dashboard generated: {outpath}")


def generate_history_html(
    in_json: str, out_html: str, site_base: str, base_git_url: str
) -> None:
    with open(in_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    commits      = data.get("commits", [])
    head_sha     = data.get("head", "N/A")
    remote_url   = data.get("remote_url", "")
    commits_json = (
        json.dumps(commits, ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    remote_block = f"""
<div style="background:var(--accent-dim);border:1px solid var(--accent);border-radius:var(--radius);
  padding:.5rem 1rem;font-size:.82rem">
  Remote detected: <a href="{remote_url}" target="_blank" style="font-weight:600">{remote_url}</a>
</div>""" if remote_url else ""

    outdir = os.path.dirname(out_html)
    html = _html_head("Git Timeline") + _topbar("History", outdir) + f"""
<div class="container">
  <div class="flex items-center gap-2 mb-3" style="justify-content:space-between;flex-wrap:wrap">
    <div>
      <h2 style="font-weight:700">&#x23F3; Git Timeline</h2>
      <p class="muted" style="font-size:.82rem">Target: {site_base}</p>
    </div>
    <div class="flex gap-2 items-center">
      {remote_block}
      <span class="badge badge-muted">HEAD: <span class="mono" style="color:var(--purple)">{head_sha[:8]}</span></span>
      <span class="badge badge-blue">{len(commits)} commits</span>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:auto 1fr 1fr;gap:.75rem;margin-bottom:1.2rem">
    <a href="report.html" class="btn btn-ghost">&#x2190; Back</a>
    <div class="search-wrap">
      <span class="search-icon">&#x2315;</span>
      <input id="qm" type="text" placeholder="Search commit (hash, author, message)&#x2026;">
    </div>
    <div class="search-wrap">
      <span class="search-icon">&#x1F4C2;</span>
      <input id="qf" type="text" placeholder="Filter by file name or diff content&#x2026;">
    </div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th style="width:10%">Hash</th>
        <th style="width:12%">Date</th>
        <th style="width:15%">Author</th>
        <th style="width:38%">Message</th>
        <th style="width:25%">Files</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>
  <div class="flex items-center mt-2" style="justify-content:space-between;color:var(--text-muted);font-size:.82rem">
    <span id="info"></span><div class="pgn" id="pgn"></div>
  </div>
</div>
<style>
.diff-wrap {{ display:none; }}
.diff-wrap.open {{ display:block; }}
</style>
<script>
const COMMITS={commits_json};
/* commitFilter = commit-level text search; fileFilter = file/diff search */
let commitFilter='', fileFilter='';
let filtered=COMMITS.slice(), cur=1;
const PS=20;
const tb=document.getElementById('tb');
const info=document.getElementById('info');
const pgn=document.getElementById('pgn');

function esc(t){{if(!t)return'';return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}}

/* ── Diff renderer (side-by-side) ── */
function renderSBS(diff){{
  if(!diff||diff.startsWith('['))return`<div style="padding:1rem;color:var(--red);font-size:.82rem">${{esc(diff||'No content')}}</div>`;
  const lines=diff.split(/\\r?\\n/);
  let rows='',ol=1,nl=1;
  for(let i=0;i<lines.length;i++){{
    const line=lines[i];
    if(line.startsWith('---')||line.startsWith('+++')||line.startsWith('index '))continue;
    if(line.startsWith('@@')){{
      rows+=`<tr style="background:var(--bg-hover)"><td colspan="4" style="padding:3px 8px;font-size:.7rem;color:var(--text-muted)">${{esc(line)}}</td></tr>`;
      continue;
    }}
    let lc='',rc='',lv='',rv='',ln='',rn='';
    if(line.startsWith('-')){{
      lc='diff-del';lv=esc(line.slice(1))||'&nbsp;';ln=ol++;
    }}else if(line.startsWith('+')){{
      rc='diff-add';rv=esc(line.slice(1))||'&nbsp;';rn=nl++;
    }}else{{
      const c=esc(line.slice(1))||'&nbsp;';lv=c;rv=c;ln=ol++;rn=nl++;
    }}
    rows+=`<tr>
      <td class="diff-num">${{ln||''}}</td>
      <td class="${{lc||'diff-empty'}}">${{lv||'&nbsp;'}}</td>
      <td class="diff-num">${{rn||''}}</td>
      <td class="${{rc||'diff-empty'}}">${{rv||'&nbsp;'}}</td></tr>`;
  }}
  return`<table class="diff-table"><colgroup><col style="width:36px"><col><col style="width:36px"><col></colgroup>${{rows}}</table>`;
}}

/* ── Toggle diff panel visibility ── */
function toggleDiff(uid, btn){{
  const el=document.getElementById(uid);
  if(!el)return;
  const isOpen=el.classList.contains('open');
  el.classList.toggle('open',!isOpen);
  if(btn)btn.textContent=isOpen?'View Diff':'Hide Diff';
}}

/* ── Toggle commit detail row ── */
function toggleDetails(idx){{
  const det=document.getElementById('det-'+idx);
  if(!det)return;
  det.style.display=det.style.display==='table-row'?'none':'table-row';
}}

/* ── Build the matched-file list for a commit given current fileFilter ──
   Returns null if fast_mode_skipped, [] if no changes, or filtered array.
   Also returns whether ANY file matched fileFilter (for row visibility). */
function getMatchedChanges(c){{
  if(c.fast_mode_skipped)return{{skipped:true,items:[],matched:true}};
  if(!c.changes||!c.changes.length)return{{skipped:false,items:[],matched:!fileFilter}};
  if(!fileFilter)return{{skipped:false,items:c.changes,matched:true}};
  const items=c.changes.filter(ch=>
    (ch.path||'').toLowerCase().includes(fileFilter)||
    (ch.diff||'').toLowerCase().includes(fileFilter)
  );
  return{{skipped:false,items,matched:items.length>0}};
}}

/* ── Apply both filters and rebuild the visible commit list ── */
function applyFilters(){{
  filtered=COMMITS.filter(c=>{{
    /* commit-level filter */
    if(commitFilter){{
      const match=(c.sha||'').includes(commitFilter)||
        (c.author||'').toLowerCase().includes(commitFilter)||
        (c.message||'').toLowerCase().includes(commitFilter);
      if(!match)return false;
    }}
    /* file-level filter: keep commit only if at least one file matches */
    if(fileFilter){{
      const m=getMatchedChanges(c);
      if(!m.matched)return false;
    }}
    return true;
  }});
  cur=1;
  render();
}}

/* ── Main render ── */
function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  tb.innerHTML='';

  sl.forEach((c,idx)=>{{
    const isStash=!!c.is_stash, isOrphan=!!c.is_orphan;
    const hashClr=isStash?'var(--accent)':isOrphan?'var(--red)':'var(--purple)';
    const shortSha=isStash?'STASH':isOrphan?'REFLOG':c.sha.slice(0,8);
    const mc=getMatchedChanges(c);
    const realCnt=mc.items.length;
    const filesSummary=mc.skipped
      ?'<span class="badge badge-red" style="font-size:.7rem">Fast Mode</span>'
      :`<span class="badge badge-muted">${{realCnt}} file${{realCnt!==1?'s':''}}</span> <span class="dim">&#x25B6;</span>`;

    /* commit row */
    const tr=document.createElement('tr');
    tr.style.cursor='pointer';
    if(isStash)tr.style.borderLeft='3px solid var(--accent)';
    if(isOrphan)tr.style.borderLeft='3px solid var(--red)';
    tr.onclick=()=>toggleDetails(idx);
    tr.innerHTML=`
      <td class="mono" style="color:${{hashClr}};font-weight:700">${{shortSha}}</td>
      <td class="dim" style="font-size:.8rem">${{c.date||'&#x2014;'}}</td>
      <td style="color:var(--text)">${{esc(c.author)||'&#x2014;'}}</td>
      <td><div style="display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:var(--text-dim)">${{esc(c.message)}}</div></td>
      <td>${{filesSummary}}</td>`;

    /* detail row */
    const det=document.createElement('tr');
    det.id='det-'+idx;
    det.style.display='none';
    det.style.background='var(--bg-inset)';

    let cHtml='';
    if(mc.skipped){{
      cHtml='<div style="padding:1rem;color:var(--red)">&#x26A0;&#xFE0F; Details omitted (Fast Mode). Re-run with <code>--full-history</code> for deep analysis.</div>';
    }}else if(mc.items.length){{
      cHtml=mc.items.map((ch,fi)=>{{
        const tagCls={{ADDED:'badge-green',MODIFIED:'badge-blue',DELETED:'badge-red',STASHED:'badge-amber'}}[ch.type]||'badge-muted';
        const uid=`diff-${{idx}}-${{fi}}`;
        const hasDiff=!!(ch.diff&&!ch.diff.startsWith('['));
        const btnHtml=hasDiff
          ?`<button class="btn btn-ghost" id="btn-${{uid}}" style="font-size:.75rem;padding:3px 8px"
              onclick="event.stopPropagation();toggleDiff('${{uid}}',this)">View Diff</button>`
          :'';
        const diffHtml=hasDiff
          ?`<div id="${{uid}}" class="diff-wrap">${{renderSBS(ch.diff)}}</div>`
          :'';
        return`<div style="border-bottom:1px solid var(--border)">
          <div style="padding:.5rem 1rem;display:flex;justify-content:space-between;align-items:center">
            <div>
              <span class="badge ${{tagCls}}">${{ch.type}}</span>
              <span class="mono" style="margin-left:.5rem;font-size:.82rem;color:var(--text)">${{esc(ch.path)}}</span>
            </div>
            ${{btnHtml}}
          </div>
          ${{diffHtml}}
        </div>`;
      }}).join('');
    }}else{{
      cHtml='<div style="padding:.75rem 1rem;color:var(--text-muted)">No recorded changes.</div>';
    }}

    det.innerHTML=`<td colspan="5" style="padding:0;border:none">${{cHtml}}</td>`;
    tb.append(tr,det);
  }});

  info.textContent=`Page ${{cur}} of ${{tp}} (${{tot}} commit${{tot!==1?'s':''}})`;
  pgn.innerHTML='';
  const pb=document.createElement('button');
  pb.textContent='\u2039';pb.disabled=cur===1;
  pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');
  nb.textContent='\u203a';nb.disabled=cur===tp;
  nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}

document.getElementById('qm').addEventListener('input',e=>{{
  commitFilter=e.target.value.trim().toLowerCase();
  applyFilters();
}});
document.getElementById('qf').addEventListener('input',e=>{{
  fileFilter=e.target.value.trim().toLowerCase();
  applyFilters();
}});
render();
</script>
""" + _html_foot()
    try:
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        print(f"Error saving history HTML: {e}")


def generate_master_dashboard(outdir: str, scan_results: List[Dict]) -> None:
    scan_results.sort(
        key=lambda x: (x["secrets_count"], x["files_count"], x["vuln_count"]),
        reverse=True,
    )
    total_secrets = sum(r["secrets_count"] for r in scan_results)
    rows = ""
    for r in scan_results:
        if r["secrets_count"] > 0:
            badge = '<span class="badge badge-red">CRITICAL</span>'
        elif r["files_count"] > 0:
            badge = '<span class="badge badge-amber">VULNERABLE</span>'
        elif r["vuln_count"] > 0:
            badge = '<span class="badge badge-blue">ALERT</span>'
        else:
            badge = '<span class="badge badge-muted">SECURE</span>'
        link = f"{r['folder_name']}/report.html"
        rows += f"""<tr>
          <td><a href="{link}" target="_blank" style="font-weight:600;color:var(--accent)">{r['target']}</a>
            <div class="dim" style="font-size:.75rem">{r['folder_name']}</div></td>
          <td>{badge}</td>
          <td class="text-right">{f'<span style="color:var(--red);font-weight:700">⚠ {r["secrets_count"]}</span>' if r["secrets_count"] > 0 else '—'}</td>
          <td class="text-right">{f'<span style="color:var(--accent)">{r["files_count"]}</span>' if r["files_count"] > 0 else '—'}</td>
          <td class="text-right"><a href="{link}" target="_blank" class="dim" style="font-size:.85rem">Open ↗</a></td>
        </tr>"""

    html = _html_head("Master Dashboard") + f"""
<style>body{{padding:2rem}}</style>
<div class="container">
  <div class="flex items-center gap-2 mb-3" style="justify-content:space-between">
    <div>
      <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
        <div style="width:28px;height:28px;background:var(--accent);color:#000;border-radius:5px;
          display:flex;align-items:center;justify-content:center;font-weight:900;font-size:.85rem">GL</div>
        <span style="font-weight:700;font-size:1.1rem">Git Leak Explorer</span>
      </div>
      <h2 style="font-weight:700">Master Dashboard</h2>
      <p class="muted" style="font-size:.82rem">{len(scan_results)} targets scanned</p>
    </div>
    <div class="flex gap-2">
      <span class="badge badge-muted">{len(scan_results)} targets</span>
      <span class="badge badge-red">{total_secrets} secrets</span>
    </div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>Target</th><th>Status</th>
        <th class="text-right">Secrets</th>
        <th class="text-right">Files</th>
        <th class="text-right">Action</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>
""" + _html_foot()
    with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)


def _ensure_html_stubs(outdir: str, args: Any) -> None:
    """
    Guarantee that every page linked from the navigation bar exists on disk.

    Called at the end of generate_unified_report so that opening any nav link
    immediately after a run never produces a 404, regardless of which flags
    were passed.  Files that already exist are never overwritten.

    Rules per page
    ──────────────
    listing.html          always generated by make_listing_modern; stub only if missing
    history.html          always generated by reconstruct_history; stub only if missing
    hardening_report.html always generated by detect_hardening; stub only if missing
    users.html            always generated by generate_users_report; stub only if missing
    secrets.html          generated when --secrets is used; stub only if missing
    sast_report.html      generated when --sast-scan is used; stub only if missing AND
                          only when sast.json exists on disk (scan was run at some point)
    infrastructure_report.html  generated when --extract-infra is used; stub only if missing
    bruteforce_report.html      generated when --bruteforce is used; stub only if missing
    """
    fd = os.path.join(outdir, "_files")

    def _missing(fname: str) -> bool:
        return not os.path.exists(os.path.join(outdir, fname))

    # secrets.html — empty stub
    if _missing("secrets.html"):
        generate_secrets_html([], os.path.join(outdir, "secrets.html"))

    # sast_report.html — stub only when the scan has been run (sast.json exists)
    sast_json = os.path.join(fd, "sast.json")
    if _missing("sast_report.html") and os.path.exists(sast_json):
        sast_data = _safe_load_json(sast_json, [])
        generate_sast_html(sast_data, os.path.join(outdir, "sast_report.html"))

    # bruteforce_report.html — stub when --bruteforce was used or data exists
    if _missing("bruteforce_report.html"):
        bf_json = os.path.join(fd, "bruteforce.json")
        if getattr(args, "bruteforce", False) or os.path.exists(bf_json):
            bf_data = _safe_load_json(bf_json, [])
            generate_bruteforce_report(bf_data, os.path.join(outdir, "bruteforce_report.html"))

    # infrastructure_report.html — stub when data exists
    if _missing("infrastructure_report.html"):
        infra_json = os.path.join(fd, "infrastructure.json")
        if os.path.exists(infra_json):
            infra_data = _safe_load_json(infra_json, [])
            generate_infrastructure_html(infra_data, os.path.join(outdir, "infrastructure_report.html"))


def generate_unified_report(outdir: str, base_url: str, args: Any) -> None:
    info("Generating Unified Dashboard (report.html)...")
    fd = os.path.join(outdir, "_files")
    abs_base = os.path.abspath(outdir).replace("\\", "/")

    hardening    = _safe_load_json(os.path.join(fd, "hardening_report.json"), {})
    misc         = _safe_load_json(os.path.join(fd, "misc_leaks.json"), [])
    packs        = _safe_load_json(os.path.join(fd, "packfiles.json"), [])
    bf_data      = _safe_load_json(os.path.join(fd, "bruteforce.json"), [])
    users_data   = _safe_load_json(os.path.join(fd, "users.json"), [])
    secrets_data = _safe_load_json(os.path.join(fd, "secrets.json"), [])
    infra_data   = _safe_load_json(os.path.join(fd, "infrastructure.json"), [])
    sast_data    = _safe_load_json(os.path.join(fd, "sast.json"), [])
    history_data = _safe_load_json(os.path.join(fd, "history.json"), {})
    commits      = history_data.get("commits", [])
    head_sha     = history_data.get("head", "N/A")
    try:
        listing_entries = load_dump_entries(os.path.join(fd, "dump.json"))
    except Exception:
        listing_entries = []
    try:
        stash_entries = load_dump_entries(os.path.join(fd, "stash.json"))
    except Exception:
        stash_entries = []

    # ── Hardening card ─────────────────────────────────────────────────────
    h_vuln = sum(1 for v in hardening.get("results", {}).values() if v.get("exposed"))
    h_rows = ""
    for k, v in hardening.get("results", {}).items():
        cls = "badge-red" if v.get("exposed") else "badge-green"
        lbl = "EXPOSED" if v.get("exposed") else "OK"
        h_rows += f'<tr><td class="mono" style="font-size:.8rem">{k}</td><td><span class="badge {cls}">{lbl}</span></td></tr>'

    hardening_card = f"""
<div class="card">
  <div class="card-header">
    <span>🛡 Hardening &amp; Config</span>
    <span class="badge {'badge-red' if h_vuln else 'badge-green'}">{h_vuln} failures</span>
  </div>
  <div class="card-body">
    <table>{h_rows}</table>
    <a href="hardening_report.html" class="btn btn-ghost w-full mt-2">Full Diagnostic →</a>
  </div>
</div>"""

    # ── History card ───────────────────────────────────────────────────────
    h_rows2 = ""
    for c in commits[:6]:
        is_s = c.get("is_stash")
        is_o = c.get("is_orphan")
        clr  = "var(--accent)" if is_s else ("var(--red)" if is_o else "var(--purple)")
        sha_lbl = "STASH" if is_s else (c.get("sha","")[:7] if not is_o else "REFLOG")
        msg = (c.get("message","").splitlines()[0][:55]).replace("<","&lt;") if c.get("message") else "—"
        date = str(c.get("date","")).split(" ")[0] or "—"
        badge = (f'<span class="badge badge-amber">STASH</span>' if is_s else
                 (f'<span class="badge badge-red">ORPHAN</span>' if is_o else
                  f'<span class="badge badge-muted">{date}</span>'))
        h_rows2 += f"""<tr>
          <td class="mono" style="color:{clr};font-weight:700">{sha_lbl}</td>
          <td class="dim" style="font-size:.82rem">{msg}</td>
          <td class="text-right">{badge}</td></tr>"""

    history_card = f"""
<div class="card">
  <div class="card-header">
    <span>⏳ Recent History</span>
    <span class="badge badge-blue">{len(commits)} commits</span>
  </div>
  <div class="card-body">
    <div class="muted mb-2" style="font-size:.8rem">HEAD: <span class="mono">{head_sha[:8] if head_sha else '—'}</span></div>
    <table>{h_rows2}</table>
    <a href="history.html" class="btn btn-ghost w-full mt-2">Explore Timeline →</a>
  </div>
</div>"""

    # ── Users card ─────────────────────────────────────────────────────────
    users_card = f"""
<div class="card">
  <div class="card-header">👤 Identities (OSINT)</div>
  <div class="card-body" style="text-align:center">
    <div class="stat-num">{len(users_data)}</div>
    <div class="stat-lbl">Identified Authors</div>
    <p class="muted mt-1" style="font-size:.82rem">Developers and emails extracted from history.</p>
    <a href="users.html" class="btn btn-ghost w-full mt-2">View User List →</a>
  </div>
</div>"""

    # ── Listing card ───────────────────────────────────────────────────────
    l_rows = ""
    for e in listing_entries[:8]:
        l_rows += f'<tr><td class="mono" style="font-size:.78rem;word-break:break-all">{e.get("path","")}</td><td class="text-right"><a href="{public_url(normalize_site_base(base_url), e.get("path",""))}" target="_blank" class="dim" style="font-size:.78rem">Remote ↗</a></td></tr>'

    listing_card = f"""
<div class="card">
  <div class="card-header">
    <span>📂 Files (.git Index)</span>
    <span class="badge badge-amber">{len(listing_entries)} files</span>
  </div>
  <div class="card-body">
    <table>{l_rows}</table>
    <p class="muted text-right mt-1" style="font-size:.75rem">+{max(0,len(listing_entries)-8)} more files</p>
    <a href="listing.html" class="btn btn-ghost w-full mt-2">Full Listing →</a>
  </div>
</div>"""

    # ── Stash section ──────────────────────────────────────────────────────
    stash_section = ""
    if stash_entries:
        stash_section = f"""
<div class="card mb-3" style="border-color:var(--accent);background:var(--accent-dim)">
  <div class="card-header" style="color:var(--accent)">
    <span>💾 Git Stash Recovered</span>
    <span class="badge badge-amber">High Priority</span>
  </div>
  <div class="card-body">
    <p style="font-size:.85rem;margin-bottom:.75rem">
      <strong>{len(stash_entries)} files</strong> with pending modifications detected.
    </p>
    <a href="history.html" class="btn btn-primary w-full">Investigate Changes in History →</a>
  </div>
</div>"""

    # ── Secrets section ────────────────────────────────────────────────────
    secrets_section = ""
    if secrets_data:
        s_rows = "".join(
            f'<tr><td><span class="badge badge-red">{s["type"]}</span></td>'
            f'<td class="dim" style="font-size:.8rem">{s["file"]}</td>'
            f'<td class="mono" style="font-size:.78rem;color:var(--red)">{s["match"][:60]}</td></tr>'
            for s in secrets_data[:5]
        )
        secrets_section = f"""
<div class="card mb-3" style="border-color:var(--red)">
  <div class="card-header" style="background:var(--red-dim);color:var(--red)">
    <span>&#x26A0;&#xFE0F; CRITICAL SECRETS DETECTED</span>
    <span class="badge badge-red">{len(secrets_data)}</span>
  </div>
  <div class="card-body">
    <table>{s_rows}</table>
    <a href="secrets.html" class="btn w-full mt-2"
       style="background:var(--red);color:#fff;border-color:var(--red);font-weight:600">
      View Secrets Report &#x2192;
    </a>
  </div>
</div>"""

    # ── SAST section ───────────────────────────────────────────────────────
    # The card is shown if and only if sast.json was written to disk, which
    # only happens when --sast-scan has actually been executed (either in this
    # run or a previous one). That way --report re-runs also show the card,
    # and targets that never ran --sast-scan show nothing.
    sast_json_exists = os.path.exists(os.path.join(fd, "sast.json"))
    sast_section = ""
    if sast_json_exists and sast_data:
        sast_errors   = sum(1 for f in sast_data if f.get("severity") == "ERROR")
        sast_warnings = sum(1 for f in sast_data if f.get("severity") == "WARNING")
        sast_rows = "".join(
            f'<tr>'
            f'<td><span class="badge '
            f'{"badge-red" if f.get("severity")=="ERROR" else "badge-amber" if f.get("severity")=="WARNING" else "badge-blue"}">'
            f'{f.get("severity","?")}</span></td>'
            f'<td class="mono" style="font-size:.78rem;color:var(--purple)">'
            f'{f.get("rule_short", f.get("rule_id",""))}</td>'
            f'<td class="dim" style="font-size:.8rem">{f.get("file","")}</td>'
            f'<td class="mono" style="font-size:.7rem">'
            f'{"line "+str(f.get("line")) if f.get("line") else ""}</td>'
            f'</tr>'
            for f in sast_data[:6]
        )
        sast_section = f"""
<div class="card mb-3" style="border-color:rgba(167,139,250,.45)">
  <div class="card-header" style="background:var(--purple-dim);color:var(--purple)">
    <span>&#x1F50D; SAST FINDINGS</span>
    <div class="flex gap-1">
      <span class="badge badge-red">{sast_errors} errors</span>
      <span class="badge badge-amber">{sast_warnings} warnings</span>
      <span class="badge badge-muted">{len(sast_data)} total</span>
    </div>
  </div>
  <div class="card-body">
    <table>{sast_rows}</table>
    <a href="sast_report.html" class="btn w-full mt-2"
       style="background:var(--purple);color:#fff;border-color:var(--purple);font-weight:600">
      View SAST Report &#x2192;
    </a>
  </div>
</div>"""
    elif sast_json_exists:
        # sast.json exists but is empty — scan ran and found nothing
        sast_section = """
<div class="card mb-3" style="border-color:rgba(167,139,250,.2)">
  <div class="card-header" style="background:var(--purple-dim);color:var(--purple)">
    <span>&#x1F50D; SAST FINDINGS</span>
    <span class="badge badge-green">Clean</span>
  </div>
  <div class="card-body">
    <p class="muted" style="font-size:.82rem">No vulnerabilities detected by Semgrep.</p>
    <a href="sast_report.html" class="btn btn-ghost w-full mt-2">View SAST Report &#x2192;</a>
  </div>
</div>"""

    # ── Brute-force section ────────────────────────────────────────────────
    bf_section = ""
    # Always generate the HTML file when --bruteforce was used so the nav
    # link never produces a 404, even if no files were found.
    if getattr(args, "bruteforce", False) or bf_data:
        generate_bruteforce_report(bf_data, os.path.join(outdir, "bruteforce_report.html"))
    if bf_data:
        bf_rows = "".join(
            f'<tr><td class="mono" style="font-size:.78rem">{f.get("filename","")}</td>'
            f'<td class="text-right"><span class="badge {"badge-green" if f.get("in_git") else "badge-muted"}">'
            f'{"VERSIONED" if f.get("in_git") else "LOCAL"}</span></td></tr>'
            for f in bf_data[:5]
        )
        bf_section = f"""
<div class="card mb-3">
  <div class="card-header">
    <span>🔨 Brute-Force Files</span>
    <span class="badge badge-blue">{len(bf_data)}</span>
  </div>
  <div class="card-body">
    <table>{bf_rows}</table>
    <a href="bruteforce_report.html" class="btn btn-ghost w-full mt-2">Full Brute-Force Report →</a>
  </div>
</div>"""

    # ── Misc leaks ─────────────────────────────────────────────────────────
    misc_content = '<p class="muted" style="font-size:.82rem">No additional leaks.</p>'
    if misc:
        misc_content = "<ul style='list-style:none;padding:0'>" + "".join(
            f'<li class="mb-1"><strong class="mono" style="font-size:.8rem">{m["type"].upper()}</strong>: '
            f'<a href="{m.get("report_file","_files/misc/"+m.get("dump_file",""))}" target="_blank">View Analysis →</a></li>'
            for m in misc
        ) + "</ul>"

    # ── Packfiles ──────────────────────────────────────────────────────────
    pack_content = '<p class="muted" style="font-size:.82rem">No packfiles detected.</p>'
    if packs:
        pack_content = "".join(
            f'<div class="mb-2" style="border-bottom:1px solid var(--border);padding-bottom:.5rem">'
            f'<div class="mono" style="font-size:.78rem;color:var(--text)">{p.get("name","")}</div>'
            f'<div class="dim" style="font-size:.75rem;margin-top:.2rem">Status: {p.get("status","")} | Files: {p.get("count",0)}</div>'
            f'</div>'
            for p in packs
        )

    # ── Infrastructure ─────────────────────────────────────────────────────
    if not args.extract_infra:
        infra_content = '<p class="muted" style="font-size:.82rem">Use --extract-infra for network mapping.</p>'
    elif not infra_data:
        infra_content = '<p style="color:var(--accent);font-size:.82rem">No assets extracted. (Verify that dump was performed)</p>'
    else:
        i_rows = "".join(
            f'<tr><td><span class="badge badge-blue" style="font-size:.68rem">{item["category"]}</span></td>'
            f'<td class="mono" style="font-size:.78rem;color:var(--purple)">{item["value"]}</td>'
            f'<td class="dim" style="font-size:.75rem">{item["file"]}</td></tr>'
            for item in infra_data[:8]
        )
        infra_content = f'<table>{i_rows}</table><a href="infrastructure_report.html" class="btn btn-ghost w-full mt-2">Open Infrastructure Map ({len(infra_data)}) →</a>'

    html = _html_head("Dashboard") + _topbar("Dashboard", outdir) + f"""
<div class="container">
  <div class="flex items-center mb-3" style="justify-content:space-between">
    <div>
      <h2 style="font-weight:700">Analysis Dashboard</h2>
      <a href="{base_url}" target="_blank" class="muted" style="font-size:.82rem">{base_url}</a>
    </div>
  </div>

  {secrets_section}
  {sast_section}
  {stash_section}

  <div class="grid-2 mb-3">
    <div>{hardening_card}<div style="margin-top:1rem">{history_card}</div></div>
    <div>{users_card}<div style="margin-top:1rem">{listing_card}</div></div>
  </div>

  <div class="card mb-3">
    <div class="card-header">
      <span>&#x1F310; Infrastructure Map</span>
      <span class="badge badge-blue">{len(infra_data)}</span>
    </div>
    <div class="card-body">{infra_content}</div>
  </div>

  {bf_section}

  <div class="grid-2">
    <div class="card">
      <div class="card-header">
        <span>📦 Packfiles</span>
        <span class="badge badge-muted">{len(packs)}</span>
      </div>
      <div class="card-body">{pack_content}</div>
    </div>
    <div class="card">
      <div class="card-header">
        <span>⚠️ Other Leaks (--full-scan)</span>
        <span class="badge badge-muted">{len(misc)}</span>
      </div>
      <div class="card-body">{misc_content}</div>
    </div>
  </div>
</div>
<script>
const ABS_BASE="{abs_base}";
const isServed=window.location.protocol.startsWith('http');
function handlePackAction(rel,btn){{
  if(isServed){{window.open(rel+'/','_blank')}}
  else{{
    const p=ABS_BASE+'/'+rel;
    navigator.clipboard.writeText(p).then(()=>{{
      const orig=btn.textContent;btn.textContent='Copied!';
      setTimeout(()=>btn.textContent=orig,2000);
    }});
  }}
}}
document.addEventListener('DOMContentLoaded',()=>{{
  document.querySelectorAll('.btn-pack-action').forEach(b=>{{
    b.textContent=isServed?'Open Folder ↗':'Copy Local Path';
  }});
}});
</script>
""" + _html_foot()

    # ── Ensure every nav-linked page always exists ─────────────────────────
    # Generating stubs for pages that may not have been produced yet prevents
    # 404 errors when the user navigates via the top bar.  Each generator is
    # called only if the target file is missing; existing files are untouched.
    _ensure_html_stubs(outdir, args)

    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)
    success(f"Unified dashboard generated: {os.path.join(outdir, 'report.html')}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 24 — SAST SCANNER (Semgrep)
# ══════════════════════════════════════════════════════════════════════════════

_SAST_SEV_ORDER: Dict[str, int] = {"ERROR": 0, "WARNING": 1, "INFO": 2}

_SAST_RULE_META: Dict[str, Dict[str, str]] = {
    "sql":           {"owasp": "A03 - Injection",                 "cwe": "CWE-89"},
    "xss":           {"owasp": "A03 - Injection",                 "cwe": "CWE-79"},
    "xxe":           {"owasp": "A05 - Security Misconfiguration", "cwe": "CWE-611"},
    "path-traversal":{"owasp": "A01 - Broken Access Control",     "cwe": "CWE-22"},
    "traversal":     {"owasp": "A01 - Broken Access Control",     "cwe": "CWE-22"},
    "command":       {"owasp": "A03 - Injection",                 "cwe": "CWE-78"},
    "exec":          {"owasp": "A03 - Injection",                 "cwe": "CWE-78"},
    "eval":          {"owasp": "A03 - Injection",                 "cwe": "CWE-94"},
    "unserializ":    {"owasp": "A08 - Insecure Deserialization",  "cwe": "CWE-502"},
    "deserializ":    {"owasp": "A08 - Insecure Deserialization",  "cwe": "CWE-502"},
    "hardcoded":     {"owasp": "A07 - Identification Failures",   "cwe": "CWE-798"},
    "crypto":        {"owasp": "A02 - Cryptographic Failures",    "cwe": "CWE-327"},
    "weak":          {"owasp": "A02 - Cryptographic Failures",    "cwe": "CWE-326"},
    "redirect":      {"owasp": "A01 - Broken Access Control",     "cwe": "CWE-601"},
    "open-redirect": {"owasp": "A01 - Broken Access Control",     "cwe": "CWE-601"},
    "ssrf":          {"owasp": "A10 - SSRF",                      "cwe": "CWE-918"},
    "csrf":          {"owasp": "A01 - Broken Access Control",     "cwe": "CWE-352"},
    "injection":     {"owasp": "A03 - Injection",                 "cwe": "CWE-74"},
    "ldap":          {"owasp": "A03 - Injection",                 "cwe": "CWE-90"},
    "nosql":         {"owasp": "A03 - Injection",                 "cwe": "CWE-943"},
    "taint":         {"owasp": "A03 - Injection",                 "cwe": "CWE-74"},
    "format-string": {"owasp": "A03 - Injection",                 "cwe": "CWE-134"},
}

_SAST_SOURCE_EXTS = {
    ".php", ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx", ".py", ".rb", ".java",
    ".go", ".cs", ".cpp", ".c", ".vue",
    ".svelte", ".sh", ".bash",
}

_SAST_SKIP_DIRS = {
    "__tmp", ".git", "node_modules",
    "vendor", ".venv", "venv", "__pycache__",
}

_SAST_SKIP_FILES = {
    "report.html", "listing.html", "history.html", "users.html",
    "secrets.html", "hardening_report.html", "infrastructure_report.html",
    "bruteforce_report.html", "sast_report.html", "stash_report.html",
    "index.html", "packfiles.json", "misc_leaks.json", "hardening_report.json",
    "history.json", "users.json", "dump.json", "stash.json",
    "secrets.json", "intelligence.json", "infrastructure.json",
    "bruteforce.json", "sast.json",
}


def _enrich_sast(rule_id: str) -> Dict[str, str]:
    rid = rule_id.lower()
    for key, meta in _SAST_RULE_META.items():
        if key in rid:
            return meta
    return {"owasp": "-", "cwe": "-"}


def run_sast_scan(outdir: str, custom_rules: Optional[str] = None) -> List[Dict[str, Any]]:
    print()
    warn("=" * 62)
    warn("  SAST SCAN STARTED  --  this may take several minutes")
    warn("  depending on the number of recovered files and the")
    warn("  rule set selected.  Please be patient.")
    warn("=" * 62)
    print()

    # Verify Semgrep is installed
    try:
        ver = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        if ver.returncode != 0:
            raise FileNotFoundError
        info(f"Semgrep detected: {ver.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        fail("Semgrep not found. Install it with:  pip install semgrep")
        fail("Then re-run with --sast-scan to perform the analysis.")
        return []

    # ── Collect scan targets ──────────────────────────────────────────────────
    # Strategy: walk the entire outdir tree, collect every source file we find,
    # and pass them to Semgrep as individual paths.  This covers:
    #   • reconstructed blobs (committed under their original directory names)
    #   • stash_restored/  (from recover_stash_content)
    #   • _files/misc/     (e.g. .env files fetched by full-scan)
    #   • _files/bruteforce/ (files downloaded by brute-force)
    #   • extracted_packs/   (unpacked packfile objects)
    #   • any other subdirectory that may contain source code
    # We explicitly skip our own generated HTML/JSON report artefacts and
    # binary/noise extensions.

    scan_targets: List[str] = []
    for root, dirs, files in os.walk(outdir):
        # Prune dirs we never want to descend into
        dirs[:] = [d for d in dirs if d not in _SAST_SKIP_DIRS]
        for fname in files:
            if fname in _SAST_SKIP_FILES:
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SAST_SOURCE_EXTS:
                scan_targets.append(os.path.join(root, fname))

    if not scan_targets:
        warn("SAST: No source files found to scan in the output directory.")
        warn("SAST: Try running --reconstruct or --default first to recover source files.")
        # Still generate an empty report so the page is reachable
        generate_sast_html([], os.path.join(outdir, "sast_report.html"))
        files_dir = os.path.join(outdir, "_files")
        os.makedirs(files_dir, exist_ok=True)
        with open(os.path.join(files_dir, "sast.json"), "w", encoding="utf-8") as fh:
            json.dump([], fh)
        return []

    info(f"SAST: {len(scan_targets)} source file(s) queued for analysis")

    # Choose rule-set
    if custom_rules:
        if os.path.isfile(custom_rules):
            rule_args = ["--config", custom_rules]
            info(f"SAST: custom rules loaded from {custom_rules}")
        else:
            warn(f"SAST: custom rules file not found ({custom_rules}). Falling back to 'auto'.")
            rule_args = ["--config", "auto"]
    else:
        rule_args = ["--config", "auto"]
        info("SAST: using Semgrep 'auto' ruleset (requires internet on first run).")

    # Execute Semgrep
    cmd = [
        "semgrep", *rule_args,
        "--json", "--no-git-ignore", "--quiet",
        "--timeout", "60", "--max-memory", "512",
        *scan_targets,
    ]
    info(f"SAST: running semgrep {' '.join(rule_args)} on {len(scan_targets)} path(s) ...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        warn("SAST: Semgrep exceeded the 10-minute timeout.")
        generate_sast_html([], os.path.join(outdir, "sast_report.html"))
        with open(os.path.join(outdir, "_files", "sast.json"), "w", encoding="utf-8") as fh:
            json.dump([], fh)
        return []
    except Exception as exc:
        warn(f"SAST: subprocess error -- {exc}")
        generate_sast_html([], os.path.join(outdir, "sast_report.html"))
        with open(os.path.join(outdir, "_files", "sast.json"), "w", encoding="utf-8") as fh:
            json.dump([], fh)
        return []

    raw = proc.stdout.strip()
    if not raw:
        info("SAST: Semgrep produced no JSON output (no findings or error).")
        if proc.stderr:
            warn(f"SAST stderr: {proc.stderr[:400]}")
        generate_sast_html([], os.path.join(outdir, "sast_report.html"))
        files_dir = os.path.join(outdir, "_files")
        os.makedirs(files_dir, exist_ok=True)
        with open(os.path.join(files_dir, "sast.json"), "w", encoding="utf-8") as fh:
            json.dump([], fh)
        return []

    try:
        semgrep_out = json.loads(raw)
    except json.JSONDecodeError as exc:
        warn(f"SAST: could not parse Semgrep JSON: {exc}")
        generate_sast_html([], os.path.join(outdir, "sast_report.html"))
        with open(os.path.join(outdir, "_files", "sast.json"), "w", encoding="utf-8") as fh:
            json.dump([], fh)
        return []

    # Normalise findings
    findings: List[Dict[str, Any]] = []
    for r in semgrep_out.get("results", []):
        rule_id   = r.get("check_id", "unknown")
        extra     = r.get("extra", {})
        severity  = extra.get("severity", "WARNING").upper()
        message   = extra.get("message", "").strip()
        filepath  = r.get("path", "")
        rel_path  = os.path.relpath(filepath, outdir) if filepath else filepath
        line_num  = r.get("start", {}).get("line", 0)
        code_ctx  = extra.get("lines", "").strip()
        meta      = _enrich_sast(rule_id)
        rule_short = rule_id.split(".")[-1] if "." in rule_id else rule_id
        findings.append({
            "rule_id":    rule_id,
            "rule_short": rule_short,
            "severity":   severity,
            "message":    message,
            "file":       rel_path,
            "line":       line_num,
            "context":    code_ctx,
            "owasp":      meta["owasp"],
            "cwe":        meta["cwe"],
        })

    findings.sort(key=lambda x: (
        _SAST_SEV_ORDER.get(x["severity"], 99), x["file"], x["line"]
    ))

    files_dir = os.path.join(outdir, "_files")
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, "sast.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)

    errors   = sum(1 for f in findings if f["severity"] == "ERROR")
    warnings = sum(1 for f in findings if f["severity"] == "WARNING")
    inf_cnt  = len(findings) - errors - warnings
    success(f"SAST complete: {len(findings)} finding(s) -- {errors} error(s), {warnings} warning(s), {inf_cnt} info")
    generate_sast_html(findings, os.path.join(outdir, "sast_report.html"))
    return findings


def generate_sast_html(findings: List[Dict[str, Any]], out_html: str) -> None:
    data_json = (
        json.dumps(findings, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    errors   = sum(1 for f in findings if f["severity"] == "ERROR")
    warnings = sum(1 for f in findings if f["severity"] == "WARNING")
    inf_cnt  = len(findings) - errors - warnings

    extra_css = """
    .sast-card{border:1px solid var(--border);border-radius:var(--radius);
      overflow:hidden;margin-bottom:.55rem;transition:border-color .15s}
    .sast-card:hover{border-color:var(--border-hl)}
    .sast-card.sev-error  {border-left:3px solid var(--red)}
    .sast-card.sev-warning{border-left:3px solid var(--accent)}
    .sast-card.sev-info   {border-left:3px solid var(--blue)}
    .sast-hdr{padding:.5rem 1rem;background:rgba(255,255,255,.02);
      border-bottom:1px solid var(--border);
      display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap}
    .sast-meta{display:flex;gap:.35rem;flex-wrap:wrap;align-items:center}
    .sast-body{padding:.6rem 1rem}
    .sast-msg{font-size:.82rem;color:var(--text);margin-bottom:.35rem}
    .sast-rule{color:var(--purple);font-weight:700}
    """

    html = _html_head("SAST Report", extra_css) + _topbar("SAST", os.path.dirname(out_html)) + f"""
<div class="container">
  <div class="card mb-3" style="border-color:rgba(167,139,250,.35);background:var(--purple-dim)">
    <div class="card-body flex items-center gap-2" style="justify-content:space-between;flex-wrap:wrap">
      <div class="flex items-center gap-2">
        <div class="pulse" style="background:var(--purple)"></div>
        <div>
          <div style="font-size:1rem;font-weight:700;color:var(--purple)">SAST &#x2014; Static Analysis Results</div>
          <div class="muted" style="font-size:.8rem">Semgrep scan of recovered source code</div>
        </div>
      </div>
      <div class="flex gap-2" style="flex-wrap:wrap">
        <span class="badge badge-red">{errors} errors</span>
        <span class="badge badge-amber">{warnings} warnings</span>
        <span class="badge badge-blue">{inf_cnt} info</span>
        <span class="badge badge-muted">{len(findings)} total</span>
      </div>
    </div>
  </div>
  <div class="flex gap-2 mb-3" style="flex-wrap:wrap">
    <a href="report.html" class="btn btn-ghost">&#x2190; Back</a>
    <div class="search-wrap" style="flex:1;min-width:180px;max-width:520px">
      <span class="search-icon">&#x2315;</span>
      <input id="q" type="text" placeholder="Filter by rule, file, message, CWE&#x2026;">
    </div>
    <select id="sev-sel" class="btn btn-ghost" style="cursor:pointer">
      <option value="">All severities</option>
      <option value="ERROR">ERROR</option>
      <option value="WARNING">WARNING</option>
      <option value="INFO">INFO</option>
    </select>
  </div>
  <div id="sast-container"></div>
  <div class="flex items-center"
       style="justify-content:space-between;padding:.75rem 0;color:var(--text-muted);font-size:.82rem">
    <span id="pg-info">Loading&#x2026;</span>
    <div class="pgn" id="pgn"></div>
  </div>
</div>
<script>
const DATA={data_json};
let filtered=DATA.slice(),cur=1;const PS=30;
const cont=document.getElementById('sast-container');
const pgInfo=document.getElementById('pg-info');
const pgn=document.getElementById('pgn');
function esc(t){{if(t==null)return'';return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}}
const SEV_BADGE={{'ERROR':'badge-red','WARNING':'badge-amber','INFO':'badge-blue'}};
const SEV_CARD={{'ERROR':'sev-error','WARNING':'sev-warning','INFO':'sev-info'}};
function render(){{
  const tot=filtered.length,tp=Math.max(1,Math.ceil(tot/PS));
  if(cur>tp)cur=tp;if(cur<1)cur=1;
  const sl=filtered.slice((cur-1)*PS,cur*PS);
  cont.innerHTML='';
  if(!tot){{
    cont.innerHTML='<p class="muted" style="padding:2rem;text-align:center">No findings match the current filter.</p>';
  }}
  sl.forEach(item=>{{
    const bCls=SEV_BADGE[item.severity]||'badge-muted';
    const cCls=SEV_CARD[item.severity]||'';
    const cweHtml=item.cwe&&item.cwe!=='-'?`<span class="badge badge-purple" style="font-size:.7rem">${{esc(item.cwe)}}</span>`:'';
    const owaspHtml=item.owasp&&item.owasp!=='-'?`<span class="badge badge-muted" style="font-size:.68rem">${{esc(item.owasp)}}</span>`:'';
    const lineHtml=item.line?`<span class="badge badge-muted" style="font-size:.7rem">line ${{item.line}}</span>`:'';
    const ctxHtml=item.context?`<div class="code-block" style="font-size:.75rem;white-space:pre-wrap;margin:.35rem 0">${{esc(item.context)}}</div>`:'';
    const d=document.createElement('div');
    d.className=`sast-card ${{cCls}}`;
    d.innerHTML=`
      <div class="sast-hdr">
        <div class="sast-meta">
          <span class="badge ${{bCls}}">${{esc(item.severity)}}</span>
          <span class="mono" style="font-size:.78rem;color:var(--text)">${{esc(item.file)}}</span>
          ${{lineHtml}}
        </div>
        <div class="sast-meta">${{cweHtml}}${{owaspHtml}}</div>
      </div>
      <div class="sast-body">
        <div class="sast-msg">
          <span class="mono sast-rule">${{esc(item.rule_short)}}</span> &mdash; ${{esc(item.message)}}
        </div>
        ${{ctxHtml}}
        <div class="flex gap-1 mt-1">
          <button class="btn btn-ghost" style="font-size:.72rem;padding:2px 7px"
            onclick="navigator.clipboard.writeText('${{esc(item.file)}}')">&#x1F4C2; Copy path</button>
          <button class="btn btn-ghost" style="font-size:.72rem;padding:2px 7px"
            onclick="navigator.clipboard.writeText('${{esc(item.rule_id)}}')">&#x1F4CB; Copy rule ID</button>
        </div>
      </div>`;
    cont.appendChild(d);
  }});
  pgInfo.textContent=`Showing ${{tot?((cur-1)*PS+1):0}}\u2013${{Math.min(cur*PS,tot)}} of ${{tot}} finding${{tot===1?'':'s'}}`;
  pgn.innerHTML='';
  const pb=document.createElement('button');pb.textContent='\u2039';pb.disabled=(cur===1);
  pb.onclick=()=>{{cur--;render()}};pgn.appendChild(pb);
  const nb=document.createElement('button');nb.textContent='\u203a';nb.disabled=(cur===tp);
  nb.onclick=()=>{{cur++;render()}};pgn.appendChild(nb);
}}
function applyFilters(){{
  const q=(document.getElementById('q').value||'').toLowerCase();
  const sev=(document.getElementById('sev-sel').value||'').toUpperCase();
  filtered=DATA.filter(f=>{{
    if(sev&&f.severity!==sev)return false;
    if(!q)return true;
    return(f.rule_id||'').toLowerCase().includes(q)
        ||(f.file||'').toLowerCase().includes(q)
        ||(f.message||'').toLowerCase().includes(q)
        ||(f.cwe||'').toLowerCase().includes(q)
        ||(f.owasp||'').toLowerCase().includes(q)
        ||(f.context||'').toLowerCase().includes(q);
  }});
  cur=1;render();
}}
document.getElementById('q').addEventListener('input',applyFilters);
document.getElementById('sev-sel').addEventListener('change',applyFilters);
render();
</script>
""" + _html_foot()
    try:
        with open(out_html, "w", encoding="utf-8") as fh:
            fh.write(html)
        success(f"SAST report saved: {out_html}")
    except Exception as exc:
        warn(f"Error saving SAST report: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 25 — MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def process_pipeline(
    base_url: str,
    output_dir: str,
    args: Any,
    proxies: Optional[Dict] = None,
) -> None:
    info(f"=== Starting Pipeline: {base_url} ===")
    info(f"Output: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    index_json = os.path.join(output_dir, "_files", args.output_index)

    # ── 1. Obtain index ────────────────────────────────────────────────────
    raw_index_path = os.path.join(output_dir, "_files", "raw_index")
    if not os.path.exists(raw_index_path):
        print("[*] Downloading .git/index...")
        ok_idx, _ = http_get_to_file(
            base_url.rstrip("/") + "/.git/index", raw_index_path, proxies=proxies
        )
    else:
        print("[*] Using existing local .git/index.")
        ok_idx = True

    has_index = False
    if ok_idx:
        try:
            index_to_json(raw_index_path, index_json)
            has_index = True
            print("[+] Git index analyzed successfully.")
        except Exception as e:
            warn(f"Warning: .git/index invalid or corrupted ({e}).")

    if not has_index:
        info("Index unavailable or invalid. Activating Blind/Crawling mode...")
        blind_recovery(base_url, output_dir, args.output_index, proxies=proxies)

    # ── 2. Hardening & intelligence ────────────────────────────────────────
    detect_hardening(base_url, output_dir, proxies=proxies)
    gather_intelligence(base_url, output_dir, proxies=proxies)

    stash_sha = recover_stash_content(
        base_url, output_dir,
        workers=args.workers, proxies=proxies, show_diff=args.show_diff,
    )
    if stash_sha:
        reconstruct_all(
            os.path.join(output_dir, "_files", "stash.json"),
            base_url,
            os.path.join(output_dir, "stash_restored"),
            workers=args.workers,
        )
        generate_stash_html(
            os.path.join(output_dir, "_files", "stash.json"),
            output_dir,
        )

    if args.full_scan:
        detect_misc_leaks(base_url, output_dir, proxies=proxies)

    if args.bruteforce:
        brute_force_scan(base_url, output_dir,
                         wordlist_path=args.wordlist, proxies=proxies)

    # ── 3. Reports & reconstruction ────────────────────────────────────────
    if args.packfile:
        handle_packfiles(args.packfile, base_url, output_dir, proxies=proxies)

    make_listing_modern(index_json, base_url, output_dir)
    reconstruct_history(
        index_json, base_url, output_dir,
        max_commits=args.max_commits,
        full_history=args.full_history,
        show_diff=args.show_diff,
        workers=args.workers,
        proxies=proxies,
    )

    if args.secrets:
        scan_for_secrets(output_dir)

    if args.sast_scan:
        run_sast_scan(output_dir, custom_rules=getattr(args, "sast_rules", None))

    if args.extract_infra:
        extract_infrastructure(output_dir, args)

    check_ds_store_exposure(base_url, output_dir, proxies=proxies)
    generate_unified_report(output_dir, base_url, args)
    success(f"Pipeline complete for {base_url}")
    print("-" * 60)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 26 — CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print(r"""
  _____ _ _   _            _    ______            _
 / ____(_) | | |          | |  |  ____|          | |
| |  __ _| |_| | ___  __ _| | _| |__  __  ___ __ | | ___  _ __ ___ _ __
| | |_ | | __| |/ _ \/ _` | |/ /  __| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|
| |__| | | |_| |  __/ (_| |   <| |____ >  <| |_) | | (_) | | |  __/ |
 \_____|_|\__|_|\___|\__,_|_|\_\______/_/\_\ .__/|_|\___/|_|  \___|_|
                                           | |
                                           |_|
""")
    p = argparse.ArgumentParser(
        prog="git_leak.py",
        description="Git Leak Explorer — Forensic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("base", nargs="?",
                   help="Target base URL (e.g. http://site.com/.git/ or site.com)")
    p.add_argument("--output-index",    default="dump.json",
                   help="Output filename for JSON index")
    p.add_argument("--output-dir",      default="./repo",
                   help="Output directory (root)")
    p.add_argument("--serve-dir",       nargs="?",
                   help="Specific directory to serve over HTTP")
    p.add_argument("--default",         action="store_true",
                   help="Run the default pipeline")
    p.add_argument("--report",          action="store_true",
                   help="Generate only the final unified report")
    p.add_argument("--parse-index",     action="store_true",
                   help="Only downloads and converts .git/index")
    p.add_argument("--blind",           action="store_true",
                   help="Enable blind mode")
    p.add_argument("--list",            action="store_true",
                   help="Generate listing.html")
    p.add_argument("--reconstruct",     action="store_true",
                   help="Reconstruct objects from dump.json")
    p.add_argument("--reconstruct-history", action="store_true",
                   help="Reconstruct commit history")
    p.add_argument("--max-commits",     type=int, default=200,
                   help="Commit limit")
    p.add_argument("--ignore-missing",  action="store_true",
                   help="Ignore missing objects")
    p.add_argument("--strict",          action="store_true",
                   help="Abort on critical errors")
    p.add_argument("--sha1",
                   help="Download a single object by SHA1 hash")
    p.add_argument("--detect-hardening", action="store_true",
                   help="Check .git exposure")
    p.add_argument("--packfile",        choices=["list", "download", "download-unpack"],
                   help="Manage .pack files")
    p.add_argument("--serve",           action="store_true",
                   help="Start web server at the end")
    p.add_argument("--workers",         type=int, default=10,
                   help="Parallel threads")
    p.add_argument("--scan",
                   help="File with URL list for full scan")
    p.add_argument("--check-public",    action="store_true",
                   help="Check HEAD request")
    p.add_argument("--full-history",    action="store_true",
                   help="Full history scan (slow)")
    p.add_argument("--full-scan",       action="store_true",
                   help="Run full leak verification (Brute-Force, Misc)")
    p.add_argument("--bruteforce",      action="store_true",
                   help="Enable common file recovery via brute force")
    p.add_argument("--wordlist",
                   help="Path to custom wordlist (Brute-Force)")
    p.add_argument("--proxy",
                   help="Proxy URL (e.g. http://127.0.0.1:8080 or socks5h://127.0.0.1:9150)")
    p.add_argument("--no-random-agent", action="store_true",
                   help="Disable User-Agent rotation (use a fixed one)")
    p.add_argument("--secrets",         action="store_true",
                   help="Run regex/entropy scanner for credentials")
    p.add_argument("--sast-scan",       action="store_true",
                   help="Run SAST (Semgrep) on recovered source files")
    p.add_argument("--sast-rules",
                   help="Path to a local Semgrep YAML rule file (optional; uses 'auto' if omitted)")
    p.add_argument("--show-diff",       action="store_true",
                   help="Download and display code diffs in history (VERY SLOW)")
    p.add_argument("--local",           type=str,
                   help="Full path to local project folder (e.g. /home/user/app)")
    p.add_argument("--extract-infra",   action="store_true",
                   help="Extract IPs, URLs and infrastructure endpoints")
    args = p.parse_args()

    # ── Global configuration ───────────────────────────────────────────────
    global USE_RANDOM_AGENT
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    USE_RANDOM_AGENT = not args.no_random_agent
    if USE_RANDOM_AGENT:
        info("User-Agent rotation: ENABLED")

    # ── Mode 1: Serve only (no scan) ───────────────────────────────────────
    if args.serve and not args.base and not args.scan and not args.local:
        target_path = (args.serve_dir if args.serve_dir else args.output_dir)
        if not os.path.exists(target_path):
            fail(f"Directory not found to serve: {target_path}")
            return
        open_file = "index.html" if os.path.exists(os.path.join(target_path, "index.html")) else "report.html"
        serve_dir(target_path, open_file=open_file)
        return

    # ── Mode 2: Target preparation ────────────────────────────────────────
    targets: List[str] = []
    if args.local:
        targets = [normalize_url(args.local)]
        info(f"Local-Scan mode: {targets[0]}")
    elif args.scan:
        if not os.path.exists(args.scan):
            fail(f"Target list file not found: {args.scan}")
            return
        try:
            with open(args.scan, "r", encoding="utf-8") as f:
                targets = [
                    normalize_url(l.strip())
                    for l in f if l.strip() and not l.startswith("#")
                ]
            info(f"Multi-Scan mode: {len(targets)} targets loaded.")
        except Exception as e:
            fail(f"Error reading list: {e}")
            return
    elif args.base:
        targets = [normalize_url(args.base)]
        info(f"Single-Target mode: {targets[0]}")
    else:
        p.print_help()
        print("\n[!] Error: A URL or --scan <file> is required.")
        return

    # ── Processing loop ────────────────────────────────────────────────────
    master_results: List[Dict] = []
    for i, target_url in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{'=' * 60}")
            print(f"[*] PROCESSING TARGET [{i}/{len(targets)}]: {target_url}")
            print(f"{'=' * 60}")
        folder_name  = safe_folder_name(target_url)
        target_outdir = os.path.join(args.output_dir, folder_name)
        os.makedirs(target_outdir, exist_ok=True)
        try:
            if args.detect_hardening:
                detect_hardening(target_url, target_outdir, proxies=proxies)
            elif args.blind:
                blind_recovery(target_url, target_outdir, args.output_index, proxies=proxies)
            elif args.sha1:
                recover_one_sha(target_url, args.sha1, target_outdir, proxies=proxies)
            elif args.parse_index:
                tmp_idx = os.path.join(target_outdir, "_files", "raw_index")
                os.makedirs(os.path.dirname(tmp_idx), exist_ok=True)
                http_get_to_file(target_url + "/.git/index", tmp_idx, proxies=proxies)
                index_to_json(tmp_idx, os.path.join(target_outdir, "_files", args.output_index))
            elif args.reconstruct_history:
                reconstruct_history(
                    os.path.join(target_outdir, "_files", args.output_index),
                    target_url, target_outdir,
                    max_commits=args.max_commits,
                    full_history=args.full_history,
                    show_diff=args.show_diff,
                    proxies=proxies,
                    workers=args.workers,
                )
            else:
                process_pipeline(target_url, target_outdir, args, proxies=proxies)

            # Collect stats
            stats = {
                "target": target_url, "folder_name": folder_name,
                "secrets_count": 0, "files_count": 0, "vuln_count": 0,
            }
            try:
                s = json.load(open(os.path.join(target_outdir, "_files", "secrets.json")))
                stats["secrets_count"] = len(s)
            except Exception:
                pass
            try:
                d = load_dump_entries(os.path.join(target_outdir, "_files", "dump.json"))
                stats["files_count"] = len(d)
            except Exception:
                pass
            try:
                h = json.load(open(os.path.join(target_outdir, "_files", "hardening_report.json")))
                stats["vuln_count"] = sum(
                    1 for v in h.get("results", {}).values() if v.get("exposed")
                )
            except Exception:
                pass
            master_results.append(stats)

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            sys.exit(0)
        except Exception as e:
            fail(f"Error processing {target_url}: {e}")
            continue

    # ── Final post-processing ──────────────────────────────────────────────
    generate_master_dashboard(args.output_dir, master_results)

    if args.serve:
        print("\n" + "=" * 60)
        info("Starting web visualisation...")
        if len(targets) > 1:
            serve_dir(args.output_dir, open_file="index.html")
        elif len(targets) == 1 and master_results:
            fld = master_results[0]["folder_name"]
            serve_dir(os.path.join(args.output_dir, fld), open_file="report.html")
    else:
        success("Processing complete!")
        try:
            if len(targets) > 1:
                print(f"Master report: {os.path.join(args.output_dir, 'index.html')}")
            elif targets and master_results:
                fld = master_results[0]["folder_name"]
                print(f"Report: {os.path.join(args.output_dir, fld, 'report.html')}")
        except IndexError:
            fail("Results list is empty. Verify that the target is valid.")


if __name__ == "__main__":
    main()