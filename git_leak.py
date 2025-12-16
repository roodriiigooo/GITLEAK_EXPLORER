#!/usr/bin/env python3
"""
git_leak.py — Git Leak Explorer
Ferramenta avançada para recuperação forense e análise de repositórios Git expostos.

Funcionalidades Principais:
 - Recuperação via Index ou Blind Mode (Crawling)
 - Reconstrução inteligente de arquivos e estrutura de diretórios
 - Análise de histórico de commits (Metadados + Arquivos)
 - Detecção de Hardening e outros vazamentos (SVN, HG, Env, DS_Store)
 - Geração de relatórios técnicos detalhados e interface visual

Uso: python git_leak.py <URL> [OPÇÕES]
Exemplo: python git_leak.py http://alvo.com --full-scan

Principais funcionalidades implementadas:
 - --parse-index         : baixa .git/index e converte para JSON
 - --blind               : Blind mode: Rastrear commits/árvores quando .git/index está ausente/403
 - --reconstruct         : Baixa os blobs do dump.json e reconstrói o diretório .git/objects localmente.
 - --list                : gera listing.html (UI simplificada) dos arquivos encontrados no indice, com links
 - --serve               : abre um servidor http para visualização dos relatórios
 - --sha1                : baixa um objeto único pelo SHA
 - --reconstruct-history : reconstrói cadeia de commits somente como interface do usuário (history.json + history.html)
 - --detect-hardening    : verificações de exposição e gera os arquivos hardening_report.json e hardening_report.html.
 - --packfile [MODE]     : manuseio de packfiles (modes: list, download, download-unpack)
 - --scan                : roda scan em multiplos albos em busca de .git/HEAD exposure
 - --default             : roda parse-index, detect-hardening, packfile(list), list, reconstruct-history e serve
 - --full-history        : analisa árvore de arquivos completa de TODOS os commits (lento)
 - --full-scan           : executa verificação completa de vazamentos (SVN, HG, Env, DS_Store)
 - --report              : gera apenas o relatório final (report.html)
 - --bruteforce          : ativa a tentativa de recuperação de arquivos comuns via força bruta
 - --wordlist            : caminho para wordlist (Brute-Force) personalizada
 - --proxy               : URL do Proxy (ex: http://127.0.0.1:8080 para Burp/ZAP ou socks5h://127.0.0.1:9150 para rede Tor) 
 - options: --max-commits, --ignore-missing, --strict, --workers, --output-index, --output-dir, --serve-dir
 

 - Todos os arquivos de saída são armazenados no diretório externo fornecido: arquivos HTML na raiz, arquivos JSON/outros arquivos em outdir/_files.

"""

from __future__ import annotations
import os
import sys
import json
import argparse
import requests
import urllib3
import shutil
import struct
import zlib
import subprocess
import re
import hashlib
import random
try:
    from ds_store import DSStore
    HAS_DS_STORE_LIB = True
except ImportError:
    HAS_DS_STORE_LIB = False
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone


#  ssl - Disable warn
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------
# Logging helpers
# ---------------------------
def info(msg: str): print(f"[+] {msg}")


def success(msg: str): print(f"[✔] {msg}")


def ok(msg: str): print(f"[✔] {msg}")


def warn(msg: str): print(f"[!] {msg}")


def fail(msg: str): print(f"[❌] {msg}")


# ---------------------------
# Network helpers
# ---------------------------
DEFAULT_TIMEOUT = 15
USE_RANDOM_AGENT = True

USER_AGENTS = [
    # --- WINDOWS (Chrome) ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    
    # --- WINDOWS (Edge) ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    
    # --- WINDOWS (Firefox) ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    
    # --- MAC OS (Chrome & Safari) ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    
    # --- MAC OS (Firefox) ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    
    # --- LINUX (X11) ---
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    
    # --- LEGACY ---
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/88.0.4324.96 Chrome/88.0.4324.96 Safari/537.36"
]

def get_random_headers() -> Dict[str, str]:
    if USE_RANDOM_AGENT:
        ua = random.choice(USER_AGENTS)
    else:
        ua = USER_AGENTS[0]
    
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0"
    }
    
    return headers

def normalize_url(url, proxies: Optional[Dict] = None):
    url = url.strip()
    url = re.sub(r'/\.git(/.*)?$', '', url, flags=re.IGNORECASE).rstrip('/')

    if url.startswith(('http://', 'https://')):
        return url

    print(f"[*] Detectando protocolo para {url}...")
    try:
        resp = requests.get(f"https://{url}", headers=get_random_headers(), timeout=5, verify=False, proxies=proxies)
        print("    -> HTTPS detectado.")
        return f"https://{url}"
    except requests.RequestException:
        print("    -> Falha no HTTPS. Usando HTTP.")
        return f"http://{url}"


def http_get_bytes(url: str, timeout: int = DEFAULT_TIMEOUT, proxies: Optional[Dict] = None) -> Tuple[bool, bytes | str]:
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.get(url, timeout=timeout, stream=True, verify=False, headers=get_random_headers(), proxies=proxies)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, r.content
    except Exception as e:
        return False, str(e)


def http_get_to_file(url: str, outpath: str, timeout: int = DEFAULT_TIMEOUT, proxies: Optional[Dict] = None) -> Tuple[bool, str]:
    try:
        requests.packages.urllib3.disable_warnings()
        print(f"[!] Tentando baixar {url} ...")
        r = requests.get(url, timeout=timeout, stream=True, verify=False, headers=get_random_headers(), proxies=proxies)
        print(f"[!] {url} - Status: {r.status_code}")
        if r.status_code != 200:
            print(f"[!] Falha ao baixar {url} - Status: {r.status_code}")
            return False, f"HTTP {r.status_code}"
        
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        with open(outpath, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
        return True, "ok"
    except Exception as e:
        print(f"[!] Falha ao baixar {url} - expt: {e}")
        return False, str(e)


def http_head_status(url: str, timeout: int = 6, proxies: Optional[Dict] = None) -> Tuple[bool, Optional[int], str]:
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=False, headers=get_random_headers(), proxies=proxies)
        code = getattr(r, "status_code", None)
        if code and 200 <= code < 300:
            return True, code, "OK"
        else:
            return False, code, f"HTTP {code}"
    except Exception as e:
        return False, None, str(e)


# ---------------------------
# .git/index parser (DIRC)
# ---------------------------
def read_u32(b: bytes, off: int) -> int:
    return struct.unpack(">I", b[off:off + 4])[0]


def read_u16(b: bytes, off: int) -> int:
    return struct.unpack(">H", b[off:off + 2])[0]


def parse_git_index(index_path):
    entries = []
    try:
        with open(index_path, "rb") as f:
            header = f.read(12)
            if len(header) < 12: return []
            
            signature, version, num_entries = struct.unpack("!4sLL", header)
            
            if signature != b"DIRC":
                print(f"[!] Erro: Assinatura inválida: {signature}")
                print(f"[!] Verifique o arquivo raw baixado (raw_index)")
                return []
            
            print(f"[*] Versão do Index: {version} | Entradas: {num_entries}")

            previous_path = b""
            
            for i in range(num_entries):
                # O cabeçalho da entrada tem 62 bytes fixos na v2/v3
                # 4s(ctime) 4ns 4s(mtime) 4ns 4dev 4ino 4mode 4uid 4gid 4size 20sha 2flags
                # Total: 10 Inteiros (40 bytes) + 20 bytes SHA + 2 bytes Flags = 62 bytes
                entry_data = f.read(62)
                
                if len(entry_data) < 62:
                    # Fim do arquivo ou arquivo truncado
                    break
                
                # ! = Big Endian
                # 10L = 10 Longs (4 bytes cada)
                # 20s = String de 20 chars (SHA1)
                # H = Unsigned Short (2 bytes, Flags)
                fields = struct.unpack("!10L20sH", entry_data)
                
                # Extraindo campos vitais
                # fields[0-3] são timestamps (ignorando)
                # fields[4] = dev, fields[5] = ino
                mode = fields[6]  # Mode
                # fields[7] = uid, fields[8] = gid
                file_size = fields[9] # Size
                sha1_raw = fields[10] # SHA1 Bytes
                flags = fields[11]    # Flags
                sha1_hex = sha1_raw.hex()
                name_length = flags & 0xFFF
                path_name = b""

                if version == 4:
                    # Lógica da Versão 4 (Compressão de Prefixo)
                    strip_len = 0
                    shift = 0
                    while True:
                        byte_read = f.read(1)
                        if not byte_read: break
                        b = byte_read[0]
                        strip_len |= (b & 0x7F) << shift
                        if (b & 0x80) == 0:
                            break
                        shift += 7
                    
                    suffix = b""
                    while True:
                        char = f.read(1)
                        if char == b"\x00": break
                        suffix += char
                    
                    path_name = previous_path[:len(previous_path) - strip_len] + suffix
                    previous_path = path_name
                    
                else:
                    # Lógica Versão 2 e 3 (Linear com Padding)
                    
                    if name_length < 0xFFF:
                        path_name = f.read(name_length)
                        f.read(1) 
                        
                        # Tamanho atual: 62 (header) + name_length + 1 (null)
                        entry_len = 62 + name_length + 1
                        padding = (8 - (entry_len % 8)) % 8
                        f.read(padding)
                        
                    else:
                        # Nome muito longo (>= 0xFFF), ler até encontrar null byte
                        # (Raro em index padrão, mas possível)
                        path_name = b""
                        while True:
                            char = f.read(1)
                            if char == b"\x00": break
                            path_name += char
                        
                        entry_len = 62 + len(path_name) + 1
                        padding = (8 - (entry_len % 8)) % 8
                        f.read(padding)

                try:
                    decoded_path = path_name.decode('utf-8', 'replace')
                    if decoded_path:
                        entries.append({"path": decoded_path, "sha1": sha1_hex, "size": file_size})
                except:
                    pass

    except Exception as e:
        print(f"[!] Erro no parser: {e}")
        import traceback
        traceback.print_exc()
        
    return entries




def index_to_json(index_path, json_out_path):
    data = parse_git_index(index_path)
    output = {"entries": data}
    with open(json_out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Index convertido: {len(data)} arquivos encontrados.")

# ---------------------------
# .DS_Store parser (DIRC)
# ---------------------------

def parse_ds_store(filepath):
    found_files = set()
    
    if not HAS_DS_STORE_LIB:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
                import re
                text_content = data.decode("utf-16-be", errors="ignore")
                candidates = re.findall(r'[\w\-\.]+\.[a-z0-9]{2,4}', text_content)
                for c in candidates:
                    found_files.add(c)
        except Exception as e:
            pass
        return list(found_files)

    try:
        if os.path.exists(filepath):
            with DSStore.open(filepath, 'r') as d:
                for record in d:
                    if record.filename:
                        found_files.add(record.filename)
    except Exception as e:
        print(f"[!] Erro ao ler .DS_Store: {e}")
    
    return list(found_files)


# ---------------------------
# URL helpers
# ---------------------------
def normalize_site_base(base_url: Optional[str]) -> str:
    if not base_url: return ""
    s = base_url.rstrip("/")
    if s.endswith("/.git/index"): s = s[:-12]
    if s.endswith("/.git"): return s[:-5]
    if s.endswith(".git"): return s[:-4]
    return s


def make_blob_url_from_git(base_git_url: str, sha: str) -> str:
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"
    return f"{base}/objects/{sha[:2]}/{sha[2:]}"


def public_url_from_path(site_base: str, path: str) -> str:
    site = site_base.rstrip("/")
    return site + "/" + path.lstrip("/")


def sanitize_folder_name(url: str) -> str:
    """Gera um nome de pasta seguro a partir da URL"""
    s = re.sub(r'^https?://', '', url)
    s = re.sub(r'/\.git/?$', '', s, flags=re.IGNORECASE)
    s = s.rstrip('/')
    s = re.sub(r'[^a-zA-Z0-9]', '_', s)
    s = re.sub(r'_+', '_', s)
    return s[:60]


join_remote_file = public_url_from_path


# ---------------------------
# Load dumps
# ---------------------------
def load_dump_entries(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Arquivo de entrada JSON não encontrado: {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if isinstance(data, dict) and "entries" in data: return data["entries"]
    if isinstance(data, list): return data
    raise ValueError("Formato JSON inválido.")


# ---------------------------
# Reconstruct objects
# ---------------------------
def ensure_git_repo_dir(outdir: str):
    os.makedirs(outdir, exist_ok=True)
    if not os.path.exists(os.path.join(outdir, ".git")):
        subprocess.run(["git", "init"], cwd=outdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.makedirs(os.path.join(outdir, ".git", "objects"), exist_ok=True)


def recover_one_sha(base_git_url: str, sha: str, outdir: str, original_path: Optional[str] = None, proxies: Optional[Dict] = None) -> bool:
    tmpdir = os.path.join(outdir, "__tmp")
    os.makedirs(tmpdir, exist_ok=True)
    tmpfile = os.path.join(tmpdir, sha)
    blob_url = make_blob_url_from_git(base_git_url, sha)
    info(f"Recuperando SHA1: {sha}")

    ok, data = http_get_to_file(blob_url, tmpfile, proxies=proxies)
    if not ok:
        warn(f"Falha ao baixar: {data}")
        return False

    try:
        ensure_git_repo_dir(outdir)
        dest_dir = os.path.join(outdir, ".git", "objects", sha[:2])
        os.makedirs(dest_dir, exist_ok=True)
        final_git_path = os.path.join(dest_dir, sha[2:])
        shutil.move(tmpfile, final_git_path)

        with open(final_git_path, "rb") as f_in:
            raw_data = f_in.read()
        parse_ok, parsed = parse_git_object(raw_data)

        if parse_ok:
            obj_type, content = parsed
            if original_path and original_path != sha:
                clean_path = original_path.lstrip("/").lstrip("\\")
                decoded_path = os.path.join(outdir, clean_path)
                os.makedirs(os.path.dirname(decoded_path), exist_ok=True)
                info(f" -> Restaurando estrutura original em: {clean_path}")
            else:
                filename = f"decoded_{sha}"
                if obj_type == "blob": filename += ".txt"
                decoded_path = os.path.join(outdir, filename)
                info(f" -> Caminho desconhecido. Salvando na raiz: {filename}")

            with open(decoded_path, "wb") as f_out:
                f_out.write(content)
            success(f"Objeto recuperado com sucesso.")
            return True
        else:
            warn(f"Falha ao decodificar objeto Git: {parsed}")
            return False
    except Exception as e:
        warn(f"Falha ao mover/processar objeto: {e}")
        return False


def reconstruct_all(input_json: str, base_git_url: str, outdir: str, workers: int = 10):
    entries = load_dump_entries(input_json)
    info(f"Entradas detectadas: {len(entries)} — iniciando downloads (workers={workers})")
    mapping = {}
    for e in entries:
        sha = e.get("sha1")
        path = e.get("path", "")
        if not sha: continue
        if sha not in mapping: mapping[sha] = path
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(recover_one_sha, base_git_url, sha, outdir, mapping.get(sha)) for sha in mapping]
        for _ in as_completed(futures): pass
    info("Executando git fsck --lost-found ...")
    try:
        subprocess.run(["git", "fsck", "--lost-found"], cwd=outdir, check=False)
    except:
        warn("git fsck falhou (git pode não estar disponível).")
    success("Reconstrução concluída.")


# ---------------------------
# Git object parsing
# ---------------------------
def parse_git_object(raw_bytes: bytes) -> Tuple[bool, Tuple[str, bytes] | str]:
    try:
        decompressed = zlib.decompress(raw_bytes)
    except Exception as e:
        return False, f"zlib error: {e}"
    try:
        header_end = decompressed.index(b"\x00")
    except ValueError:
        return False, "invalid object: missing header null"
    header = decompressed[:header_end].decode(errors="ignore")
    parts = header.split(" ")
    if len(parts) < 1: return False, "invalid object header"
    obj_type = parts[0]
    content = decompressed[header_end + 1:]
    return True, (obj_type, content)


def parse_commit_content(content_bytes: bytes) -> Dict[str, Any]:
    try:
        text = content_bytes.decode(errors="replace")
    except:
        text = content_bytes.decode("latin1", errors="replace")
    lines = text.splitlines()
    info = {"tree": None, "parents": [], "author": None, "committer": None, "message": "", "date": ""}
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "": i += 1; break
        if line.startswith("tree "):
            info["tree"] = line.split()[1].strip()
        elif line.startswith("parent "):
            info["parents"].append(line.split()[1].strip())
        elif line.startswith("author "):
            # Captura completa de "Nome <Email>"
            raw = line[7:].strip()
            try:
                last_gt = raw.rfind(">")
                if last_gt != -1:
                    info["author"] = raw[:last_gt + 1]  # Pega até o fechamento do email
                    ts_part = raw[last_gt + 1:].strip().split(" ")[0]
                    if ts_part.isdigit():
                        info["date"] = datetime.fromtimestamp(int(ts_part)).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    info["author"] = raw
            except:
                info["author"] = raw
        elif line.startswith("committer "):
            info["committer"] = line[10:].strip()
        i += 1
    info["message"] = "\n".join(lines[i:]).strip()
    return info


def parse_tree(content_bytes: bytes) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    i = 0;
    b = content_bytes;
    L = len(b)
    while i < L:
        j = b.find(b' ', i);
        if j == -1: break
        mode = b[i:j].decode(errors="ignore")
        k = b.find(b'\x00', j + 1)
        if k == -1: break
        name = b[j + 1:k].decode(errors="ignore")
        sha_raw = b[k + 1:k + 21]
        if len(sha_raw) != 20: break
        sha_hex = sha_raw.hex()
        entries.append({"mode": mode, "name": name, "sha": sha_hex})
        i = k + 21
    return entries


def fetch_object_raw(base_git_url: str, sha: str, proxies=None) -> Tuple[bool, bytes | str]:
    url = make_blob_url_from_git(base_git_url, sha)
    return http_get_bytes(url, proxies=proxies)


def collect_files_from_tree(base_git_url: str, tree_sha: str, proxies: Optional[Dict] = None, ignore_missing: bool = True) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    stack: List[Tuple[str, str]] = [("", tree_sha)]
    while stack:
        prefix, sha = stack.pop()
        ok, raw = fetch_object_raw(base_git_url, sha, proxies=proxies)
        if not ok:
            if ignore_missing:
                warn(f"Tree object {sha} não encontrado."); continue
            else:
                raise RuntimeError(f"Tree object {sha} não encontrado.")
        ok2, parsed = parse_git_object(raw)
        if not ok2: continue
        obj_type, content = parsed
        if obj_type != "tree": continue
        entries = parse_tree(content)
        for e in entries:
            path = (prefix + "/" + e["name"]).lstrip("/")
            if e["mode"].startswith("4") or e["mode"] == "40000":
                stack.append((path, e["sha"]))
            else:
                files.append({"path": path, "sha": e["sha"], "mode": e["mode"],
                              "blob_url": make_blob_url_from_git(base_git_url, e["sha"])})
    return files

def calculate_git_sha1(content: bytes) -> str:
    """Calcula o SHA1 de um blob git: 'blob <tamanho>\x00<conteúdo>'"""
    s = hashlib.sha1()
    s.update(f"blob {len(content)}\0".encode('utf-8'))
    s.update(content)
    return s.hexdigest()

# ---------------------------
# Misc Leaks (Full Scan)
# ---------------------------


def check_ds_store_exposure(base_url, output_dir, proxies=None):
    if not base_url.endswith("/"):
        base_url += "/"
        
    ds_url = base_url + ".DS_Store"
    local_path = os.path.join(output_dir, "_files", "DS_Store_dump")
    print(f"[*] Verificando exposição de .DS_Store em: {ds_url}")
    success, _ = http_get_to_file(ds_url, local_path, proxies=proxies)
    
    if success:
        print("[+] .DS_Store encontrado! Extraindo arquivos...")
        files = parse_ds_store(local_path)
        
        if files:
            print(f"[+] {len(files)} entradas descobertas no .DS_Store:")
            full_urls = []
            for f in files:
                full_url = base_url + f
                full_urls.append(full_url)
                
                print(f"    -> Encontrado: {f}")
                print(f"       [URL]: {full_url}")

            ds_json = os.path.join(output_dir, "_files", "ds_store_leaks.json")
            with open(ds_json, "w") as f:
                json.dump(full_urls, f, indent=2)
        else:
            print("[-] .DS_Store estava vazio ou não continha nomes de arquivos legíveis.")
    #else:
    #    print("[-] .DS_Store não encontrado.")


# --- ASSINATURAS DE SEGREDOS (REGEX) ---
SECRET_PATTERNS = {
    # ---------------------------------------------------------
    # 1. INFRAESTRUTURA CLOUD & SERVIDORES
    # ---------------------------------------------------------
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*([a-zA-Z0-9/+]{40})",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com",
    "GCP Service Account": r"\"type\":\s*\"service_account\"", # Detecta JSON de credencial do Google
    "Azure Storage Key": r"DefaultEndpointsProtocol=[^;\s]+;AccountName=[^;\s]+;AccountKey=[^;\s]+",
    "Heroku API Key": r"(?i)HEROKU_API_KEY\s*=\s*[0-9a-fA-F-]{36}",
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    
    # ---------------------------------------------------------
    # 2. SAAS & DEVOPS
    # ---------------------------------------------------------
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-\_]{20}",
    "NPM Access Token": r"npm_[a-zA-Z0-9]{36}",
    "PyPI Upload Token": r"pypi-[a-zA-Z0-9\-\_]+",
    "Docker Hub Token": r"dckr_pat_[a-zA-Z0-9\-\_]{27}",
    "Sentry DSN": r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+",
    "Datadog API Key": r"(?i)DD_API_KEY\s*=\s*[a-f0-9]{32}",

    # ---------------------------------------------------------
    # 3. COMUNICAÇÃO & SOCIAL
    # ---------------------------------------------------------
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Discord Webhook": r"https://discord\.com/api/webhooks/[0-9]{18,19}/[a-zA-Z0-9\-_]+",
    "Telegram Bot Token": r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}",
    "Twilio Account SID": r"AC[a-zA-Z0-9]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",

    # ---------------------------------------------------------
    # 4. PAGAMENTOS & FINANCEIRO
    # ---------------------------------------------------------
    "Stripe API Key": r"(sk_live|rk_live)_[0-9a-zA-Z]{24,}",
    "PayPal Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",

    # ---------------------------------------------------------
    # 5. BANCOS DE DADOS & ARQUITETURA
    # ---------------------------------------------------------
    "Laravel APP_KEY": r"APP_KEY=base64:[a-zA-Z0-9/\+=]{30,}",
    "Connection String (URI)": r"(postgres|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@[a-zA-Z0-9\.-]+",
    "Redis Connection": r"(?i)REDIS_URL\s*=\s*redis://:[^@]+@",

    # ---------------------------------------------------------
    # 6. CRIPTOGRAFIA & AUTENTICAÇÃO
    # ---------------------------------------------------------
    "Private Key (RSA/DSA/EC)": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----",
    "JWT Token": r"eyJh[a-zA-Z0-9\-_]+\.eyJh[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", # JSON Web Token

    # ---------------------------------------------------------
    # 7. GENÉRICOS (Para .env e config files)
    # ---------------------------------------------------------
    # Procura por: (DB|MAIL|REDIS...)_(PASSWORD|SECRET|KEY) = valor
    # Ignora valores comuns seguros: null, true, false, file, sync, local, debug, 0, 1, localhost
    "DotEnv Sensitive Assignment": r"(?im)^[A-Z0-9_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z0-9_]*\s*=\s*(?!(?:null|true|false|0|1|file|sync|local|debug|empty|root|admin|localhost))([^\s#]+)",

    # Genérico para código (High Entropy): pega strings longas atribuídas a variáveis suspeitas
    "Generic High Entropy Secret": r"(?i)(api_key|access_token|client_secret)[\s=:\"'>]{1,5}([0-9a-zA-Z\-_=]{20,})"
}

MISC_SIGNATURES = {
    "svn": {"path": "/.svn/wc.db", "magic": b"SQLite format 3", "desc": "Repositório SVN (wc.db)"},
    "hg": {"path": "/.hg/store/00manifest.i", "magic": b"\x00\x00\x00\x01", "desc": "Repositório Mercurial"},
    "ds_store": {"path": "/.DS_Store", "magic": b"\x00\x00\x00\x01", "desc": "Metadados macOS (.DS_Store)"},
    "env": {"path": "/.env", "regex": br"^\s*[A-Z_0-9]+\s*=", "desc": "Variáveis de Ambiente (.env)"}
}


COMMON_FILES = [
    # --- Environment & Secrets ---
    ".env", ".env.local", ".env.dev", ".env.development", ".env.prod", ".env.production",
    ".env.example", ".env.sample", ".env.save", ".env.bak", ".env.old",
    "config.json", "secrets.json", "config.yaml", "secrets.yaml", "config.toml", "config.php",
    "settings.py", "database.yml", "robots.txt", "README.md", "index.php", "index.html", "server.js",

    
    # --- Version Control & CI/CD (Risco Crítico) ---
    ".git/config", ".gitignore", ".gitmodules",
    ".gitlab-ci.yml", ".travis.yml", "circle.yml", "jenkinsfile", "Jenkinsfile",
    ".github/workflows/main.yml", ".github/workflows/deploy.yml",
    
    # --- Javascript / Node.js ---
    "package.json", "package-lock.json", "yarn.lock", ".npmrc",
    "webpack.config.js", "rollup.config.js", "next.config.js", "nuxt.config.js",
    "server.js", "app.js",
    
    # --- PHP / CMS / Frameworks ---
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old", # WordPress
    "configuration.php", "configuration.php.bak", # Joomla
    ".htaccess", "composer.json", "composer.lock", "auth.json",
    "artisan", "phpunit.xml", # Laravel
    
    # --- Python / Django / Flask ---
    "requirements.txt", "Pipfile", "Pipfile.lock", "setup.py", "pyproject.toml",
    "manage.py", "app.py", "wsgi.py", "uwsgi.ini",
    
    # --- ASP.NET / C# (IIS) ---
    "web.config", "Web.config", "appsettings.json", "appsettings.Development.json",
    "packages.config", "Global.asax",
    
    # --- Docker / Kubernetes / Cloud / Terraform ---
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore",
    "Makefile", "Vagrantfile",
    "k8s.yaml", "kubeconfig", "deployment.yaml",
    "main.tf", "variables.tf", "terraform.tfvars", ".terraform.lock.hcl",
    "serverless.yml", "serverless.yaml",
    
    # --- Backups & Dumps (Arquivos pesados) ---
    "backup.zip", "backup.tar.gz", "backup.sql",
    "dump.sql", "database.sql", "db_backup.sql", "users.sql",
    "www.zip", "site.zip", "public.zip", "html.tar.gz",
    
    # --- IDEs & Logs ---
    ".vscode/settings.json", ".idea/workspace.xml",
    "debug.log", "error_log", "access.log", "npm-debug.log",
    "id_rsa", "id_rsa.pub", "known_hosts"
]

def scan_for_secrets(outdir: str):
    info("Iniciando Scanner de Segredos (Regex Analysis)...")
    
    scan_root = outdir
    findings = []
    ignored_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".exe", ".pack", ".idx"}
    
    scanned_count = 0
    
    for root, dirs, files in os.walk(scan_root):
        if "metadata" in root: continue 
        
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in ignored_exts:
                continue
                
            filepath = os.path.join(root, filename)
            scanned_count += 1
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if len(content) > 5 * 1024 * 1024:
                        continue

                    for name, pattern in SECRET_PATTERNS.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            secret_val = match.group(0)
                            masked_val = secret_val[:4] + "*" * (len(secret_val)-8) + secret_val[-4:] if len(secret_val) > 10 else "***"
                            
                            findings.append({
                                "type": name,
                                "file": os.path.relpath(filepath, outdir),
                                "match": secret_val,
                                "context": content[max(0, match.start()-20):min(len(content), match.end()+20)].strip()
                            })
                            print(f"[!] SEGREDO ENCONTRADO: {name}")
                            print(f"    -> Arquivo: {filename}")
                            print(f"    -> Match: {masked_val}")

            except Exception:
                pass

    info(f"Scan finalizado. {scanned_count} arquivos analisados.")
    
    if findings:
        success(f"TOTAL DE SEGREDOS ENCONTRADOS: {len(findings)}")
        report_path = os.path.join(outdir, "_files", "secrets.json")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)
        except Exception as e:
            warn(f"Erro ao salvar secrets.json: {e}")
            
        html_path = os.path.join(outdir, "secrets.html")
        generate_secrets_html(findings, html_path)
    else:
        info("Nenhum segredo óbvio encontrado nos arquivos baixados.")

def generate_secrets_html(findings, outpath):
    rows = ""
    for f in findings:
        safe_context = f['context'].replace("<", "&lt;").replace(">", "&gt;")
        safe_match = f['match'].replace("<", "&lt;").replace(">", "&gt;")
        
        rows += f"""
        <tr>
            <td style="width: 15%"><span class="tag">{f['type']}</span></td>
            <td style="width: 25%" class="filename">{f['file']}</td>
            <td style="width: 60%">
                <div class="code-box">
                    {safe_context}
                </div>
                <div class="match-box">
                    Match: <span>{safe_match}</span>
                </div>
            </td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <title>Relatório de Segredos - Git Leak Explorer</title>
        <style>
            body {{
                background: #0f1111;
                color: #dcdcdc;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                padding: 20px;
                margin: 0;
            }}
            h1 {{
                color: #ff5555;
                border-bottom: 2px solid #ff5555;
                padding-bottom: 10px;
                text-align: center;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .btn-back {{
                display: inline-block;
                padding: 8px 16px;
                background-color: #333;
                color: #fff;
                text-decoration: none;
                border: 1px solid #555;
                border-radius: 4px;
                margin-bottom: 20px;
            }}
            .btn-back:hover {{
                background-color: #444;
                border-color: #777;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                background-color: #252526;
                box-shadow: 0 0 10px rgba(0,0,0,0.5);
            }}
            th, td {{
                padding: 12px;
                border: 1px solid #3e3e42;
                vertical-align: top;
                text-align: left;
            }}
            th {{
                background-color: #333337;
                color: #fff;
                font-weight: bold;
            }}
            tr:nth-child(even) {{
                background-color: #2d2d30;
            }}
            tr:hover {{
                background-color: #3e3e40;
            }}
            .tag {{
                background-color: #d32f2f;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.85em;
                display: inline-block;
            }}
            .filename {{
                color: #4ec9b0; /* Cor estilo VS Code para arquivos */
            }}
            .code-box {{
                background-color: #1e1e1e;
                border: 1px solid #444;
                padding: 10px;
                white-space: pre-wrap;
                word-break: break-all;
                color: #ce9178; /* Cor de string */
                font-size: 0.9em;
                border-radius: 3px;
            }}
            .match-box {{
                margin-top: 5px;
                font-size: 0.85em;
                color: #888;
            }}
            .match-box span {{
                color: #ff5555;
                font-weight: bold;
                background-color: rgba(255, 85, 85, 0.1);
                padding: 0 4px;
            }}
            footer {{
                margin-top: 40px;
                text-align: center;
                color: #666;
                font-size: 0.8em;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="report.html" class="btn-back">&larr; Voltar para Relatório</a>
            
            <h1>⚠️ Segredos Detectados ({len(findings)})</h1>
            
            <table>
                <thead>
                    <tr>
                        <th>Tipo</th>
                        <th>Arquivo</th>
                        <th>Contexto</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            
            <footer>
                Gerado por Git Leak Explorer
            </footer>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)
        success(f"Relatório HTML de Segredos gerado: {outpath}")
    except Exception as e:
        warn(f"Erro ao gerar HTML de segredos: {e}")


def brute_force_scan(base_git_url: str, outdir: str, wordlist_path: Optional[str] = None, proxies: Optional[Dict] = None) -> List[Dict[str, Any]]:
    target_list = COMMON_FILES
    source_type = "Lista Padrão"

    if wordlist_path:
        if os.path.exists(wordlist_path):
            info(f"Carregando wordlist personalizada: {wordlist_path}")
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    custom_items = []
                    for line in f:
                        clean_line = line.replace('\ufeff', '').replace('\x00', '').strip()
                        if clean_line and not clean_line.startswith("#"):
                            custom_items.append(clean_line)
                
                if custom_items:
                    target_list = custom_items
                    source_type = "Custom"
                    success(f"Wordlist carregada com sucesso: {len(target_list)} entradas válidas.")
                else:
                    warn("A wordlist fornecida parece vazia. Revertendo para lista padrão.")
            except Exception as e:
                warn(f"Erro ao ler wordlist: {e}. Revertendo para padrão.")
        else:
            warn(f"Wordlist não encontrada: {wordlist_path}. Revertendo para padrão.")

    info(f"Iniciando Brute-Force... Fonte: {source_type} ({len(target_list)} itens)")
    
    site_root = base_git_url.rstrip("/")
    if site_root.endswith("/.git"):
        site_root = site_root[:-5]
    
    found_files = []
    
    bf_dir = os.path.join(outdir, "_files", "bruteforce")
    trav_dir = os.path.join(bf_dir, "traversal")
    
    os.makedirs(bf_dir, exist_ok=True)
    os.makedirs(trav_dir, exist_ok=True)

    for raw_path in target_list:
        url_path = raw_path.replace("\\", "/")
        
        is_traversal = ".." in url_path
        
        target_url = ""
        local_full_path = ""
        
        if is_traversal:
            target_url = f"{site_root}/{url_path}"
            
            safe_name = url_path.replace("..", "UP").replace("/", "_").replace("\\", "_")
            flat_filename = f"TRAV_{safe_name}"
            local_full_path = os.path.join(trav_dir, flat_filename)
            
        else:
            url_path_clean = url_path.lstrip("/")
            target_url = f"{site_root}/{url_path_clean}"
            
            relative_system_path = os.path.normpath(url_path_clean)
            local_full_path = os.path.join(bf_dir, relative_system_path)
            
            try:
                os.makedirs(os.path.dirname(local_full_path), exist_ok=True)
            except Exception as e:
                warn(f"Erro ao criar diretório local para {url_path}: {e}")
                continue

        ok_http, data = http_get_bytes(target_url, proxies=proxies)
        
        if ok_http and len(data) > 0:
            if len(data) < 200 and b"<html" in data.lower() and b"404" in data:
                continue

            try:
                with open(local_full_path, "wb") as f:
                    f.write(data)
                
                if url_path.endswith(".DS_Store") or "/.DS_Store" in target_url:
                    info(f"[+] .DS_Store detectado no Brute-Force! Iniciando análise profunda...")
                    parent_folder_url = target_url.rsplit(".DS_Store", 1)[0]
                    check_ds_store_exposure(parent_folder_url, outdir, proxies=proxies)
                    print(f"[*] Retornando ao fluxo de brute-force...")

                git_sha = calculate_git_sha1(data)
                obj_url = make_blob_url_from_git(base_git_url, git_sha)
                git_exists, _, _ = http_head_status(obj_url, proxies=proxies)
                
                log_prefix = "Traversal" if is_traversal else "Brute-Force"
                status_msg = f"(SHA: {git_sha[:8]} - Versionado)" if git_exists else "(Apenas Local)"
                
                if git_exists:
                    success(f"{log_prefix}: {url_path} encontrado! {status_msg}")
                else:
                    warn(f"{log_prefix}: {url_path} encontrado no site {status_msg}")

                found_files.append({
                    "filename": url_path,  
                    "local_path": local_full_path,
                    "url": target_url,
                    "git_sha": git_sha,
                    "in_git": git_exists,
                    "type": "traversal" if is_traversal else "LISTA PADRÃO"
                })

            except Exception as e:
                warn(f"Erro ao processar arquivo '{url_path}': {e}")
                continue

    try:
        with open(os.path.join(outdir, "_files", "bruteforce.json"), "w", encoding="utf-8") as f:
            json.dump(found_files, f, indent=2)
    except Exception as e:
        warn(f"Erro ao salvar JSON: {e}")
        
    return found_files

def generate_misc_html(out_html: str, title: str, content_data: str, is_text: bool):
    display_content = f"<pre>{content_data}</pre>" if is_text else f"<p>Arquivo binário detectado e salvo.<br>Consulte a pasta <code>_files/misc</code>.</p>"
    html = f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><title>{title}</title><style>body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}.wrap{{max-width:1000px;margin:0 auto;}}h1{{color:#6be;}}pre{{background:#1a1c1d;padding:15px;border-radius:6px;overflow-x:auto;border:1px solid #333;}}p.meta{{font-size:13px;color:#779;margin-top:20px;text-align:center;}}</style></head><body><div class='wrap'><h1>⚠️ Vazamento Detectado: {title}</h1>{display_content}<p class="meta">Gerado por Git Leak Explorer</p></div></body></html>"""
    with open(out_html, "w", encoding="utf-8") as f: f.write(html)


def detect_misc_leaks(base_url: str, outdir: str, proxies: Optional[Dict] = None) -> List[Dict[str, Any]]:
    info("Iniciando varredura na raíz (Full Scan) por outros vazamentos...")
    
    base = base_url.rstrip("/")
    if base.endswith("/.git"): base = base[:-5]

    misc_dir = os.path.join(outdir, "_files", "misc")
    os.makedirs(misc_dir, exist_ok=True)
    findings = []

    for key, sig in MISC_SIGNATURES.items():
        target_url = base + sig["path"]
        ok, data = http_get_bytes(target_url, proxies=proxies)

        if ok:
            is_valid = False
            if "magic" in sig:
                if data.startswith(sig["magic"]): is_valid = True
                if key == "ds_store" and data.startswith(b"\x00\x00\x00\x01Bud1"): is_valid = True
            elif "regex" in sig:
                if re.search(sig["regex"], data, re.MULTILINE): is_valid = True

            if is_valid:
                success(f"Vazamento Confirmado: {sig['desc']}")
                
                filename = key + "_dump"
                if key == "env": filename = ".env"
                elif key == "svn": filename = "wc.db"
                elif key == "ds_store": filename = "DS_Store_dump"

                dump_path = os.path.join(misc_dir, filename)

                with open(dump_path, "wb") as f:
                    f.write(data)

                html_name = f"{key}_report.html"
                content_display = ""
                is_text = False

                if key == "env":
                    is_text = True
                    content_display = data.decode("utf-8", "ignore")

                elif key == "ds_store":
                    try:
                        extracted_files = parse_ds_store(dump_path)
                        
                        full_urls = [f"{base}/{f}" for f in extracted_files]
                        
                        ds_json_path = os.path.join(outdir, "_files", "ds_store_leaks.json")
                        with open(ds_json_path, "w", encoding="utf-8") as f:
                            json.dump(full_urls, f, indent=2)
                        
                        if extracted_files:
                            is_text = True
                            content_display = "=== URLs EXTRAÍDAS DO .DS_Store ===\n\n"
                            content_display += "\n".join(full_urls) 
                            content_display += f"\n\n[!] Total: {len(full_urls)} caminhos descobertos."
                        else:
                            is_text = True
                            content_display = "=== ARQUIVO .DS_Store VÁLIDO ===\n\nO arquivo não contém registros de nomes visíveis."
                            
                    except Exception as e:
                        warn(f"Erro ao analisar .DS_Store: {e}")
                        content_display = f"Erro ao decodificar: {e}"

                generate_misc_html(os.path.join(outdir, html_name), sig['desc'], content_display, is_text)

                findings.append({
                    "type": key, 
                    "desc": sig["desc"], 
                    "url": target_url, 
                    "report_file": html_name, 
                    "dump_file": filename
                })

    with open(os.path.join(outdir, "_files", "misc_leaks.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
        
    return findings


# ---------------------------
# Intelligence & Logs
# ---------------------------
def parse_git_log_file(file_path: str) -> List[Dict[str, Any]]:
    entries = []
    if not os.path.exists(file_path): return entries
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split("\t");
                if len(parts) < 1: continue
                meta = parts[0].split(" ");
                message = parts[1] if len(parts) > 1 else ""
                if len(meta) >= 4:
                    old_sha = meta[0];
                    new_sha = meta[1];
                    ts = meta[-2];
                    author_raw = " ".join(meta[2:-2])
                    try:
                        dt = datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        dt = ts
                    entries.append(
                        {"sha": new_sha, "old_sha": old_sha, "author": author_raw, "date": dt, "message": message,
                         "source": "log"})
    except:
        pass
    return entries[::-1]


def parse_git_config_file(file_path: str) -> Optional[str]:
    if not os.path.exists(file_path): return None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            m = re.search(r'url\s*=\s*(.*)', content)
            if m: return m.group(1).strip()
    except:
        pass
    return None


def gather_intelligence(base_git_url: str, outdir: str, proxies: Optional[Dict] = None) -> Dict[str, Any]:
    info("Coletando inteligência (Config, Logs, Refs)...")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"

    meta_dir = os.path.join(outdir, "_files", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    intel = {"remote_url": None, "logs": [], "packed_refs": []}

    ok, data = http_get_bytes(base + "/config", proxies=proxies)
    if ok:
        cfg_path = os.path.join(meta_dir, "config");
        with open(cfg_path, "wb") as f:
            f.write(data)
        intel["remote_url"] = parse_git_config_file(cfg_path)
        if intel["remote_url"]: success(f"Remote Origin detectado: {intel['remote_url']}")

    ok, data = http_get_bytes(base + "/logs/HEAD" , proxies=proxies)
    if ok:
        log_path = os.path.join(meta_dir, "logs_HEAD");
        with open(log_path, "wb") as f: f.write(data)
        intel["logs"] = parse_git_log_file(log_path)
        success(f"Logs de histórico recuperados: {len(intel['logs'])} entradas.")

    ok, data = http_get_bytes(base + "/packed-refs" , proxies=proxies)
    if ok:
        pr_path = os.path.join(meta_dir, "packed-refs");
        with open(pr_path, "wb") as f:
            f.write(data)
        refs = []
        for line in data.decode(errors='ignore').splitlines():
            if not line.startswith("#") and " " in line:
                sha, ref = line.split(" ", 1)
                refs.append({"sha": sha, "ref": ref})
        intel["packed_refs"] = refs

    with open(os.path.join(outdir, "_files", "intelligence.json"), "w", encoding="utf-8") as f:
        json.dump(intel, f, indent=2, ensure_ascii=False)
    return intel


# ---------------------------
# Discovery & Blind Mode Logic
# ---------------------------
def find_candidate_shas(base_git_url: str, proxies: Optional[Dict] = None) -> List[Dict[str, str]]:
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"
    candidates = {}

    head_urls = [base + "/HEAD"]
    for url in head_urls:
        ok, data = http_get_bytes(url, proxies=proxies)
        if not ok: continue
        text = data.decode(errors="ignore").strip()
        if all(c in "0123456789abcdef" for c in text.lower()) and len(text.strip()) == 40:
            candidates[text.strip()] = {"sha": text.strip(), "ref": "HEAD", "source": url}
        elif text.startswith("ref:"):
            ref = text.split(":", 1)[1].strip()
            for ref_url in [base + "/" + ref]:
                ok2, data2 = http_get_bytes(ref_url, proxies=proxies)
                if ok2:
                    sha = data2.decode(errors="ignore").strip().splitlines()[0].strip()
                    if len(sha) == 40:
                        candidates[sha] = {"sha": sha, "ref": ref, "source": ref_url}
                        break
    ok, data = http_get_bytes(base + "/packed-refs", proxies=proxies)
    if ok:
        for line in data.decode(errors="ignore").splitlines():
            if line.startswith("#") or not line.strip(): continue
            parts = line.split(" ", 1)
            if len(parts) == 2:
                sha, ref = parts[0].strip(), parts[1].strip()
                if len(sha) == 40 and sha not in candidates: candidates[sha] = {"sha": sha, "ref": ref,
                                                                                "source": base + "/packed-refs"}

    common_refs = ["refs/heads/master", "refs/heads/main", "refs/heads/develop", "refs/heads/staging",
                   "refs/remotes/origin/master"]
    for ref in common_refs:
        ok, data = http_get_bytes(base + "/" + ref, proxies=proxies)
        if ok:
            sha = data.decode(errors="ignore").strip().splitlines()[0].strip()
            if len(sha) == 40 and sha not in candidates: candidates[sha] = {"sha": sha, "ref": ref,
                                                                            "source": base + "/" + ref}

    return list(candidates.values())


def blind_recovery(base_git_url: str, outdir: str, output_index_name: str, proxies: Optional[Dict] = None) -> bool:
    info("Iniciando MODO BLIND (Reconstrução sem index)...")
    gather_intelligence(base_git_url, outdir, proxies=proxies)
    candidates = find_candidate_shas(base_git_url, proxies=proxies)
    if not candidates: fail("Modo Blind falhou: Nenhum SHA inicial."); return False

    start_sha = candidates[0]['sha']
    info(f"Ponto de partida encontrado: {start_sha} ({candidates[0]['ref']})")

    ok, raw = fetch_object_raw(base_git_url, start_sha, proxies)
    if not ok: fail("Falha ao baixar commit inicial"); return False
    ok2, parsed = parse_git_object(raw)
    if not ok2 or parsed[0] != "commit": fail("Objeto inicial inválido"); return False

    commit_meta = parse_commit_content(parsed[1])
    root_tree_sha = commit_meta.get("tree")
    if not root_tree_sha: fail("Sem tree associada"); return False

    info(f"Root Tree encontrada: {root_tree_sha}. Crawling...")
    all_files = collect_files_from_tree(base_git_url, root_tree_sha, proxies=proxies, ignore_missing=True)

    synthetic_json = {"entries": [{"path": f["path"], "sha1": f["sha"]} for f in all_files]}
    out_path = os.path.join(outdir, "_files", output_index_name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(synthetic_json, f, indent=2)
    success(f"Modo Blind concluído! Index sintético: {len(all_files)} arquivos.")
    return True


# ---------------------------
# Detect hardening/exposure
# ---------------------------
def detect_hardening(base_git_url: str, outdir: str, proxies: Optional[Dict] = None) -> Dict[str, Any]:
    info("Detectando exposição de .git e configuração de hardening...")
    base = base_git_url.rstrip("/")
    candidates = {"HEAD": [base + "/HEAD", base + "/.git/HEAD"],
                  "refs_heads": [base + "/refs/heads/", base + "/.git/refs/heads/"],
                  "packed_refs": [base + "/packed-refs", base + "/.git/packed-refs"],
                  "index": [base + "/index", base + "/.git/index"],
                  "objects_root": [base + "/objects/", base + "/.git/objects/"],
                  "logs": [base + "/logs/HEAD", base + "/.git/logs/HEAD"],
                  "config": [base + "/config", base + "/.git/config"]}
    report = {"base": base_git_url, "checked_at": datetime.now(timezone.utc).isoformat(), "results": {}}
    for name, urls in candidates.items():
        status = {"exposed": False, "positive_urls": []}
        for u in urls:
            try:
                ok_status, code, _ = http_head_status(u, proxies=proxies)
                if ok_status:
                    status["exposed"] = True; status["positive_urls"].append(
                        {"url": u, "status_code": code, "method": "HEAD"})
                else:
                    ok_get, _ = http_get_bytes(u, proxies=proxies)
                    if ok_get: status["exposed"] = True; status["positive_urls"].append(
                        {"url": u, "status_code": 200, "method": "GET"})
            except:
                pass
        report["results"][name] = status
    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    outjson = os.path.join(outdir, "_files", "hardening_report.json")
    with open(outjson, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    success(f"Relatório salvo em: {outjson}")
    out_html = os.path.join(outdir, "hardening_report.html")
    generate_hardening_html(report, out_html)
    success(f"hardening_report.html gravado em: {out_html}")
    return report


def generate_hardening_html(report: Dict[str, Any], out_html: str):
    rows = []
    descr_map = {"HEAD": ".git/HEAD acessível", "refs_heads": ".git/refs/heads/ acessível",
                 "packed_refs": ".git/packed-refs acessível", "index": ".git/index acessível",
                 "objects_root": ".git/objects/ acessível", "logs": ".git/logs/ acessível",
                 "config": ".git/config acessível"}
    for k, v in report.get("results", {}).items():
        exposed = v.get("exposed", False)
        evidence = "; ".join([f"{p.get('method', '?')} {p.get('url')} ({p.get('status_code', '?')})" for p in
                              v.get("positive_urls", [])]) or "-"
        status = "OK"
        if exposed:
            if k in ("index", "objects_root", "config"):
                status = "CRÍTICO"
            else:
                status = "ATENÇÃO"
        rows.append({"category": k, "description": descr_map.get(k, k), "status": status, "evidence": evidence})
    data_json = json.dumps(rows, ensure_ascii=False)
    html = f"""<!DOCTYPE html><html lang='pt-BR'><head><meta charset='utf-8'><title>Hardening Report</title><style>body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}.wrap{{max-width:1200px;margin:0 auto;}}h1{{color:#6be;}}input{{padding:8px;width:360px;border-radius:6px;border:1px solid #333;background:#071117;color:#dff;margin-bottom:12px;}}table{{width:100%;border-collapse:collapse;margin-top:10px}}th,td{{padding:10px;text-align:left;border-bottom:1px solid #222;}}th{{color:#6be;font-weight:bold;border-bottom:1px solid #444;}}.ok{{color:#6f6;font-weight:bold;}}.warning{{color:#ff9800;font-weight:bold;}}.bad{{color:#ff5252;font-weight:bold;}}.meta{{font-size:13px;color:#779;margin-top:20px;}}#summary{{margin-bottom:15px;padding:10px;border:1px solid #333;border-radius:6px;background:#161819;}}</style></head><body><div class='wrap'><h1>🛡 Hardening Report</h1><div id='summary'></div><input id='search' placeholder='Filtrar resultados...'><table id='tbl'><thead><tr><th>Categoria</th><th>Descrição</th><th>Status</th><th>Evidência</th></tr></thead><tbody id='tbody'></tbody></table><p class="meta" style='text-align:center; margin-top:30px;'>Gerado por Git Leak Explorer</p></div><script>const ROWS={data_json};const tbody=document.getElementById('tbody');const search=document.getElementById('search');function render(){{tbody.innerHTML='';let score=0;for(const r of ROWS){{let cls='';if(r.status==='OK')cls='ok';else if(r.status==='ATENÇÃO')cls='warning';else if(r.status==='CRÍTICO')cls='bad';if(r.status==='CRÍTICO')score+=5;if(r.status==='ATENÇÃO')score+=2;tbody.innerHTML+=`<tr><td>${{r.category}}</td><td>${{r.description}}</td><td class='${{cls}}'>${{r.status}}</td><td>${{r.evidence}}</td></tr>`;}}let risk='🔍 Indeterminado';let riskColor='';if(score===0){{risk='🟢 Seguro';riskColor='#6f6';}}else if(score<10){{risk='🟡 Moderado';riskColor='#ff9800';}}else{{risk='🔴 Crítico';riskColor='#ff5252';}}document.getElementById('summary').innerHTML=`<span style='font-size:16px; font-weight:bold;'>Status Geral: <span style='color:${{riskColor}}'>${{risk}}</span></span> — Pontuação: ${{score}} — Verificações: ${{ROWS.length}}`;}}search.addEventListener('input',()=>{{const q=search.value.toLowerCase();const filtered=ROWS.filter(r=>JSON.stringify(r).toLowerCase().includes(q));tbody.innerHTML='';for(const r of filtered){{let cls='';if(r.status==='OK')cls='ok';else if(r.status==='ATENÇÃO')cls='warning';else if(r.status==='CRÍTICO')cls='bad';tbody.innerHTML+=`<tr><td>${{r.category}}</td><td>${{r.description}}</td><td class='${{cls}}'>${{r.status}}</td><td>${{r.evidence}}</td></tr>`;}}}});render();</script></body></html>"""
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


def handle_packfiles(mode: str, base_git_url: str, outdir: str, proxies: Optional[Dict] = None):
    info(f"Iniciando manuseio de Packfiles em modo: {mode}")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"
    info_packs_url = base + "/objects/info/packs"
    ok, data = http_get_bytes(info_packs_url, proxies=proxies)
    found_packs = []
    if ok:
        try:
            content = data.decode(errors='ignore')
            for line in content.splitlines():
                line = line.strip()
                if not line: continue
                parts = line.split()
                for p in parts:
                    if p.endswith(".pack"): found_packs.append(p)
        except Exception as e:
            warn(f"Erro info/packs: {e}")
    found_packs = list(set(found_packs))
    info(f"Packfiles encontrados: {len(found_packs)}")
    results = []
    pack_dir = os.path.join(outdir, ".git", "objects", "pack")
    if mode in ["download", "download-unpack"]:
        ensure_git_repo_dir(outdir);
        os.makedirs(pack_dir, exist_ok=True)
    for pname in found_packs:
        url_pack = f"{base}/objects/pack/{pname}";
        url_idx = url_pack.replace(".pack", ".idx")
        status = "Listado";
        local_pack_path = os.path.join(pack_dir, pname);
        local_idx_path = local_pack_path.replace(".pack", ".idx")
        if mode in ["download", "download-unpack"]:
            info(f"Baixando {pname}...")
            ok_p, _ = http_get_to_file(url_pack, local_pack_path, proxies=proxies)
            ok_i, _ = http_get_to_file(url_idx, local_idx_path, proxies=proxies)
            if ok_p:
                status = "Baixado"
                if mode == "download-unpack":
                    info(f"Tentando descompactar {pname}...")
                    try:
                        with open(local_pack_path, "rb") as f_in:
                            proc = subprocess.run(["git", "unpack-objects"], cwd=outdir, stdin=f_in,
                                                  capture_output=True)
                            if proc.returncode == 0:
                                success(f"Descompactado: {pname}"); status = "Extraído (Unpacked)"
                            else:
                                fail(f"Falha unpack {pname}"); status = "Falha na Extração"
                    except Exception as e:
                        fail(f"Erro exec: {e}"); status = "Erro (Execução)"
            else:
                fail(f"Falha ao baixar pack: {pname}"); status = "Falha Download"
        results.append({"name": pname, "url_pack": url_pack, "status": status})
    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    with open(os.path.join(outdir, "_files", "packfiles.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return results


# ---------------------------
# Reports: Unified & Components
# ---------------------------

def generate_bruteforce_report(findings, outpath):
    rows = ""
    for f in findings:
        f_source = f.get("list_source", "Lista Padrão")
        f_path = f.get("filename", "unknown")
        f_url = f.get("url", "#")
        f_status = "VERSIONADO" if f.get("in_git") else "LOCAL"
        f_sha = f.get("git_sha", "")[:8] if f.get("git_sha") else "-"
        
        source_cls = "badge-std"
        if "Custom" in f_source: source_cls = "badge-custom"
        elif "Traversal" in f_source: source_cls = "badge-trav"
        
        status_cls = "status-git" if f.get("in_git") else "status-local"

        rows += f"""
        <tr>
            <td><span class="badge {source_cls}">{f_source}</span></td>
            <td class="file-cell" title="{f_path}">{f_path}</td>
            <td class="url-cell"><a href="{f_url}" target="_blank">{f_url}</a></td>
            <td><span class="{status_cls}">{f_status}</span></td>
            <td class="mono">{f_sha}</td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Relatório Avançado - Brute Force</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-body: #0f111a;
                --bg-card: #1a1d2d;
                --bg-hover: #23273a;
                --text-primary: #e2e8f0;
                --text-secondary: #94a3b8;
                --accent-color: #6366f1;
                --border-color: #2d3748;
                --success: #10b981;
                --warning: #f59e0b;
                --danger: #ef4444;
                --info: #3b82f6;
                --custom-purple: #8b5cf6;
            }}

            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
            body {{
                background-color: var(--bg-body);
                color: var(--text-primary);
                font-family: 'Inter', sans-serif;
                min-height: 100vh;
                padding: 2rem;
            }}

            .container {{ max-width: 1400px; margin: 0 auto; }}

            /* Header */
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 2rem;
                padding-bottom: 1rem;
                border-bottom: 1px solid var(--border-color);
            }}

            .title h1 {{ font-size: 1.5rem; font-weight: 600; color: var(--text-primary); }}
            .title p {{ color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }}
            .stats {{ font-size: 0.9rem; color: var(--text-secondary); background: var(--bg-card); padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border-color); }}
            .highlight {{ color: var(--accent-color); font-weight: 600; }}

            /* Controls */
            .controls {{
                display: flex;
                justify-content: space-between;
                gap: 1rem;
                margin-bottom: 1.5rem;
                flex-wrap: wrap;
            }}

            .btn-back {{
                display: inline-flex;
                align-items: center;
                padding: 0.5rem 1rem;
                background-color: var(--bg-card);
                color: var(--text-primary);
                text-decoration: none;
                border-radius: 6px;
                border: 1px solid var(--border-color);
                transition: all 0.2s;
                font-size: 0.9rem;
            }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}

            .search-box {{
                flex: 1;
                max-width: 400px;
                position: relative;
            }}
            .search-box input {{
                width: 100%;
                padding: 0.6rem 1rem 0.6rem 2.5rem;
                background-color: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                color: var(--text-primary);
                font-size: 0.9rem;
            }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{
                position: absolute;
                left: 0.8rem;
                top: 50%;
                transform: translateY(-50%);
                color: var(--text-secondary);
                pointer-events: none;
            }}

            /* Table */
            .table-container {{
                background-color: var(--bg-card);
                border-radius: 8px;
                border: 1px solid var(--border-color);
                overflow: hidden;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }}

            table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }}
            
            th {{
                background-color: rgba(255,255,255,0.03);
                padding: 1rem;
                text-align: left;
                font-weight: 500;
                color: var(--text-secondary);
                border-bottom: 1px solid var(--border-color);
                user-select: none;
            }}
            
            td {{
                padding: 0.8rem 1rem;
                border-bottom: 1px solid var(--border-color);
                color: var(--text-primary);
                vertical-align: middle;
            }}
            
            tbody tr:hover {{ background-color: var(--bg-hover); }}
            tbody tr:last-child td {{ border-bottom: none; }}

            /* Columns Widths */
            th:nth-child(1) {{ width: 12%; }} /* Origem */
            th:nth-child(2) {{ width: 25%; }} /* Arquivo */
            th:nth-child(3) {{ width: 35%; }} /* URL */
            th:nth-child(4) {{ width: 13%; }} /* Status */
            th:nth-child(5) {{ width: 15%; }} /* SHA */

            /* Typography & Badges */
            .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--text-secondary); }}
            .file-cell {{ font-weight: 500; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
            
            .url-cell a {{ 
                color: var(--info); 
                text-decoration: none; 
                font-family: 'JetBrains Mono', monospace; 
                font-size: 0.8rem;
                display: block;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }}
            .url-cell a:hover {{ text-decoration: underline; }}

            .badge {{
                padding: 0.25rem 0.6rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                display: inline-block;
            }}
            .badge-std {{ background: rgba(59, 130, 246, 0.15); color: var(--info); border: 1px solid rgba(59, 130, 246, 0.3); }}
            .badge-custom {{ background: rgba(139, 92, 246, 0.15); color: var(--custom-purple); border: 1px solid rgba(139, 92, 246, 0.3); }}
            .badge-trav {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }}

            .status-git {{ color: var(--success); font-weight: 600; display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; }}
            .status-git::before {{ content: ''; width: 6px; height: 6px; background: var(--success); border-radius: 50%; }}
            
            .status-local {{ color: var(--warning); font-weight: 600; display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; }}
            .status-local::before {{ content: ''; width: 6px; height: 6px; background: var(--warning); border-radius: 50%; }}

            /* Pagination */
            .pagination-container {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-top: 1rem;
                padding-top: 1rem;
                border-top: 1px solid var(--border-color);
                color: var(--text-secondary);
                font-size: 0.9rem;
            }}
            
            .pagination-controls {{ display: flex; gap: 0.5rem; }}
            
            .page-btn {{
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                color: var(--text-primary);
                width: 32px;
                height: 32px;
                border-radius: 6px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.2s;
            }}
            .page-btn:hover:not(:disabled) {{ border-color: var(--accent-color); color: var(--accent-color); }}
            .page-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
            .page-btn.active {{ background: var(--accent-color); border-color: var(--accent-color); color: white; }}

        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div class="title">
                    <h1>Arquivos Recuperados</h1>
                    <p>Relatório de Descobertas via Brute-Force & Traversal</p>
                </div>
                <div class="stats">
                    Total Encontrado: <span class="highlight">{len(findings)}</span>
                </div>
            </header>

            <div class="controls">
                <a href="report.html" class="btn-back">← Voltar ao Painel</a>
                
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="searchInput" placeholder="Filtrar por nome, path ou status...">
                </div>
            </div>

            <div class="table-container">
                <table id="dataTable">
                    <thead>
                        <tr>
                            <th>Origem</th>
                            <th>Arquivo (Relativo)</th>
                            <th>URL Completa</th>
                            <th>Status</th>
                            <th>Git SHA-1</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                        {rows}
                    </tbody>
                </table>
            </div>

            <div class="pagination-container">
                <div id="entriesInfo">Mostrando 0 de 0</div>
                <div class="pagination-controls" id="paginationControls">
                    </div>
            </div>
        </div>

        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                const searchInput = document.getElementById('searchInput');
                const tableBody = document.getElementById('tableBody');
                const entriesInfo = document.getElementById('entriesInfo');
                const paginationControls = document.getElementById('paginationControls');
                
                let allRows = Array.from(tableBody.querySelectorAll('tr'));
                let filteredRows = allRows;
                let currentPage = 1;
                const rowsPerPage = 15;

                function filterRows(query) {{
                    const lowerQuery = query.toLowerCase();
                    filteredRows = allRows.filter(row => {{
                        const text = row.innerText.toLowerCase();
                        return text.includes(lowerQuery);
                    }});
                    currentPage = 1;
                    renderTable();
                }}

                function renderTable() {{
                    const totalPages = Math.ceil(filteredRows.length / rowsPerPage) || 1;
                    
                    if (currentPage > totalPages) currentPage = totalPages;
                    if (currentPage < 1) currentPage = 1;

                    const start = (currentPage - 1) * rowsPerPage;
                    const end = start + rowsPerPage;
                    const pageRows = filteredRows.slice(start, end);

                    tableBody.innerHTML = '';
                    pageRows.forEach(row => tableBody.appendChild(row));

                    const startInfo = filteredRows.length === 0 ? 0 : start + 1;
                    const endInfo = Math.min(end, filteredRows.length);
                    entriesInfo.innerText = `Mostrando ${{startInfo}} a ${{endInfo}} de ${{filteredRows.length}} registros`;

                    renderPagination(totalPages);
                }}

                function renderPagination(totalPages) {{
                    paginationControls.innerHTML = '';
                    
                    const btnPrev = document.createElement('button');
                    btnPrev.className = 'page-btn';
                    btnPrev.innerHTML = '‹';
                    btnPrev.disabled = currentPage === 1;
                    btnPrev.onclick = () => {{ currentPage--; renderTable(); }};
                    paginationControls.appendChild(btnPrev);

                    let startPage = Math.max(1, currentPage - 2);
                    let endPage = Math.min(totalPages, startPage + 4);
                    
                    if (endPage - startPage < 4) {{
                        startPage = Math.max(1, endPage - 4);
                    }}

                    for (let i = startPage; i <= endPage; i++) {{
                        const btn = document.createElement('button');
                        btn.className = `page-btn ${{i === currentPage ? 'active' : ''}}`;
                        btn.innerText = i;
                        btn.onclick = () => {{ currentPage = i; renderTable(); }};
                        paginationControls.appendChild(btn);
                    }}

                    const btnNext = document.createElement('button');
                    btnNext.className = 'page-btn';
                    btnNext.innerHTML = '›';
                    btnNext.disabled = currentPage === totalPages;
                    btnNext.onclick = () => {{ currentPage++; renderTable(); }};
                    paginationControls.appendChild(btnNext);
                }}

                searchInput.addEventListener('input', (e) => filterRows(e.target.value));

                renderTable();
            }});
        </script>
    </body>
    </html>
    """
    
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)
        success(f"Relatório Dashboard de Brute-Force gerado: {outpath}")
    except Exception as e:
        warn(f"Erro ao gerar HTML de brute-force: {e}")



def generate_unified_report(outdir: str, base_url: str):
    info("Gerando Relatório Unificado (report.html)...")
    files = os.path.join(outdir, "_files")

    try:
        hardening = json.load(open(os.path.join(files, "hardening_report.json")))
    except:
        hardening = {}

    try:
        misc = json.load(open(os.path.join(files, "misc_leaks.json")))
    except:
        misc = []

    try:
        packs = json.load(open(os.path.join(files, "packfiles.json")))
    except:
        packs = []

    listing_count = "N/A"
    listing_entries = []
    try:
        listing_entries = load_dump_entries(os.path.join(files, "dump.json"))
        listing_count = len(listing_entries)
    except:
        pass

    commits_count = "N/A"
    history_data = {}
    try:
        history_data = json.load(open(os.path.join(files, "history.json")))
        commits_count = len(history_data.get('commits', []))
    except:
        pass

    bruteforce_data = []
    try:
        with open(os.path.join(outdir, "_files", "bruteforce.json"), "r", encoding="utf-8") as f:
            bruteforce_data = json.load(f)
    except: pass

    users_count = 0
    try:
        users_path = os.path.join(files, "users.json")
        if os.path.exists(users_path):
            with open(users_path, 'r', encoding='utf-8') as f:
                users_data = json.load(f)
                users_count = len(users_data)
    except:
        users_count = 0
    
    try: bf_data = json.load(open(os.path.join(files, "bruteforce.json")))
    except: bf_data = []

    # 1. Hardening HTML
    hardening_html = "<h3>1. Verificação de Hardening (.git Exposure)</h3><p style=\"background-color:#fff3cd;color:#856404;padding:4px;border:1px solid #ffeeba;border-radius:3px;font-size:0.9em;margin:5px 0;\"><strong>⚠ Atenção:</strong> StatusCode positivos podem indicar falsos positivos.</p><table style='width: 100%;'><thead><tr><th>Componente</th><th>Status</th><th>Evidência</th></tr></thead><tbody>"
    for k, v in hardening.get("results", {}).items():
        status_text = "EXPOSTO" if v.get('exposed') else "OK"
        status_class = "error" if v.get('exposed') else "ok"
        evidence = "; ".join([p.get('url') for p in v.get('positive_urls', [])]) or "N/A"
        hardening_html += f"<tr><td>{k}</td><td class='{status_class}'>{status_text}</td><td>{evidence}</td></tr>"
    hardening_html += "</tbody></table>"

    # 2. Files Summary (Top 10)
    listing_html = f"<h3>2. Arquivos Encontrados (.git Index Dump)</h3><p>Total de Arquivos Listados: {listing_count}</p><table style='width: 100%;'><thead><tr><th>Caminho</th><th>SHA (Blob)</th><th>Link Remoto</th></tr></thead><tbody>"
    if listing_entries:
        for e in listing_entries[:10]:
            listing_html += f"<tr><td>{e.get('path')}</td><td>{e.get('sha1')[:12]}...</td><td><a href='{make_blob_url_from_git(base_url, e.get('sha1', ''))}' target='_blank'>Ver Blob</a></td></tr>"
        if len(listing_entries) > 10:
            listing_html += f"<tr><td colspan='3' class='meta'>... e mais {len(listing_entries) - 10} entradas. <a href='listing.html'>Consulte listing.html para o relatório completo</a>.</td></tr>"
    else:
        listing_html += "<tr><td colspan='3'>Dados não disponíveis.</td></tr>"
    listing_html += "</tbody></table>"

    # 3. History Summary (Top 5)
    history_summary = "<h3>3. Histórico de Commits (Análise de Tree)</h3>"
    if history_data:
        head_sha = history_data.get('head', 'N/A')
        commits = history_data.get('commits', [])

        # Tenta pegar URL remota
        remote_url = ""
        try:
            remote_url = json.load(open(os.path.join(files, "intelligence.json"))).get("remote_url", "")
        except:
            pass

        history_summary += f"<p><b>Origem Remota:</b> {remote_url}</p><p>HEAD Inicial: {head_sha}</p><p>Total de Commits Processados: {len(commits)}</p><details><summary>Detalhes dos Últimos 5 Commits</summary><ol>"
        for c in commits[:5]:
            cls = 'ok' if c.get('ok') else 'error'
            sha_display = c['sha'][:10]
            if remote_url:
                clean_url = remote_url.replace('.git', '')
                sha_display = f"<a href='{clean_url}/commit/{c['sha']}' target='_blank'>{sha_display}</a>"

            msg = c.get('message', '').splitlines()[0] if c.get('message') else 'Sem mensagem'
            # Escapar HTML básico na mensagem para evitar quebra de layout
            msg = msg.replace("<", "&lt;").replace(">", "&gt;")

            history_summary += f"<li><span class='{cls}'>[{'OK' if c.get('ok') else 'ERR'}]</span> {sha_display}: {msg} ({c.get('file_count', 0)} arquivos)</li>"
        history_summary += "</ol><p class='meta'>Consulte <a href='history.html'>history.html</a> para o histórico completo e detalhes de arquivos.</p></details>"
    else:
        history_summary += "<p>Dados de histórico não disponíveis.</p>"


    # 4. Users/Authors Section
    users_section_html = "<h3>4. Identidades e E-mails (OSINT)</h3>"
    if users_count > 0:
        users_section_html += f"<p>Foram identificados <b>{users_count}</b> autores únicos (nomes e e-mails) participando do histórico deste repositório.</p>"
        users_section_html += f"<p><a href='users.html'>Consulte o Relatório de Identidades (users.html) para visualização completa.</a></p>"
    else:
        users_section_html += "<p class='muted'>Nenhuma informação de usuário (autor/email) foi encontrada nos metadados processados.</p>"

    # 5. Packfiles Section
    packfiles_html = f"<h3>5. Packfiles Encontrados</h3><p>Total Encontrado: {len(packs)}</p>"
    if packs:
        packfiles_html += "<table style='width: 100%;'><thead><tr><th>Nome</th><th>Status</th><th>URL</th></tr></thead><tbody>"
        for p in packs:
            cls = "muted"
            status = p['status']
            if "Extraído" in status:
                cls = "ok"
            elif "Baixado" in status:
                cls = "ok"
            elif "Falha" in status:
                cls = "error"

            packfiles_html += f"<tr><td>{p['name']}</td><td class='{cls}'>{status}</td><td><a href='{p['url_pack']}' target='_blank'>Download</a></td></tr>"
        packfiles_html += "</tbody></table>"
    else:
        packfiles_html += "<p class='muted'>Nenhum packfile detectado.</p>"

    # 6. Misc Section (Full Scan)
    misc_html = "<h3>6. Outros Vazamentos na raíz (Full Scan)</h3>"
    if misc:
        misc_html += "<ul>"
        for m in misc:
            # Usa o nome real do arquivo se disponível (ex: .env), senão usa o padrão _dump
            dump_file = m.get('dump_file', f"{m['type']}_dump")
            misc_html += f"<li><b>{m['type']}</b>: {m['desc']} (<a href='_files/misc/{dump_file}' target='_blank'>Dump</a> | <a href='{m['report_file']}' target='_blank'>Relatório</a>)</li>"
        misc_html += "</ul>"
    else:
        misc_html += "<p class='muted'>Nenhum outro vazamento detectado ou varredura --full-scan não executada.</p>"
    
    # 7. Brute Force ---
    bf_section = ""
    if bruteforce_data:
        # 1. Gera o relatório completo separado (já atualizado acima)
        bf_report_path = os.path.join(outdir, "bruteforce_report.html")
        generate_bruteforce_report(bruteforce_data, bf_report_path)
        
        # 2. Gera o Preview para o relatório principal
        preview_limit = 5
        preview_rows = ""
        for item in bruteforce_data[:preview_limit]:
            fname = item.get("filename", "unknown")
            fsource = item.get("list_source", "LISTA PADRÃO") 
            furl = item.get("url", "#")
            
            badge_cls = "bg-secondary"
            if "Custom" in fsource: badge_cls = "bg-purple" 
            elif "Traversal" in fsource: badge_cls = "bg-warning text-dark"
            else: badge_cls = "bg-primary"
            
            # --- ATUALIZAÇÃO DA LINHA DO PREVIEW ---
            preview_rows += f"""
            <tr>
                <td><span class='badge {badge_cls}'>{fsource}</span></td>
                <td>{fname}</td>
                <td><a href='{furl}' target='_blank' style='font-size: 0.85em; word-break: break-all;'>{furl}</a></td>
            </tr>
            """
        
        # Botão para ver tudo
        btn_full = f"""
        <div class="text-center mt-3">
        <p class='muted'>Legenda: LISTA PADRÃO : Tipo de lista padrão (hardcoded) | TRAVERSAL : Encontrado usando a técnica path traversal na lista CUSTOM | CUSTOM : Encontrado com base em lista personalizada </p>
            <a href="bruteforce_report.html" class="btn btn-primary w-100">
                <!-- Ver Lista Completa ({len(bruteforce_data)} arquivos); -->
                Consulte o Relatório bruteforce_report.html para visualização completa.
            </a>
        </div>
        """
        
        bf_section = f"""
        <div class="card mb-4">
            <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <h3>7. Arquivos Encontrados (Brute-Force)</h3>
            </div>
            <div class="card-body">
                <p class="text-muted small">Total: {len(bruteforce_data)} - Exibindo os primeiros {preview_limit} resultados.</p>
                <div class="table-responsive">
                    <table style='width: 100%;'>
                        <thead><tr><th>Origem</th><th>Arquivo</th><th>URL Completa</th></tr></thead>
                        <tbody>{preview_rows}</tbody>
                    </table>
                </div>
                {btn_full}
            </div>
        </div>
        """
    else:
        bf_section = """
        <div class="card mb-4 border-secondary">
            <div class="card-header bg-secondary text-white">
                <h3>Arquivos Encontrados (Brute-Force)</h3>
                </div>
            <div class="card-body text-center text-muted">
                Nenhum arquivo encontrado via força bruta, ou não executado --bruteforce.
            </div>
        </div>
        """

    secrets_data = []
    try:
        with open(os.path.join(outdir, "_files", "secrets.json"), "r", encoding="utf-8") as f:
            secrets_data = json.load(f)
    except: pass

    secrets_section = ""
    if secrets_data:
        rows = ""
        for s in secrets_data:
            rows += f"""
            <tr>
                <td><span class="badge bg-danger">{s['type']}</span></td>
                <td>{s['file']}</td>
                <td><code>{s['match']}</code></td>
            </tr>
            """
        secrets_section = f"""
        <div class="card mb-4 border-danger">
            <div class="card-header bg-danger text-white">
                <h3 class="mb-0">⚠️ SEGREDOS CRÍTICOS ENCONTRADOS - REGEX ({len(secrets_data)})</h3>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table style='width: 100%;'>
                        <thead><tr><th>Tipo</th><th>Arquivo</th><th>Match</th></tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>
                <a href="secrets.html" class="btn btn-outline-danger btn-sm mt-2">Ver Relatório Detalhado de Segredos</a>
            </div>
        </div>
        """



    # HTML Template Final
    html = f"""
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Git Leak Explorer - Relatório Técnico</title>
    <style>
        body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding: 20px;}}
        .wrap{{max-width:1200px;margin:0 auto;}}
        h1, h3{{color:#6be;}}
        h3{{margin-top: 30px;}}
        .meta, .muted{{font-size:13px;color:#779;}}
        table{{border-collapse: collapse; margin-top: 10px;}}
        th, td{{border: 1px solid #333; padding: 8px; text-align: left; font-size: 14px;}}
        .ok{{color:#6f6;}}
        .error{{color:#ff5252;}}
        a{{color:#6be;}}
    </style>
</head>
<body>
<div class='wrap'>
    <h1>Git Leak Explorer - Relatório Técnico</h1>
    <p class='meta'>URL Alvo: <b>{base_url}</b></p>
    <p class='meta'>Data do Relatório: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <hr>
    {hardening_html}
    <hr>
    {listing_html}
    <hr>
    {history_summary}
    <hr>
    {users_section_html}
    <hr>
    {packfiles_html}
    <hr>
    {misc_html}
    <hr>
    {bf_section}    
    <hr>
    {secrets_section}
    <hr>
    <p class='muted'>Para visualização interativa do histórico e da listagem completa, inicie o servidor: <code>python git_leak.py --serve --output-dir {outdir}</code></p>
    <p class='meta' style='text-align:center; margin-top:30px;'>Gerado por Git Leak Explorer</p>
</div>
</body>
</html>
    """

    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)

    success(f"Relatório unificado salvo: {os.path.join(outdir, 'report.html')}")


def make_listing_modern(json_file: str, base_git_url: str, outdir: str):
    info(f"Gerando listagem simplificada para {json_file}")
    try:
        entries = load_dump_entries(json_file)
    except Exception as e:
        warn(f"Não foi possível carregar index ({e}). Gerando HTML vazio."); entries = []
    site_base = normalize_site_base(base_git_url)
    rows = []
    for e in entries:
        path = e.get("path", "");
        sha = e.get("sha1", "")
        if not sha: continue
        rows.append({
            "path": path,
            "remote_url": join_remote_file(site_base, path),
            "blob_url": make_blob_url_from_git(base_git_url, sha),
            "sha": sha,
            "local_exists": os.path.exists(os.path.join(outdir, path.lstrip("/"))),
            "local_url": f"file://{os.path.abspath(os.path.join(outdir, path.lstrip('/')))}"
        })
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "listing.html")
    data_json = json.dumps(rows, ensure_ascii=False)

    html = f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Git Leak Explorer - Arquivos</title>
  <style>
    body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;}}
    .wrap{{max-width:1200px;margin:20px auto;padding:12px}}
    header{{display:flex;gap:10px;align-items:center}}
    input[type=text]{{padding:8px;width:420px;border-radius:6px;border:1px solid #333;background:#071117;color:#dff}}
    table{{width:100%;border-collapse:collapse;margin-top:12px}}
    th,td{{padding:8px;border-bottom:1px solid #222;text-align:left;font-size:13px}}
    th.sortable{{cursor:pointer}}
    a{{color:#6be}}
    .muted{{color:#779}}
    .pager{{margin-top:12px;display:flex;gap:8px;align-items:center}}
    .btn{{padding:6px 10px;border-radius:6px;background:#213;color:#dff;border:none;cursor:pointer}}
    .btn:hover{{background:#324}}
    .btn-back {{
                display: inline-block;
                padding: 8px 16px;
                background-color: #333;
                color: #fff;
                text-decoration: none;
                border: 1px solid #555;
                border-radius: 4px;
                margin-bottom: 20px;
    }}
    .btn-back:hover {{
                background-color: #444;
                border-color: #777;
    }}
  </style>
</head>
<body>
<div class='wrap'>
<a href="report.html" class="btn-back">&larr; Voltar para Relatório</a>
  <h1>Git Leak Explorer</h1>
  <p class='muted'>Total de arquivos: <b>{len(rows)}</b></p>
  <header>
    <input id='q' style='width:400px' type='text' placeholder='Buscar por path ou SHA...'>
    <label> Itens por pág:
      <select id='pageSize'>
        <option>25</option>
        <option>50</option>
        <option selected>100</option>
        <option>250</option>
      </select>
    </label>
    <button id='reset' class='btn'>Limpar</button>
  </header>
  <table id='tbl'>
    <thead>
      <tr>
        <th class='sortable' data-sort='path'>Arquivo</th>
        <th>Local</th>
        <th>Remoto</th>
        <th class='sortable' data-sort='sha'>Blob (SHA)</th>
      </tr>
    </thead>
    <tbody id='tbody'></tbody>
  </table>
  <div class='pager'>
    <button id='prev' class='btn'>« Anterior</button>
    <span class='muted'>Página <span id='cur'>1</span> / <span id='total'>1</span></span>
    <button id='next' class='btn'>Próximo »</button>
    <span style='flex:1'></span>
    <span class='muted'>Resultados: <span id='count'>0</span></span>
  </div>
</div>
<p class="meta" style='text-align:center; margin-top:30px; font-size:12px; color:#779;'>Gerado por Git Leak Explorer</p>
<script>
const DATA={data_json};
let filtered=DATA.slice();
let sortKey=null, sortDir=1, pageSize=100, curPage=1;

const tbody=document.getElementById('tbody');
const q=document.getElementById('q');
const pageSizeSel=document.getElementById('pageSize');
const curSpan=document.getElementById('cur');
const totalSpan=document.getElementById('total');
const countSpan=document.getElementById('count');

function render(list){{
    // Atualiza pageSize
    pageSize = parseInt(pageSizeSel.value, 10);
    const total = list.length;
    const pages = Math.max(1, Math.ceil(total/pageSize));

    // Valida página atual
    if(curPage > pages) curPage = pages;
    if(curPage < 1) curPage = 1;

    // Fatia os dados
    const start = (curPage-1) * pageSize;
    const slice = list.slice(start, start + pageSize);

    // Renderiza Tabela
    tbody.innerHTML='';
    slice.forEach(r=>{{
        const tr=document.createElement('tr');
        tr.innerHTML=`<td>${{r.path}}</td><td>${{r.local_exists?`<a href="${{r.local_url}}" target="_blank">Abrir (local)</a>`:'<span class="muted">Não restaurado</span>'}}</td><td><a href="${{r.remote_url}}" target="_blank">Link</a></td><td>${{r.sha?`<a href="${{r.blob_url}}" target="_blank">${{r.sha}}</a>`:'<span class="muted">sem SHA</span>'}}</td>`;
        tbody.appendChild(tr);
    }});

    // Atualiza controles
    curSpan.textContent = curPage;
    totalSpan.textContent = pages;
    countSpan.textContent = total;
}}

function applyFilter(){{
    const qv=q.value.trim().toLowerCase();
    if(!qv){{
        filtered=DATA.slice();
    }} else {{
        filtered=DATA.filter(r=>(r.path||'').toLowerCase().includes(qv)||(r.sha||'').toLowerCase().includes(qv));
    }}

    if(sortKey){{
        filtered.sort((a,b)=>{{
            const A=(a[sortKey]||'').toLowerCase();
            const B=(b[sortKey]||'').toLowerCase();
            if(A<B)return -1*sortDir;
            if(A>B)return 1*sortDir;
            return 0;
        }});
    }}

    curPage=1; // Reseta para a primeira página ao filtrar/ordenar
    render(filtered);
}}

// Event Listeners
q.addEventListener('input', ()=> applyFilter());

pageSizeSel.addEventListener('change', ()=> {{
    curPage=1; 
    render(filtered);
}});

document.getElementById('reset').addEventListener('click', ()=> {{
    q.value='';
    pageSizeSel.value='100';
    sortKey=null;
    sortDir=1;
    filtered=DATA.slice();
    curPage=1;
    render(filtered);
}});

document.getElementById('prev').addEventListener('click', ()=> {{
    if(curPage > 1){{
        curPage--;
        render(filtered);
    }}
}});

document.getElementById('next').addEventListener('click', ()=> {{
    const total = filtered.length;
    const pages = Math.max(1, Math.ceil(total/pageSize));
    if(curPage < pages){{
        curPage++;
        render(filtered);
    }}
}});

document.querySelectorAll('th.sortable').forEach(th=>{{
    th.addEventListener('click', ()=> {{
        const k=th.getAttribute('data-sort');
        if(sortKey===k){{
            sortDir = -sortDir;
        }} else {{
            sortKey=k;
            sortDir=1;
        }}
        applyFilter();
    }});
}});

// Renderização inicial
render(DATA);
</script>
</body>
</html>"""

    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    ok(f"Listing gerado: {outpath}")


def generate_history_html(in_json: str, out_html: str, site_base: str, base_git_url: str):
    with open(in_json, 'r', encoding='utf-8') as f: data = json.load(f)
    commits = data.get('commits', []);
    head_sha = data.get('head', 'N/A')
    commits_json = json.dumps(commits, ensure_ascii=False)

    intel_path = os.path.join(os.path.dirname(in_json), "intelligence.json");
    remote_url = ""
    if os.path.exists(intel_path):
        with open(intel_path, 'r', encoding='utf-8') as f: remote_url = json.load(f).get("remote_url", "")

    html_content = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Git History</title><style>body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}.wrap{{max-width:1200px;margin:0 auto;}}h1{{color:#6be;}}.commit-card{{border:1px solid #333;margin-bottom:15px;padding:15px;border-radius:6px;background:#161819;}}.sha{{font-weight:bold;color:#6be;}}.message{{margin-top:5px;white-space:pre-wrap;font-size:14px;}}.meta{{font-size:12px;color:#779;}}.files{{margin-top:10px;border-top:1px solid #333;padding-top:10px;}}.file-item{{display:block;margin-bottom:3px;}}.error{{color:#ff5252;}}.ok{{color:#6f6;}}a{{color:#6be;}}.source-tag{{font-size:10px;padding:2px 5px;border-radius:4px;margin-left:10px;}}.source-log{{background:#2a3;color:#fff;}}.source-walk{{background:#444;color:#ddd;}}#commits-container>div:nth-child(1) .commit-card{{border-color:#6be;box-shadow:0 0 5px rgba(102,187,238,0.3);}}.filter-header{{display:flex;align-items:center;gap:20px;margin-bottom:20px;}}input[type=text]{{padding:8px;width:100%;max-width:420px;border-radius:6px;border:1px solid #333;background:#071117;color:#dff;}}details{{margin-top:10px;cursor:pointer;}}summary{{font-weight:bold;}}.remote-info{{margin-bottom:20px;padding:10px;background:#1a1c1d;border-radius:6px;border-left:4px solid #6be;}}  .btn:hover{{background:#324}} .btn-back {{ display: inline-block; padding: 8px 16px; background-color: #333; color: #fff; text-decoration: none; border: 1px solid #555; border-radius: 4px; margin-bottom: 20px;}} .btn-back:hover {{ background-color: #444; border-color: #777; }}</style></head><body><div class='wrap'><a href="report.html" class="btn-back">&larr; Voltar para Relatório</a><h1>Reconstrução de Histórico para {site_base}</h1><div class="remote-info"><p class="meta">Referência HEAD: <span class='sha'>{head_sha}</span></p><p class="meta">Origem Remota: <b>{remote_url or "Não detectado"}</b></p><p class="meta">Total: <b>{len(commits)}</b></p></div><div class="filter-header"><input id='q' type='text' placeholder='Filtrar por SHA, autor ou mensagem...'><span id="result-count" class="meta"></span></div><div id='commits-container'></div></div><script>const COMMITS={commits_json};const container=document.getElementById('commits-container');const qInput=document.getElementById('q');const resultCount=document.getElementById('result-count');const remoteUrl="{remote_url}";function getCommitLink(sha){{if(!remoteUrl)return sha;let cleanUrl=remoteUrl.replace('.git','');return `<a href="${{cleanUrl}}/commit/${{sha}}" target="_blank">${{sha}}</a>`;}}function renderCommits(list){{container.innerHTML='';resultCount.textContent=`Exibindo ${{list.length}} commits.`;list.forEach(c=>{{const cardWrapper=document.createElement('div');const card=document.createElement('div');card.className='commit-card';let parentsHtml=c.parents.map(p=>`<a href='#${{p}}'>${{p.substring(0,10)}}</a>`).join(', ');let contentHtml='';let statusBadge='';const statusClass=c.ok?'ok':'error';const shaDisplay=getCommitLink(c.sha);const sourceTag=c.source==='log'?'<span class="source-tag source-log">VIA LOGS</span>':'<span class="source-tag source-walk">VIA GRAFO</span>';if(!c.ok){{let err='Indisponível';statusBadge='ERRO';if(c.error)err=c.error;contentHtml=`<p class='error'>[FALHA] ${{err}}</p>`;}}else{{statusBadge='OK';let filesHtml='';if(c.file_collection_error){{filesHtml=`<span class="error">${{c.file_collection_error}}</span>`;}}else if(c.files&&c.files.length>0){{filesHtml=c.files.map(f=>`<span class='file-item'>${{f.path}} (SHA: ${{f.sha.substring(0,8)}})</span>`).join('');}}else{{filesHtml='<span class="meta">Sem arquivos ou tree vazia.</span>';}}contentHtml=`<p><span class='ok'>[OK]</span> ${{c.message}}</p><p class='meta'>Data: ${{c.date||'?'}}</p><details><summary>Arquivos (${{c.file_count}})</summary><div class='files'>${{filesHtml}}</div></details>`;}}card.innerHTML=`<div><b>${{list.indexOf(c)+1}}.</b> ${{shaDisplay}} <span class='${{statusClass}}'>${{statusBadge}}</span> ${{sourceTag}}</div><div class='meta'>Autor: ${{c.author.replace('<', ' - ').replace('>', ' ')||'N/A'}} — Pais: ${{parentsHtml||'Nenhum'}}</div>${{contentHtml}}`;cardWrapper.appendChild(card);container.appendChild(cardWrapper);}});}}qInput.addEventListener('input',()=>{{const q=qInput.value.toLowerCase().trim();renderCommits(COMMITS.filter(c=>(c.sha||'').toLowerCase().includes(q)||(c.author.replace('<', ' - ').replace('>', ' ')||'').toLowerCase().includes(q)||(c.message||'').toLowerCase().includes(q)));}});renderCommits(COMMITS);</script></body></html>"""
    with open(out_html, "w", encoding="utf-8") as f: f.write(html_content)


def generate_users_report(outdir: str, authors_stats: Dict[str, int]):
    info("Gerando relatório de usuários (OSINT)...")
    
    users_data = []
    import re
    
    sorted_authors = sorted(authors_stats.items(), key=lambda item: item[1], reverse=True)

    for raw_author, count in sorted_authors:
        name = raw_author
        email = ""
        
        match = re.search(r'(.*)\s+<(.*)>', raw_author)
        if match:
            name = match.group(1).strip()
            email = match.group(2).strip()
        
        users_data.append({
            "raw": raw_author,
            "name": name,
            "email": email,
            "commits": count
        })

    files_dir = os.path.join(outdir, "_files")
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, "users.json"), "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

    rows_html = ""
    for u in users_data:
        email_display = f"<a href='mailto:{u['email']}'>{u['email']}</a>" if u['email'] else "<span class='muted'>N/A</span>"
        rows_html += f"""
        <tr>
            <td>{u['name'] or 'Desconhecido'}</td>
            <td>{email_display}</td>
            <td>{u['commits']}</td>
            <td class='muted'>{u['raw']}</td>
        </tr>
        """

    html = f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Git Leak Explorer - Identidades</title>
  <style>
    body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}
    .wrap{{max-width:1000px;margin:0 auto;}}
    h1{{color:#6be;}}
    table{{width:100%;border-collapse:collapse;margin-top:20px;background:#161819;border-radius:6px;overflow:hidden;}}
    th,td{{padding:12px;text-align:left;border-bottom:1px solid #333;}}
    th{{background:#222;color:#6be;font-weight:bold;text-transform:uppercase;font-size:12px;}}
    tr:hover{{background:#1f2223;}}
    a{{color:#6be;text-decoration:none;}}
    a:hover{{text-decoration:underline;}}
    .muted{{color:#779;font-size:12px;}}
    .stat-card{{display:inline-block;background:#1a1c1d;padding:15px;border-radius:6px;border:1px solid #333;margin-right:15px;margin-bottom:20px;}}
    .stat-num{{font-size:24px;font-weight:bold;color:#fff;}}
    .stat-label{{font-size:12px;color:#779;text-transform:uppercase;}}
    .btn:hover{{background:#324}} .btn-back {{ display: inline-block; padding: 8px 16px; background-color: #333; color: #fff; text-decoration: none; border: 1px solid #555; border-radius: 4px; margin-bottom: 20px;}} .btn-back:hover {{ background-color: #444; border-color: #777; }}
  </style>
</head>
<body>
<div class='wrap'>
  <a href="report.html" class="btn-back">&larr; Voltar para Relatório</a>
  <h1>Identidades Encontradas (OSINT)</h1>
  <div>
      <div class='stat-card'>
          <div class='stat-num'>{len(users_data)}</div>
          <div class='stat-label'>Autores Únicos</div>
      </div>
      <div class='stat-card'>
          <div class='stat-num'>{sum(x['commits'] for x in users_data)}</div>
          <div class='stat-label'>Commits Analisados</div>
      </div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Nome</th>
        <th>E-mail</th>
        <th>Commits</th>
        <th>String Bruta (Git)</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
  <p class="muted" style='text-align:center; margin-top:30px;'>Gerado por Git Leak Explorer</p>
</div>
</body>
</html>"""

    out_html = os.path.join(outdir, "users.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    
    success(f"Relatório de usuários salvo: {out_html}")


def reconstruct_history(input_json: str, base_git_url: str, outdir: str, max_commits: int = 200,
                        ignore_missing: bool = True, strict: bool = False, full_history: bool = False,
                        workers: int = 10, proxies: Optional[Dict] = None):
    info(f"Reconstruindo histórico (Fast Mode: {not full_history}). max_commits={max_commits}")
    os.makedirs(outdir, exist_ok=True)
    site_base = normalize_site_base(base_git_url)

    intel_path = os.path.join(outdir, "_files", "intelligence.json")
    intel_logs = []
    if os.path.exists(intel_path):
        try:
            with open(intel_path, 'r', encoding='utf-8') as f:
                intel_logs = json.load(f).get("logs", [])
            info(f"Carregados {len(intel_logs)} commits a partir de logs/HEAD.")
        except:
            pass

    all_commits_out = []
    processed_shas = set()

    def process_log_entry(log_entry, index):
        sha = log_entry.get("sha");
        if not sha: return None
        commit_data = {
            "sha": sha, "ok": True, "author": log_entry.get("author"), "date": log_entry.get("date"),
            "message": log_entry.get("message"), "source": "log",
            "parents": [log_entry.get("old_sha")] if log_entry.get("old_sha") != "0" * 40 else [],
            "files": [], "file_count": 0
        }
        should_scan = full_history or index < 10
        if not should_scan:
            commit_data["file_collection_error"] = "Objetos não listados (Fast Mode). Use --full-history para listagem completa (mais lenta)."
            return commit_data

        ok, raw = fetch_object_raw(base_git_url, sha, proxies=proxies)
        if ok:
            ok2, parsed = parse_git_object(raw)
            if ok2 and parsed[0] == "commit":
                meta = parse_commit_content(parsed[1])
                commit_data["tree"] = meta.get("tree")
                if meta.get("date"): commit_data["date"] = meta.get("date")
                if meta.get("tree"):
                    try:
                        files = collect_files_from_tree(base_git_url, meta.get("tree"), proxies=proxies, ignore_missing=True)
                        commit_data["files"] = files;
                        commit_data["file_count"] = len(files)
                    except:
                        pass
        else:
            commit_data["ok"] = False;
            commit_data["error"] = "Objeto não encontrado (visto em logs)"
        return commit_data

    if intel_logs:
        info(f"Processando {min(len(intel_logs), max_commits)} logs em paralelo...")
        logs_to_process = intel_logs[:max_commits]
        # Nota: Threads e Proxies podem ser instáveis em volumes altos, mas requests é thread-safe
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(process_log_entry, entry, i) for i, entry in enumerate(logs_to_process)]
            for future in as_completed(futures):
                res = future.result()
                if res: all_commits_out.append(res); processed_shas.add(res['sha'])

    def parse_date_sort(c):
        try:
            return datetime.strptime(c.get("date", ""), '%Y-%m-%d %H:%M:%S')
        except:
            return datetime.min

    all_commits_out.sort(key=parse_date_sort, reverse=True)

    if len(all_commits_out) == 0:
        candidate_shas = find_candidate_shas(base_git_url, proxies=proxies)
        queue = [c['sha'] for c in candidate_shas];
        visited = set(queue)
        while queue and len(all_commits_out) < max_commits:
            cur = queue.pop(0)
            ok, raw = fetch_object_raw(base_git_url, cur, proxies=proxies)
            if not ok: continue
            ok2, parsed = parse_git_object(raw)
            if not ok2 or parsed[0] != 'commit': continue
            meta = parse_commit_content(parsed[1])
            files = []
            if len(all_commits_out) < 10 and meta.get("tree"):
                try:
                    files = collect_files_from_tree(base_git_url, meta.get("tree"), proxies=proxies, ignore_missing=True)
                except:
                    pass
            all_commits_out.append({
                "sha": cur, "ok": True, "tree": meta.get("tree"), "parents": meta.get("parents", []),
                "author": meta.get("author"), "date": meta.get("date"), "message": meta.get("message"),
                "files": files, "file_count": len(files), "source": "graph"
            })
            for p in meta.get("parents", []):
                if p not in visited: queue.append(p); visited.add(p)

    author_stats = {}
    for c in all_commits_out:
        auth = c.get("author")
        if auth:
            auth = auth.strip()
            author_stats[auth] = author_stats.get(auth, 0) + 1
    
    generate_users_report(outdir, author_stats)

    head_sha = "N/A"
    hist_json = os.path.join(outdir, "_files", "history.json")
    os.makedirs(os.path.dirname(hist_json), exist_ok=True)
    try:
        with open(hist_json, "w", encoding="utf-8") as f:
            json.dump({"base": base_git_url, "site_base": site_base, "head": head_sha, "commits": all_commits_out}, f,
                      indent=2, ensure_ascii=False)
        success(f"Histórico salvo: {hist_json} ({len(all_commits_out)} commits)")
    except Exception as e:
        fail(f"Falha ao gravar history.json: {e}"); return
    hist_html = os.path.join(outdir, "history.html")
    generate_history_html(hist_json, hist_html, site_base, base_git_url)
    success(f"HTML do histórico gerado: {hist_html}")


def scan_urls(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    except Exception as e:
        fail(f"Erro ao ler arquivo: {e}"); return
    info(f"Escaneando {len(urls)} alvos...")
    for u in urls:
        base = u.rstrip("/")
        if not base.endswith(".git"): base += "/.git"
        test = base + "/HEAD"
        try:
            ok, data = http_get_bytes(test, timeout=5)
            if ok and b"ref:" in data.lower():
                print(f"[!] VULNERÁVEL: {u}")
            else:
                print(f"[.] Seguro/Inacessível: {u}")
        except:
            print(f"[X] Erro: {u}")


def serve_dir(path: str):
    if not path: fail("Requer output dir."); return
    p = os.path.abspath(path)
    if not os.path.isdir(p): fail(f"Diretório não existe: {p}"); return
    info(f"Servindo '{p}' em http://127.0.0.1:8000")
    os.chdir(p)
    try:
        HTTPServer(("0.0.0.0", 8000), SimpleHTTPRequestHandler).serve_forever()
    except KeyboardInterrupt:
        info("\nServidor parado.")


def process_pipeline(base_url: str, output_dir: str, args, proxies: Optional[Dict] = None):
    info(f"=== Iniciando Pipeline em: {base_url} ===")
    info(f"Output: {output_dir}")
    
    os.makedirs(output_dir, exist_ok=True)
    index_json = os.path.join(output_dir, "_files", args.output_index)

    # 1. Index / Blind
    # Tenta baixar o index
    
    raw_index_path = os.path.join(output_dir, "_files", "raw_index")
    
    # Se o arquivo já existe, não baixar
    if not os.path.exists(raw_index_path):
        print("[*] Baixando .git/index...")
        ok_idx, _ = http_get_to_file(base_url.rstrip("/") + "/.git/index", raw_index_path, proxies=proxies)
    else:
        print("[*] Usando .git/index local existente.")
        ok_idx = True

    # Ou se preferir que sempre seja substituído:
    # ok_idx, _ = http_get_to_file(base_url.rstrip("/") + "/.git/index", raw_index_path, proxies=proxies)
    
    has_index = False
    if ok_idx:
        print(f"[+] .git/index baixado. Tentando analisar...")
        try:
            index_to_json(raw_index_path, index_json)
            has_index = True
            print("[+] Índice Git analisado com sucesso.")
        except ValueError as e:
            warn(f"Aviso: .git/index inválido ou corrompido ({e}).")
        except Exception as e:
            fail(f"Erro inesperado no parser: {e}")

    # Se falhou o index ou foi solicitado blind, tenta blind mode
    if not has_index:
        info("Index não disponível ou inválido. Ativando modo Blind/Crawling...")
        blind_recovery(base_url, output_dir, args.output_index, proxies=proxies)

    # 2. Hardening & Misc
    detect_hardening(base_url, output_dir, proxies=proxies)
    gather_intelligence(base_url, output_dir, proxies=proxies)
    
    # Lógica Condicional de Full Scan (Brute Force + Misc)
    if args.full_scan:
        detect_misc_leaks(base_url, output_dir, proxies=proxies)

    # Brute force
    if args.bruteforce:
        brute_force_scan(base_url, output_dir, wordlist_path=args.wordlist, proxies=proxies)
    else:
        if args.wordlist:
            warn("A flag --wordlist foi ignorada pois --bruteforce não foi ativado.")
        if not args.full_scan: 
            pass

    # 3. Reports & Reconstruction
    handle_packfiles('list', base_url, output_dir, proxies=proxies)
    make_listing_modern(index_json, base_url, output_dir)
    
    # Reconstrução de histórico
    reconstruct_history(index_json, base_url, output_dir, 
                        max_commits=args.max_commits,
                        full_history=args.full_history, 
                        workers=args.workers, proxies=proxies)
    
    if args.secrets:
        scan_for_secrets(output_dir)

    check_ds_store_exposure(base_url, output_dir, proxies=proxies)    
    
    # Relatório final
    generate_unified_report(output_dir, base_url)
    success(f"Pipeline concluído para {base_url}")
    print("-" * 60)


def main():
    p = argparse.ArgumentParser(prog="git_leak.py", description="Git Leak Explorer - Ferramenta de Análise Forense")
    p.add_argument("base", nargs="?", help="URL base alvo (ex: http://site.com/.git/ ou site.com)")
    p.add_argument("--output-index", default="dump.json", help="Nome do arquivo de saída para o índice JSON")
    p.add_argument("--output-dir", default="./repo", help="Diretório de saída (Raiz)")
    p.add_argument("--serve-dir", nargs="?", help="Diretório específico para servir via HTTP")
    p.add_argument("--default", action="store_true", help="Executa o pipeline padrão")
    p.add_argument("--report", action="store_true", help="Gera apenas o relatório unificado")
    p.add_argument("--parse-index", action="store_true", help="Apenas baixa e converte o .git/index")
    p.add_argument("--blind", action="store_true", help="Ativa modo Blind")
    p.add_argument("--list", action="store_true", help="Gera listing.html")
    p.add_argument("--reconstruct-history", action="store_true", help="Reconstrói histórico")
    p.add_argument("--max-commits", type=int, default=200, help="Limite de commits")
    p.add_argument("--ignore-missing", action="store_true", help="Ignora objetos ausentes")
    p.add_argument("--strict", action="store_true", help="Aborta em erros críticos")
    p.add_argument("--sha1", help="Baixa objeto pelo Hash SHA1")
    p.add_argument("--detect-hardening", action="store_true", help="Verifica exposição .git")
    p.add_argument("--packfile", choices=['list', 'download', 'download-unpack'], help="Gerencia .pack")
    p.add_argument("--serve", action="store_true", help="Inicia servidor web ao final")
    p.add_argument("--workers", type=int, default=10, help="Threads paralelas")
    p.add_argument("--scan", help="Arquivo com lista de URLs para varredura completa")
    p.add_argument("--check-public", action="store_true", help="Check HEAD request")
    p.add_argument("--full-history", action="store_true", help="Scan completo de histórico (lento)")
    p.add_argument("--full-scan", action="store_true", help="Executa verificação completa (Brute-Force, Misc)")
    p.add_argument("--bruteforce", action="store_true", help="Ativa a tentativa de recuperação de arquivos comuns via força bruta")
    p.add_argument("--wordlist", help="Caminho para wordlist (Brute-Force) personalizada")
    p.add_argument("--proxy", help="URL do Proxy (ex: http://127.0.0.1:8080 para Burp/ZAP ou socks5h://127.0.0.1:9150 para rede Tor)")
    p.add_argument("--no-random-agent", action="store_true", help="desativa a rotação de User-Agents (Usa um fixo)")
    p.add_argument("--secrets", action="store_true", help="executa scanner de regex em busca de chaves e senhas nos arquivos baixados")

    args = p.parse_args()

    global USE_RANDOM_AGENT

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        info(f"Usando Proxy: {args.proxy}")
    
    if args.no_random_agent:
        USE_RANDOM_AGENT = False
        info("Rotação de User-Agents: DESATIVADA (Modo Estático)")
    else:
        USE_RANDOM_AGENT = True
        info("Rotação de User-Agents: ATIVADA (Padrão)")

    if args.serve and not args.base and not args.scan:
        serve_dir(args.serve_dir if args.serve_dir else args.output_dir)
        return

    if args.scan:
        if not os.path.exists(args.scan):
            fail(f"Arquivo de lista não encontrado: {args.scan}")
            return
        
        try:
            with open(args.scan, "r", encoding="utf-8", errors="ignore") as f:
                urls = []
                for line in f:
                    clean_line = line.replace('\ufeff', '').replace('\x00', '').strip()
                    if clean_line and not clean_line.startswith("#"):
                        urls.append(clean_line)

            if not urls:
                fail("Nenhum alvo válido encontrado na lista (verifique se não são apenas comentários).")
                return

        except Exception as e:
            fail(f"Erro ao ler lista de alvos: {e}")
            return

        info(f"Iniciando varredura em massa: {len(urls)} alvos.")
        info(f"Diretório Raiz de Saída: {args.output_dir}")

        for i, raw_url in enumerate(urls, 1):
            target_url = normalize_url(raw_url)
            print(f"\n>>> Processando [{i}/{len(urls)}]: {target_url}")
            
            folder_name = sanitize_folder_name(target_url)
            target_outdir = os.path.join(args.output_dir, folder_name)
            
            try:
                process_pipeline(target_url, target_outdir, args, proxies=proxies)
            except Exception as e:
                fail(f"Erro fatal ao processar {target_url}: {e}")
                continue
        
        success("Varredura em lista concluída.")
        
        if args.serve:
            print("\n" + "="*60)
            info("Iniciando servidor para visualização dos resultados...")
            serve_dir(args.output_dir)
        
        return

    if not args.base:
        p.print_help()
        print("\n[!] Erro: É necessário fornecer uma URL ou usar --scan <arquivo> (ou apenas --serve para visualizar resultados anteriores)")
        return

    base_url = normalize_url(args.base, proxies=proxies)
    print(f"[*] URL alvo normalizada: {base_url}")
    
    if args.report:
        generate_unified_report(args.output_dir, base_url)
        if args.serve: serve_dir(args.output_dir)
        return
    
    if args.packfile:
        handle_packfiles(args.packfile, base_url, args.output_dir, proxies=proxies)
        return
    
    if args.blind:
        blind_recovery(base_url, args.output_dir, args.output_index, proxies=proxies)
        if args.serve: serve_dir(args.output_dir)
        return
        
    if args.sha1:
        recover_one_sha(base_url, args.sha1, args.output_dir, proxies=proxies)
        return
        
    if args.detect_hardening:
        detect_hardening(base_url, args.output_dir, proxies=proxies)
        return

    if args.parse_index:
        tmp = os.path.join(args.output_dir, "_files", "raw_index")
        http_get_to_file(base_url + "/.git/index", tmp, proxies=proxies)
        index_to_json(tmp, os.path.join(args.output_dir, "_files", args.output_index))
        return

    process_pipeline(base_url, args.output_dir, args, proxies=proxies)
    
    if args.serve:
        serve_dir(args.output_dir)

if __name__ == "__main__":
    main()