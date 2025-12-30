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


def recover_stash_content(base_git_url: str, outdir: str, proxies: Optional[Dict] = None) -> Optional[str]:
    stash_url = base_git_url.rstrip("/") + "/.git/refs/stash"
    
    ok, data = http_get_bytes(stash_url, proxies=proxies)
    if not ok:
        return None
    
    stash_sha = data.decode(errors='ignore').strip()
    if len(stash_sha) != 40:
        return None

    info(f"[!] STASH ENCONTRADO! SHA: {stash_sha}")
    
    ok_obj, raw_obj = fetch_object_raw(base_git_url, stash_sha, proxies=proxies)
    if not ok_obj:
        warn(f"Falha ao baixar objeto do Stash {stash_sha}")
        return None

    _, parsed = parse_git_object(raw_obj)
    meta = parse_commit_content(parsed[1])
    tree_sha = meta.get("tree")
    
    if not tree_sha:
        warn("Commit do Stash não possui Tree.")
        return None

    info(f" -> Extraindo arquivos do Stash (Tree: {tree_sha})...")
    
    stash_files = collect_files_from_tree(base_git_url, tree_sha, proxies=proxies, ignore_missing=True)
    
    if stash_files:
        success(f"Recuperados {len(stash_files)} arquivos do Stash.")
        
        stash_json_path = os.path.join(outdir, "_files", "stash.json")
        output = {"entries": [{"path": f["path"], "sha1": f["sha"]} for f in stash_files]}
        
        with open(stash_json_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
            
        return stash_sha
    else:
        warn("Stash encontrado, mas a árvore de arquivos estava vazia ou inacessível.")
        return stash_sha


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
    "env": {"path": "/.env", "regex": br"^\s*[A-Z_0-9]+\s*=", "desc": "Variáveis de Ambiente (.env)"},
    "exclude": {
        "path": "/.git/info/exclude", 
        "desc": "Git Ignore Local (info/exclude)",
        "regex": br"(?m)^#.*git ls-files" 
    },
    "description": {
        "path": "/.git/description", 
        "desc": "Descrição GitWeb",
        "min_len": 5 
    },
    "commit_msg": {
        "path": "/.git/COMMIT_EDITMSG", 
        "desc": "Última Mensagem de Commit",
        "min_len": 1
    },
    "hook_sample": {
        "path": "/.git/hooks/pre-commit.sample", 
        "desc": "Hook Sample (Exposição de Dir)",
        "magic": b"#!"
    },
    "hook_active": {
        "path": "/.git/hooks/pre-commit", 
        "desc": "Hook Ativo (RCE Potencial)",
        "magic": b"#!"
    }
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

def get_safe_folder_name(target_url):
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    name = parsed.netloc or parsed.path
    safe_name = name.replace(":", "_").replace("/", "_").replace("\\", "_")
    if safe_name.startswith("www_"): safe_name = safe_name[4:]
    return safe_name if safe_name else "unknown_target"

def generate_master_dashboard(outdir: str, scan_results: list):
    import json
    from datetime import datetime
    
    scan_results.sort(key=lambda x: (x['secrets_count'], x['files_count'], x['vuln_count']), reverse=True)

    rows = ""
    total_secrets = sum(r['secrets_count'] for r in scan_results)

    for r in scan_results:
        status_badge = '<span class="badge bg-secondary">SEGURO</span>'
        row_class = ""
        
        if r['secrets_count'] > 0:
            status_badge = '<span class="badge bg-danger">CRÍTICO</span>'
            row_class = "row-crit"
        elif r['files_count'] > 0:
            status_badge = '<span class="badge bg-warning text-dark">VULNERÁVEL</span>'
            row_class = "row-warn"
        elif r['vuln_count'] > 0:
            status_badge = '<span class="badge bg-info">ALERTA</span>'

        report_link = f"{r['folder_name']}/report.html"
        
        rows += f"""
        <tr class="{row_class}">
            <td><a href="{report_link}" target="_blank" style="font-weight:bold; color:#6366f1">{r['target']}</a><div style="font-size:0.8em; color:#666">{r['folder_name']}</div></td>
            <td>{status_badge}</td>
            <td style="text-align:center">{f'<span style="color:#ef4444; font-weight:bold">⚠️ {r["secrets_count"]}</span>' if r['secrets_count'] > 0 else '-'}</td>
            <td style="text-align:center">{f'<span style="color:#f59e0b; font-weight:bold">📂 {r["files_count"]}</span>' if r['files_count'] > 0 else '-'}</td>
            <td style="text-align:right"><a href="{report_link}" target="_blank" style="text-decoration:none">Abrir ↗</a></td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <title>Master Dashboard</title>
        <style>
            body {{ background: #0f111a; color: #e2e8f0; font-family: sans-serif; padding: 20px; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            table {{ width: 100%; border-collapse: collapse; background: #1a1d2d; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 15px; border-bottom: 1px solid #2d3748; text-align: left; }}
            th {{ background: rgba(255,255,255,0.05); color: #94a3b8; }}
            tr:hover {{ background: rgba(255,255,255,0.02); }}
            a {{ color: #6366f1; text-decoration: none; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }}
            .bg-danger {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
            .bg-warning {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
            .bg-secondary {{ background: #333; color: #aaa; }}
            .bg-info {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #60a5fa; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Git Leak Explorer - Visão Geral</h1>
            <p style="color:#aaa">Total de Alvos: {len(scan_results)} | Total de Segredos: {total_secrets}</p>
            <table>
                <thead><tr><th>Alvo</th><th>Status</th><th style="text-align:center">Segredos</th><th style="text-align:center">Arquivos</th><th style="text-align:right">Ação</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </body>
    </html>
    """
    with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

def generate_secrets_html(findings, outpath):
    import json
    
    js_data = []
    for f in findings:
        js_data.append({
            "type": f.get('type', 'Generic'),
            "file": f.get('file', 'Unknown'),
            "context": f.get('context', ''),
            "match": f.get('match', '')
        })
    
    data_json = json.dumps(js_data, ensure_ascii=False)

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Segredos Detectados - Git Leak Explorer</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-body: #0f111a;
                --bg-card: #1a1d2d;
                --bg-hover: #23273a;
                --text-primary: #e2e8f0;
                --text-secondary: #94a3b8;
                --accent-color: #ef4444; /* Vermelho para perigo */
                --border-color: #2d3748;
                --success: #10b981;
                --warning: #f59e0b;
                --code-bg: #111;
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

            /* Header Warning Style */
            .header {{
                background: linear-gradient(to right, rgba(239, 68, 68, 0.1), rgba(239, 68, 68, 0.05));
                border: 1px solid rgba(239, 68, 68, 0.3);
                padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;
                display: flex; justify-content: space-between; align-items: center;
            }}
            .title h1 {{ font-size: 1.5rem; font-weight: 700; color: #f87171; display: flex; align-items: center; gap: 10px; }}
            .title p {{ color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }}
            
            .pulse-dot {{
                width: 10px; height: 10px; background-color: #ef4444; border-radius: 50%;
                box-shadow: 0 0 0 rgba(239, 68, 68, 0.7);
                animation: pulse 2s infinite;
            }}
            @keyframes pulse {{
                0% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }}
                70% {{ box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }}
                100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
            }}

            /* Controls */
            .controls {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
            .btn-back {{
                display: inline-flex; align-items: center; padding: 0.6rem 1rem;
                background-color: var(--bg-card); color: var(--text-primary);
                text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color);
                font-size: 0.9rem; transition: all 0.2s;
            }}
            .btn-back:hover {{ border-color: var(--text-primary); color: #fff; }}

            .search-box {{ flex: 1; position: relative; max-width: 600px; }}
            .search-box input {{
                width: 100%; padding: 0.7rem 1rem 0.7rem 2.5rem;
                background-color: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 6px; color: #fff; font-size: 0.95rem;
            }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); }}

            /* Cards Container (Grid) */
            .cards-container {{
                display: grid; grid-template-columns: repeat(auto-fill, minmax(100%, 1fr)); gap: 15px;
            }}

            /* Secret Item Row */
            .secret-row {{
                background: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 8px; overflow: hidden; transition: transform 0.2s, border-color 0.2s;
                display: flex; flex-direction: column;
            }}
            .secret-row:hover {{ border-color: rgba(239, 68, 68, 0.5); transform: translateY(-2px); }}

            .row-header {{
                padding: 10px 15px; background: rgba(0,0,0,0.2); border-bottom: 1px solid var(--border-color);
                display: flex; justify-content: space-between; align-items: center;
            }}
            .file-path {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #fff; word-break: break-all; }}
            .secret-type {{ 
                font-size: 0.75rem; text-transform: uppercase; font-weight: 700; 
                padding: 3px 8px; border-radius: 4px; background: rgba(239, 68, 68, 0.2); color: #fca5a5;
            }}

            .row-body {{ padding: 15px; }}

            /* Code Block */
            .code-block {{
                background: var(--code-bg); padding: 10px; border-radius: 6px;
                border: 1px solid #333; font-family: 'JetBrains Mono', monospace;
                font-size: 0.85rem; color: #a5b4fc; overflow-x: auto; white-space: pre-wrap;
                margin-bottom: 10px; position: relative;
            }}
            
            /* Match Highlighter */
            .match-highlight {{
                background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: bold;
                border-bottom: 1px dashed #ef4444; padding: 0 2px; cursor: pointer;
            }}
            .match-highlight:hover {{ background: #ef4444; color: #000; }}

            /* Action Bar */
            .action-bar {{
                display: flex; justify-content: flex-end; gap: 10px; margin-top: 5px;
            }}
            .btn-action {{
                padding: 4px 10px; border-radius: 4px; border: 1px solid var(--border-color);
                background: transparent; color: var(--text-secondary); font-size: 0.8rem; cursor: pointer;
            }}
            .btn-action:hover {{ border-color: #fff; color: #fff; }}

            /* Pagination */
            .pagination-container {{
                display: flex; justify-content: space-between; align-items: center;
                padding: 1rem; border-top: 1px solid var(--border-color); margin-top: 2rem; color: var(--text-secondary);
            }}
            .page-btn {{
                background: var(--bg-card); border: 1px solid var(--border-color);
                color: var(--text-primary); width: 32px; height: 32px; border-radius: 6px;
                cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center;
            }}
            .page-btn:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="title">
                    <h1><div class="pulse-dot"></div> Segredos Detectados</h1>
                    <p>Potenciais credenciais, chaves de API e tokens encontrados no código.</p>
                </div>
                <div style="text-align:right">
                    <span style="font-size: 2rem; font-weight: 700; color: #f87171;">{len(findings)}</span>
                    <div style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-secondary);">Incidentes</div>
                </div>
            </div>

            <div class="controls">
                <a href="report.html" class="btn-back">← Voltar ao Painel</a>
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="searchInput" placeholder="Filtrar por tipo (ex: AWS), arquivo ou conteúdo...">
                </div>
            </div>

            <div class="cards-container" id="resultsContainer">
                </div>

            <div class="pagination-container">
                <div id="entriesInfo">Carregando...</div>
                <div style="display:flex; gap:5px;" id="paginationControls"></div>
            </div>
            
            <p style="text-align:center; color:#555; margin-top:2rem; font-size:0.8rem;">
                Git Leak Explorer • Secrets Detection Module
            </p>
        </div>

        <script>
            const DATA = {data_json};
            
            let filtered = DATA.slice();
            let curPage = 1;
            const pageSize = 20;

            const container = document.getElementById('resultsContainer');
            const searchInput = document.getElementById('searchInput');
            const entriesInfo = document.getElementById('entriesInfo');
            const pgControls = document.getElementById('paginationControls');

            function escapeHtml(text) {{
                if (!text) return '';
                return text
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            }}

            function render() {{
                const total = filtered.length;
                const totalPages = Math.max(1, Math.ceil(total / pageSize));

                if (curPage > totalPages) curPage = totalPages;
                if (curPage < 1) curPage = 1;

                const start = (curPage - 1) * pageSize;
                const end = start + pageSize;
                const slice = filtered.slice(start, end);

                container.innerHTML = '';

                slice.forEach(item => {{
                    const el = document.createElement('div');
                    el.className = 'secret-row';
                    
                    let safeCtx = escapeHtml(item.context);
                    const safeMatch = escapeHtml(item.match);
                    
                    // Highlight simples (pode falhar se o match tiver caracteres especiais de regex, mas é visual apenas)
                    try {{
                        if(safeMatch) {{
                            const parts = safeCtx.split(safeMatch);
                            safeCtx = parts.join(`<span class="match-highlight" title="Clique para copiar" onclick="copyText('${{safeMatch}}')">${{safeMatch}}</span>`);
                        }}
                    }} catch(e) {{}}

                    el.innerHTML = `
                        <div class="row-header">
                            <span class="file-path">${{escapeHtml(item.file)}}</span>
                            <span class="secret-type">${{escapeHtml(item.type)}}</span>
                        </div>
                        <div class="row-body">
                            <div class="code-block">${{safeCtx}}</div>
                            <div class="action-bar">
                                <button class="btn-action" onclick="copyText('${{escapeHtml(item.match)}}')">📋 Copiar Match</button>
                                <button class="btn-action" onclick="copyText('${{escapeHtml(item.file)}}')">📂 Copiar Path</button>
                            </div>
                        </div>
                    `;
                    container.appendChild(el);
                }});

                const startInfo = total === 0 ? 0 : start + 1;
                const endInfo = Math.min(end, total);
                entriesInfo.innerText = `Mostrando ${{startInfo}} a ${{endInfo}} de ${{total}} segredos`;
                
                renderPagination(totalPages);
            }}

            function renderPagination(totalPages) {{
                pgControls.innerHTML = '';
                const createBtn = (lbl, page, disabled) => {{
                    const btn = document.createElement('button');
                    btn.className = 'page-btn';
                    btn.innerText = lbl;
                    btn.disabled = disabled;
                    btn.onclick = () => {{ curPage = page; render(); }};
                    return btn;
                }};

                pgControls.appendChild(createBtn('‹', curPage-1, curPage===1));
                pgControls.appendChild(createBtn('›', curPage+1, curPage===totalPages));
            }}

            searchInput.addEventListener('input', (e) => {{
                const term = e.target.value.toLowerCase();
                filtered = DATA.filter(item => 
                    (item.type || '').toLowerCase().includes(term) ||
                    (item.file || '').toLowerCase().includes(term) ||
                    (item.context || '').toLowerCase().includes(term)
                );
                curPage = 1;
                render();
            }});

            window.copyText = function(text) {{
                navigator.clipboard.writeText(text).then(() => {{
                    // Feedback visual sutil poderia ser adicionado aqui
                    console.log('Copiado:', text);
                }});
            }};

            render();
        </script>
    </body>
    </html>
    """
    
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        print(f"Erro ao gerar HTML de segredos: {e}")

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
    import html as html_lib 
    
    content_block = ""
    is_ds_store = "DS_Store" in title
    
    if is_text:
        if is_ds_store:
            lines = content_data.strip().split('\n')
            rows = ""
            count = 0
            for line in lines:
                if line.strip() and not line.startswith("===") and not line.startswith("[!]"):
                    rows += f"""
                    <tr>
                        <td class="mono"><a href="{line.strip()}" target="_blank">{line.strip()}</a></td>
                        <td style="text-align:right;"><a href="{line.strip()}" target="_blank" class="btn-icon">🔗</a></td>
                    </tr>
                    """
                    count += 1
            
            content_block = f"""
            <div class="controls">
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="searchInput" placeholder="Filtrar arquivos...">
                </div>
            </div>
            <div class="table-container">
                <table id="dataTable">
                    <thead>
                        <tr>
                            <th>URL Recuperada</th>
                            <th style="width: 50px;">Ação</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                        {rows}
                    </tbody>
                </table>
            </div>
            <div class="meta-footer">Total de arquivos: {count}</div>
            """
        else:
            safe_content = html_lib.escape(content_data)
            
            content_block = f"""
            <div class="code-card">
                <div class="code-header">
                    <span class="lang-tag">TEXT / CONFIG</span>
                    <button class="btn-copy" onclick="copyCode()">📋 Copiar Conteúdo</button>
                </div>
                <pre><code id="fileContent">{safe_content}</code></pre>
            </div>
            """
    else:
        content_block = f"""
        <div class="binary-card">
            <div class="binary-icon">📦</div>
            <h3>Arquivo Binário Capturado</h3>
            <p>Este arquivo não pode ser exibido no navegador.</p>
            <p class="path-info">Salvo em: <code>_files/misc/</code></p>
            <div class="alert-box">
                <strong>Análise Recomendada:</strong> Utilize ferramentas como <code>sqlite3</code> (para .db), 
                <code>strings</code> ou um visualizador Hexadecimal.
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vazamento: {title}</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-body: #0f111a;
                --bg-card: #1a1d2d;
                --text-primary: #e2e8f0;
                --text-secondary: #94a3b8;
                --accent-color: #6366f1;
                --border-color: #2d3748;
                --success: #10b981;
                --warning: #f59e0b;
                --danger: #ef4444;
            }}
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                background-color: var(--bg-body); color: var(--text-primary);
                font-family: 'Inter', sans-serif; padding: 2rem; min-height: 100vh;
            }}
            .container {{ max-width: 1000px; margin: 0 auto; }}

            /* Header */
            .header {{
                background: var(--bg-card); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--border-color);
                margin-bottom: 1.5rem; display: flex; align-items: center; justify-content: space-between;
            }}
            .header h1 {{ font-size: 1.2rem; font-weight: 600; color: var(--warning); display: flex; align-items: center; gap: 10px; }}
            
            .btn-back {{
                padding: 0.5rem 1rem; background: transparent; border: 1px solid var(--border-color);
                color: var(--text-secondary); border-radius: 6px; text-decoration: none; font-size: 0.9rem; transition: 0.2s;
            }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}

            /* Code View (.env) */
            .code-card {{
                background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border-color); overflow: hidden;
            }}
            .code-header {{
                background: rgba(0,0,0,0.2); padding: 0.5rem 1rem; border-bottom: 1px solid var(--border-color);
                display: flex; justify-content: space-between; align-items: center;
            }}
            .lang-tag {{ font-size: 0.75rem; font-weight: bold; color: var(--text-secondary); }}
            .btn-copy {{
                background: var(--accent-color); border: none; color: white; padding: 4px 10px;
                border-radius: 4px; cursor: pointer; font-size: 0.8rem;
            }}
            .btn-copy:hover {{ opacity: 0.9; }}
            pre {{ margin: 0; padding: 1.5rem; overflow-x: auto; }}
            code {{ font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #a5b4fc; }}

            /* Table View (.DS_Store) */
            .table-container {{
                background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border-color); overflow: hidden;
            }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ background: rgba(255,255,255,0.03); padding: 1rem; text-align: left; color: var(--text-secondary); font-weight: 500; }}
            td {{ padding: 0.8rem 1rem; border-top: 1px solid var(--border-color); }}
            a {{ color: var(--accent-color); text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            .btn-icon {{ text-decoration: none; font-size: 1.1rem; }}

            /* Binary View */
            .binary-card {{
                background: var(--bg-card); padding: 3rem; border-radius: 8px; border: 1px solid var(--border-color);
                text-align: center;
            }}
            .binary-icon {{ font-size: 3rem; margin-bottom: 1rem; }}
            .path-info {{ background: #000; display: inline-block; padding: 5px 10px; border-radius: 4px; margin: 10px 0; font-family: monospace; color: var(--success); }}
            .alert-box {{ 
                margin-top: 20px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); 
                color: var(--warning); padding: 1rem; border-radius: 6px; font-size: 0.9rem; display: inline-block;
            }}

            /* Utils */
            .search-box {{ margin-bottom: 1rem; position: relative; }}
            .search-box input {{
                width: 100%; padding: 0.6rem 1rem 0.6rem 2.5rem; background: var(--bg-card);
                border: 1px solid var(--border-color); border-radius: 6px; color: #fff;
            }}
            .search-icon {{ position: absolute; left: 10px; top: 50%; transform: translateY(-50%); }}
            .meta-footer {{ text-align: center; margin-top: 2rem; color: var(--text-secondary); font-size: 0.8rem; }}

        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>⚠️ {title}</h1>
                <a href="report.html" class="btn-back">← Voltar ao Painel</a>
            </div>

            {content_block}

            <div class="meta-footer">Git Leak Explorer • Artifact Analysis</div>
        </div>

        <script>
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {{
                searchInput.addEventListener('input', function(e) {{
                    const term = e.target.value.toLowerCase();
                    const rows = document.querySelectorAll('#tableBody tr');
                    rows.forEach(row => {{
                        const text = row.innerText.toLowerCase();
                        row.style.display = text.includes(term) ? '' : 'none';
                    }});
                }});
            }}

            function copyCode() {{
                const content = document.getElementById('fileContent').innerText;
                navigator.clipboard.writeText(content).then(() => {{
                    const btn = document.querySelector('.btn-copy');
                    const original = btn.innerText;
                    btn.innerText = "✅ Copiado!";
                    setTimeout(() => btn.innerText = original, 2000);
                }});
            }}
        </script>
    </body>
    </html>
    """

    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


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
            
            elif "min_len" in sig:
                if len(data) >= sig["min_len"]: is_valid = True

            if is_valid:
                success(f"Vazamento Confirmado: {sig['desc']}")
                
                filename = key + "_dump"
                if key == "env": filename = ".env"
                elif key == "svn": filename = "wc.db"
                elif key == "ds_store": filename = "DS_Store_dump"
                elif key == "exclude": filename = "info_exclude.txt"
                elif key == "description": filename = "description.txt"
                elif key == "commit_msg": filename = "COMMIT_EDITMSG.txt"
                elif "hook" in key: filename = "hook_script.sh"

                dump_path = os.path.join(misc_dir, filename)

                with open(dump_path, "wb") as f:
                    f.write(data)

                html_name = f"{key}_report.html"
                content_display = ""
                
                text_keys = ["env", "exclude", "description", "commit_msg", "hook_sample", "hook_active"]
                is_text = key in text_keys
                
                if is_text:
                    try:
                        content_display = data.decode("utf-8", "ignore")
                    except:
                        content_display = "[Erro na decodificação de texto]"
                        is_text = False

                elif key == "ds_store":
                    try:
                        extracted_files = parse_ds_store(dump_path)
                        full_urls = [f"{base}/{f}" for f in extracted_files]
                        if extracted_files:
                            is_text = True
                            content_display = "=== URLs EXTRAÍDAS DO .DS_Store ===\n\n" + "\n".join(full_urls)
                        else:
                            is_text = True
                            content_display = "=== ARQUIVO .DS_Store VÁLIDO ===\n\nSem registros visíveis."
                    except Exception as e:
                        content_display = f"Erro: {e}"

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
    info("Coletando inteligência (Config, Logs, Refs, Info/Refs)...")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"

    meta_dir = os.path.join(outdir, "_files", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    
    intel = {"remote_url": None, "logs": [], "packed_refs": [], "info_refs": []}

    ok, data = http_get_bytes(base + "/config", proxies=proxies)
    if ok:
        cfg_path = os.path.join(meta_dir, "config")
        with open(cfg_path, "wb") as f: f.write(data)
        intel["remote_url"] = parse_git_config_file(cfg_path)
        if intel["remote_url"]: success(f"Remote Origin detectado: {intel['remote_url']}")

    ok, data = http_get_bytes(base + "/logs/HEAD" , proxies=proxies)
    if ok:
        log_path = os.path.join(meta_dir, "logs_HEAD")
        with open(log_path, "wb") as f: f.write(data)
        intel["logs"] = parse_git_log_file(log_path)
        success(f"Logs de histórico recuperados: {len(intel['logs'])} entradas.")

    ok, data = http_get_bytes(base + "/packed-refs" , proxies=proxies)
    if ok:
        pr_path = os.path.join(meta_dir, "packed-refs")
        with open(pr_path, "wb") as f: f.write(data)
        refs = []
        for line in data.decode(errors='ignore').splitlines():
            if not line.startswith("#") and " " in line:
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    refs.append({"sha": parts[0], "ref": parts[1].strip()})
        intel["packed_refs"] = refs

    ok, data = http_get_bytes(base + "/info/refs", proxies=proxies)
    if ok:
        ir_path = os.path.join(meta_dir, "info_refs")
        with open(ir_path, "wb") as f: f.write(data)
        
        info_refs_list = []
        content = data.decode(errors='ignore')
        
        matches = re.findall(r'([0-9a-f]{40})\s+([^\s]+)', content)
        
        for sha, ref in matches:
            info_refs_list.append({"sha": sha, "ref": ref})
            
        intel["info_refs"] = info_refs_list
        if info_refs_list:
            success(f"Info/Refs recuperado: {len(info_refs_list)} referências encontradas.")

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

    info_refs_url = base + "/info/refs"
    ok, data = http_get_bytes(info_refs_url, proxies=proxies)
    if ok:
        content = data.decode(errors='ignore')
        matches = re.findall(r'([0-9a-f]{40})\s+([^\s]+)', content)
        for sha, ref in matches:
            if sha not in candidates:
                candidates[sha] = {"sha": sha, "ref": ref, "source": info_refs_url}

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
                  "config": [base + "/config", base + "/.git/config"],
                  "stash": [base + "/refs/stash", base + "/.git/refs/stash"],
                  "info_refs": [base + "/info/refs", base + "/.git/info/refs"]}
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
    import json
    
    rows = []
    descr_map = {
        "HEAD": ".git/HEAD acessível", 
        "refs_heads": ".git/refs/heads/ acessível",
        "packed_refs": ".git/packed-refs acessível", 
        "index": ".git/index acessível",
        "objects_root": ".git/objects/ acessível", 
        "logs": ".git/logs/ acessível",
        "config": ".git/config acessível",
        "stash": ".git/refs/stash",
        "info_refs": ".git/info/refs (Mapa de Referências/SmartHTTP)"
    }
    
    total_score = 0
    
    for k, v in report.get("results", {}).items():
        exposed = v.get("exposed", False)
        
        evidence = "; ".join([f"{p.get('method', '?')} {p.get('url')} ({p.get('status_code', '?')})" for p in v.get("positive_urls", [])]) or "-"
        
        status = "OK"
        action = "Nenhuma ação necessária."
        
        if exposed:
            if k in ("index", "objects_root", "config", "stash", "info_refs"):
                status = "CRÍTICO"
                total_score += 5
                action = "Bloquear acesso imediatamente (HTTP 403) via .htaccess ou regras do servidor."
            else:
                status = "ATENÇÃO"
                total_score += 2
                action = "Restringir acesso. Arquivo pode revelar estrutura interna."
        
        description = descr_map.get(k, k)
        
        rows.append({
            "category": k, 
            "description": description, 
            "status": status, 
            "evidence": evidence,
            "action": action
        })
    
    risk_label = "SEGURO"
    risk_color = "var(--success)"
    
    if total_score >= 10:
        risk_label = "CRÍTICO"
        risk_color = "var(--danger)"
    elif total_score > 0:
        risk_label = "MODERADO"
        risk_color = "var(--warning)"

    data_json = json.dumps(rows, ensure_ascii=False)

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Relatório de Hardening</title>
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
                --danger: #ef4444;
                --warning: #f59e0b;
                --risk-color: {risk_color};
            }}

            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
            body {{
                background-color: var(--bg-body);
                color: var(--text-primary);
                font-family: 'Inter', sans-serif;
                min-height: 100vh;
                padding: 2rem;
            }}

            .container {{ max-width: 1200px; margin: 0 auto; }}

            /* Header */
            .header {{
                background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border-color);
                padding: 2rem; margin-bottom: 2rem; display: flex; align-items: center; justify-content: space-between;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
            }}
            .header-info h1 {{ font-size: 1.8rem; font-weight: 700; margin-bottom: 0.5rem; color: #fff; }}
            .header-info p {{ color: var(--text-secondary); }}

            .score-card {{
                text-align: center; padding: 1rem 2rem; border-left: 1px solid var(--border-color);
            }}
            .score-val {{ font-size: 2.5rem; font-weight: 800; color: var(--risk-color); line-height: 1; }}
            .score-lbl {{ font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; }}

            /* Controls */
            .controls {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
            .btn-back {{
                display: inline-flex; align-items: center; padding: 0.6rem 1.2rem;
                background-color: var(--bg-card); color: var(--text-primary);
                text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color);
                font-size: 0.9rem; transition: all 0.2s;
            }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}

            .search-box {{ flex: 1; position: relative; }}
            .search-box input {{
                width: 100%; padding: 0.6rem 1rem 0.6rem 2.5rem;
                background-color: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 6px; color: var(--text-primary); font-size: 0.9rem;
            }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); pointer-events: none; }}

            /* Table */
            .table-container {{
                background-color: var(--bg-card); border-radius: 8px;
                border: 1px solid var(--border-color); overflow: hidden;
            }}
            table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
            
            th {{
                background: rgba(255,255,255,0.03); padding: 1rem; text-align: left;
                color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--border-color);
            }}
            td {{ padding: 1rem; border-bottom: 1px solid var(--border-color); vertical-align: middle; }}
            tbody tr:hover {{ background-color: var(--bg-hover); }}

            /* Badges & Status */
            .badge {{
                padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.75rem;
                text-transform: uppercase; letter-spacing: 0.05em; display: inline-block;
            }}
            .status-ok {{ background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }}
            .status-warn {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }}
            .status-crit {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }}

            /* Typography */
            .cat-name {{ font-weight: 600; color: #fff; margin-bottom: 2px; }}
            .cat-desc {{ color: var(--text-secondary); font-size: 0.85rem; }}
            .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #a5b4fc; word-break: break-all; }}
            .action-text {{ font-style: italic; color: #64748b; font-size: 0.85rem; }}

            /* Row Highlight for Issues */
            .row-issue {{ background: rgba(239, 68, 68, 0.03); }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="header-info">
                    <h1>🛡 Hardening Report</h1>
                    <p>Auditoria de exposição de diretórios e arquivos de configuração Git.</p>
                </div>
                <div class="score-card">
                    <div class="score-val">{risk_label}</div>
                    <div class="score-lbl">Score de Risco: {total_score}</div>
                </div>
            </div>

            <div class="controls">
                <a href="report.html" class="btn-back">&larr; Voltar ao Painel</a>
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input id="search" type="text" placeholder="Filtrar por categoria, status ou evidência...">
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 30%">Categoria / Descrição</th>
                            <th style="width: 15%">Status</th>
                            <th style="width: 30%">Evidência Técnica</th>
                            <th style="width: 25%">Ação Recomendada</th>
                        </tr>
                    </thead>
                    <tbody id="tbody"></tbody>
                </table>
            </div>
            
            <p style="text-align:center; margin-top:30px; color:#555; font-size:0.8rem;">
                Git Leak Explorer • Security Module
            </p>
        </div>

        <script>
            const ROWS = {data_json};
            const tbody = document.getElementById('tbody');
            const search = document.getElementById('search');

            function renderTable(data) {{
                tbody.innerHTML = '';
                data.forEach(r => {{
                    const tr = document.createElement('tr');
                    
                    // Definição de Classes e Badges
                    let badgeClass = 'status-ok';
                    let rowClass = '';
                    
                    if (r.status === 'ATENÇÃO') {{
                        badgeClass = 'status-warn';
                        rowClass = 'row-issue';
                    }} else if (r.status === 'CRÍTICO') {{
                        badgeClass = 'status-crit';
                        rowClass = 'row-issue';
                    }}

                    if (rowClass) tr.className = rowClass;

                    tr.innerHTML = `
                        <td>
                            <div class="cat-name">${{r.category}}</div>
                            <div class="cat-desc">${{r.description}}</div>
                        </td>
                        <td><span class="badge ${{badgeClass}}">${{r.status}}</span></td>
                        <td class="mono">${{r.evidence}}</td>
                        <td class="action-text">${{r.action}}</td>
                    `;
                    tbody.appendChild(tr);
                }});
            }}

            search.addEventListener('input', (e) => {{
                const q = e.target.value.toLowerCase();
                const filtered = ROWS.filter(r => 
                    r.category.toLowerCase().includes(q) || 
                    r.description.toLowerCase().includes(q) || 
                    r.status.toLowerCase().includes(q) ||
                    r.evidence.toLowerCase().includes(q)
                );
                renderTable(filtered);
            }});

            // Render Inicial
            renderTable(ROWS);
        </script>
    </body>
    </html>
    """
    
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
    info("Gerando Dashboard Unificado (report.html)...")
    files_dir = os.path.join(outdir, "_files")
    
    try: hardening = json.load(open(os.path.join(files_dir, "hardening_report.json")))
    except: hardening = {}

    try: misc = json.load(open(os.path.join(files_dir, "misc_leaks.json")))
    except: misc = []

    try: packs = json.load(open(os.path.join(files_dir, "packfiles.json")))
    except: packs = []

    try:
        listing_entries = load_dump_entries(os.path.join(files_dir, "dump.json"))
        listing_count = len(listing_entries)
    except:
        listing_entries = []
        listing_count = 0

    try:
        history_data = json.load(open(os.path.join(files_dir, "history.json")))
        commits = history_data.get('commits', [])
        head_sha = history_data.get('head', 'N/A')
    except:
        history_data = {}
        commits = []
        head_sha = "N/A"

    try: bruteforce_data = json.load(open(os.path.join(files_dir, "bruteforce.json")))
    except: bruteforce_data = []

    try: users_data = json.load(open(os.path.join(files_dir, "users.json")))
    except: users_data = []
    
    try: secrets_data = json.load(open(os.path.join(files_dir, "secrets.json")))
    except: secrets_data = []

    try: stash_entries = load_dump_entries(os.path.join(files_dir, "stash.json"))
    except: stash_entries = []

    stash_section = ""
    if stash_entries:
        stash_rows = ""
        # Lista apenas os 5 primeiros para não poluir
        for e in stash_entries[:5]:
            path = e.get('path', '')
            sha = e.get('sha1', '')[:7]
            stash_rows += f"""
            <tr>
                <td class="mono">{path}</td>
                <td class="text-right"><a href="{make_blob_url_from_git(base_url, e.get('sha1', ''))}" target="_blank" class="link-icon">Ver Blob</a></td>
            </tr>
            """
        
        stash_section = f"""
        <div class="card mb-4" style="border: 1px solid #f59e0b;">
            <div class="card-header d-flex justify-content-between" style="background: rgba(245, 158, 11, 0.1); color: #f59e0b;">
                <span>💾 Git Stash Recuperado</span>
                <span class="badge bg-warning text-dark">{len(stash_entries)} Arquivos</span>
            </div>
            <div class="card-body">
                <div class="alert-box" style="margin-bottom:15px; font-size:0.85rem; color:#ccc;">
                    O Stash contém modificações que não foram commitadas. Examine estes arquivos com prioridade.
                </div>
                <table class="table-simple">
                    {stash_rows}
                </table>
                <p class="text-center mt-2 small muted">... e mais {max(0, len(stash_entries) - 5)} arquivos.</p>
                <a href="_files/stash.json" target="_blank" class="btn btn-outline w-100">Ver JSON Completo</a>
            </div>
        </div>
        """

    hardening_rows = ""
    h_vuln_count = 0
    for k, v in hardening.get("results", {}).items():
        if v.get('exposed'):
            h_vuln_count += 1
            hardening_rows += f"<tr><td>{k}</td><td><span class='badge bg-danger'>EXPOSTO</span></td></tr>"
        else:
            hardening_rows += f"<tr><td>{k}</td><td><span class='badge bg-success'>OK</span></td></tr>"
    
    hardening_card = f"""
    <div class="card">
        <div class="card-header d-flex justify-content-between">
            <span>🛡 Hardening & Config</span>
            <span class="badge {'bg-danger' if h_vuln_count > 0 else 'bg-success'}">
                {h_vuln_count} Falhas
            </span>
        </div>
        <div class="card-body">
            <table class="table-simple">
                {hardening_rows}
            </table>
            <a href="hardening_report.html" class="btn btn-outline w-100 mt-3">Ver Diagnóstico Completo</a>
        </div>
    </div>
    """

    users_card = f"""
    <div class="card">
        <div class="card-header">👤 Identidades (OSINT)</div>
        <div class="card-body text-center">
            <div class="big-stat">{len(users_data)}</div>
            <div class="stat-label">Autores Identificados</div>
            <p class="muted small mt-2">Desenvolvedores e e-mails extraídos do histórico.</p>
            <a href="users.html" class="btn btn-primary w-100 mt-2">Ver Lista de Usuários</a>
        </div>
    </div>
    """

    hist_rows = ""
    for c in commits[:5]:
        msg = c.get('message', '').splitlines()[0][:50]
        msg = msg.replace("<", "&lt;").replace(">", "&gt;")
        sha = c.get('sha', '')[:7]
        hist_rows += f"""
        <tr>
            <td class="mono"><span style="color:var(--hash-color)">{sha}</span></td>
            <td>{msg}...</td>
            <td class="text-right"><span class="badge bg-secondary">{c.get('date', '').split(' ')[0]}</span></td>
        </tr>
        """
    
    history_card = f"""
    <div class="card">
        <div class="card-header d-flex justify-content-between">
            <span>⏳ Histórico Recente</span>
            <span class="badge bg-info">{len(commits)} Commits</span>
        </div>
        <div class="card-body">
            <div class="meta mb-3">HEAD: <span class="mono">{head_sha[:8]}</span></div>
            <table class="table-simple">
                {hist_rows}
            </table>
            <a href="history.html" class="btn btn-outline w-100 mt-3">Explorar Timeline Completa</a>
        </div>
    </div>
    """

    list_rows = ""
    for e in listing_entries[:10]:
        path = e.get('path', '')
        sha = e.get('sha1', '')[:7]
        list_rows += f"""
        <tr>
            <td class="mono">{path}</td>
            <td class="text-right"><a href="{make_blob_url_from_git(base_url, e.get('sha1', ''))}" target="_blank" class="link-icon">Blob Remoto</a></td>
        </tr>
        """

    listing_card = f"""
    <div class="card">
        <div class="card-header d-flex justify-content-between">
            <span>📂 Arquivos (.git Index)</span>
            <span class="badge bg-warning text-dark">{listing_count} Arquivos</span>
        </div>
        <div class="card-body">
            <table class="table-simple">
                {list_rows}
            </table>
            <p class="text-center mt-2 small muted">... e mais {max(0, listing_count - 10)} arquivos.</p>
            <a href="listing.html" class="btn btn-outline w-100">Ver Listagem Completa</a>
        </div>
    </div>
    """

    bf_section = ""
    if bruteforce_data:
        generate_bruteforce_report(bruteforce_data, os.path.join(outdir, "bruteforce_report.html"))
        
        preview_rows = ""
        for item in bruteforce_data[:5]:
            fname = item.get("filename", "unknown")
            fsource = item.get("list_source", "PADRÃO")
            furl = item.get("url", "#")
            
            b_cls = "bg-primary"
            if "Custom" in fsource: b_cls = "bg-purple"
            elif "Traversal" in fsource: b_cls = "bg-warning text-dark"

            preview_rows += f"""
            <tr>
                <td><span class='badge {b_cls}'>{fsource}</span></td>
                <td>{fname}</td>
                <td class="text-right"><a href='{furl}' target='_blank'>Link</a></td>
            </tr>
            """
        
        bf_section = f"""
        <div class="card mb-4">
            <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <span>🔨 Arquivos via Brute-Force</span>
                <span class="badge bg-light text-primary">{len(bruteforce_data)}</span>
            </div>
            <div class="card-body">
                <table class="table-simple">
                    <thead><tr><th>Origem</th><th>Arquivo</th><th>Ação</th></tr></thead>
                    <tbody>{preview_rows}</tbody>
                </table>
                <div class="text-center mt-3">
                    <a href="bruteforce_report.html" class="btn btn-primary w-100">Ver Relatório de Brute-Force Completo</a>
                </div>
            </div>
        </div>
        """

    secrets_section = ""
    if secrets_data:
        s_rows = ""
        for s in secrets_data:
            s_rows += f"""
            <tr>
                <td><span class="badge bg-danger">{s['type']}</span></td>
                <td>{s['file']}</td>
                <td class="mono small">{s['match']}</td>
            </tr>
            """
        secrets_section = f"""
        <div class="card mb-4 border-danger">
            <div class="card-header bg-danger text-white">
                <h3 class="m-0" style="font-size:1.1rem">⚠️ SEGREDOS CRÍTICOS DETECTADOS ({len(secrets_data)})</h3>
            </div>
            <div class="card-body">
                <table class="table-simple">
                    {s_rows}
                </table>
                <a href="secrets.html" class="btn btn-outline-danger w-100 mt-2">Ver Relatório de Segredos</a>
            </div>
        </div>
        """

    misc_content = "<p class='muted small'>Nenhum vazamento extra.</p>"
    if misc:
        misc_rows = ""
        for m in misc:
            dump_file = m.get('dump_file', "")
            link = m.get('report_file') if m.get('report_file') else f"_files/misc/{dump_file}"
            misc_rows += f"<li style='margin-bottom:5px;'><strong>{m['type'].upper()}</strong>: <a href='{link}' target='_blank'>Ver Análise</a></li>"
        misc_content = f"<ul style='list-style:none; padding:0;'>{misc_rows}</ul>"

    pack_content = "<p class='muted small'>Nenhum packfile detectado.</p>"
    if packs:
        pack_list_items = ""
        for p in packs:
            local_href = f"_files/packs/{p['name']}"
            
            st = p.get('status', '')
            st_style = "color: var(--text-secondary);"
            if "Baixado" in st or "Extraído" in st:
                st_style = "color: var(--success);"
            elif "Falha" in st:
                st_style = "color: var(--danger);"

            pack_list_items += f"""
            <li style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 0.85rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">
                <a href="{local_href}" download class="mono" style="text-decoration:none; color: var(--accent-color); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width: 75%;" title="Baixar {p['name']}">{p['name']}</a>
                <span style="{st_style} font-size: 0.75rem;">{st}</span>
            </li>
            """
        pack_content = f"<ul style='list-style:none; padding:0; margin:0; max-height: 180px; overflow-y: auto;'>{pack_list_items}</ul>"

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard - Git Leak Explorer</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-body: #0f111a;
                --bg-card: #1a1d2d;
                --text-primary: #e2e8f0;
                --text-secondary: #94a3b8;
                --accent-color: #6366f1;
                --border-color: #2d3748;
                --success: #10b981;
                --danger: #ef4444;
                --warning: #f59e0b;
                --info: #3b82f6;
                --hash-color: #ec4899;
            }}
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                background-color: var(--bg-body); color: var(--text-primary);
                font-family: 'Inter', sans-serif; padding: 20px;
            }}
            .container {{ max-width: 1200px; margin: 0 auto; }}

            /* Typography */
            h1 {{ font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem; }}
            .muted {{ color: var(--text-secondary); }}
            .small {{ font-size: 0.85rem; }}
            .mono {{ font-family: 'JetBrains Mono', monospace; }}

            /* Grid & Cards */
            .dashboard-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
            @media (max-width: 768px) {{ .dashboard-grid {{ grid-template-columns: 1fr; }} }}

            .card {{ background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; display: flex; flex-direction: column; }}
            .card-header {{ padding: 12px 16px; background: rgba(255,255,255,0.03); border-bottom: 1px solid var(--border-color); font-weight: 600; font-size: 0.95rem; display: flex; align-items: center; }}
            .card-body {{ padding: 16px; flex: 1; }}
            .mb-4 {{ margin-bottom: 1.5rem; }}

            /* Tables */
            .table-simple {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
            .table-simple td {{ padding: 8px 0; border-bottom: 1px solid var(--border-color); }}
            .table-simple tr:last-child td {{ border-bottom: none; }}
            .text-right {{ text-align: right; }}

            /* Badges */
            .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
            .bg-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }}
            .bg-success {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }}
            .bg-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }}
            .bg-info {{ background: rgba(59, 130, 246, 0.2); color: var(--info); border: 1px solid rgba(59, 130, 246, 0.3); }}
            .bg-primary {{ background: rgba(99, 102, 241, 0.2); color: var(--accent-color); border: 1px solid rgba(99, 102, 241, 0.3); }}
            .bg-secondary {{ background: #333; color: #ccc; }}
            .bg-purple {{ background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); }}
            
            .text-white {{ color: #fff !important; }}
            .d-flex {{ display: flex; }}
            .justify-content-between {{ justify-content: space-between; }}
            .align-items-center {{ align-items: center; }}
            .w-100 {{ width: 100%; }}
            .mt-2 {{ margin-top: 0.5rem; }} .mt-3 {{ margin-top: 1rem; }}
            .m-0 {{ margin: 0; }}

            /* Buttons */
            .btn {{ display: inline-block; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 0.9rem; text-align: center; transition: 0.2s; cursor: pointer; border: 1px solid transparent; }}
            .btn-primary {{ background: var(--accent-color); color: #fff; }}
            .btn-primary:hover {{ opacity: 0.9; }}
            .btn-outline {{ background: transparent; border: 1px solid var(--border-color); color: var(--text-primary); }}
            .btn-outline:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}
            .btn-outline-danger {{ border: 1px solid var(--danger); color: var(--danger); }}
            .btn-outline-danger:hover {{ background: var(--danger); color: white; }}

            .big-stat {{ font-size: 3rem; font-weight: 800; color: #fff; line-height: 1; }}
            .stat-label {{ text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px; color: var(--text-secondary); }}

            footer {{ margin-top: 40px; text-align: center; color: var(--text-secondary); font-size: 0.8rem; border-top: 1px solid var(--border-color); padding-top: 20px; }}
            a {{ color: var(--accent-color); text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h1>Git Leak Explorer</h1>
                    <p class="muted">Relatório de Análise Técnica</p>
                </div>
                <div class="text-right">
                    <p class="small muted mb-0">Alvo:</p>
                    <a href="{base_url}" target="_blank" style="font-weight:bold;">{base_url}</a>
                </div>
            </div>

            {secrets_section}

            {stash_section}

            <div class="dashboard-grid">
                <div>
                    {hardening_card}
                    <div style="margin-top:20px;"></div>
                    {history_card}
                </div>
                <div>
                    {users_card}
                    <div style="margin-top:20px;"></div>
                    {listing_card}
                </div>
            </div>

            {bf_section}

            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header d-flex justify-content-between">
                        <span>📦 Packfiles</span>
                        <span class="badge bg-secondary">{len(packs)}</span>
                    </div>
                    <div class="card-body">
                        {pack_content}
                    </div>
                </div>
                <div class="card">
                    <div class="card-header d-flex justify-content-between">
                        <span>⚠️ Outros Vazamentos (--full-scan)</span>
                        <span class="badge bg-secondary">{len(misc)}</span>
                    </div>
                    <div class="card-body">
                        {misc_content}
                    </div>
                </div>
            </div>

            <footer>
                <p>Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
                <p>Git Leak Explorer • Pentest & Forensic Tool</p>
            </footer>
        </div>
    </body>
    </html>
    """

    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)
    
    success(f"Dashboard Unificado Gerado: {os.path.join(outdir, 'report.html')}")

def make_listing_modern(json_file: str, base_git_url: str, outdir: str):
    info(f"Gerando Dashboard de Listagem para {json_file}")
    
    import json, os
    try:
        entries = load_dump_entries(json_file)
    except Exception as e:
        warn(f"Não foi possível carregar index ({e}). Gerando HTML vazio."); entries = []
    
    site_base = normalize_site_base(base_git_url)
    rows = []
    
    for e in entries:
        path = e.get("path", "")
        sha = e.get("sha1", "")
        if not sha: continue
        
        local_path_rel = path.lstrip("/")
        local_full_path = os.path.join(outdir, local_path_rel)
        local_exists = os.path.exists(local_full_path)
        
        local_url = f"file://{os.path.abspath(local_full_path)}"
        
        rows.append({
            "path": path,
            "remote_url": join_remote_file(site_base, path),
            "blob_url": make_blob_url_from_git(base_git_url, sha),
            "sha": sha,
            "local_exists": local_exists,
            "local_url": local_url
        })

    data_json = json.dumps(rows, ensure_ascii=False)
    
    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Arquivos Recuperados - Git Leak Explorer</title>
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
                --hash-color: #ec4899;
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
                display: flex; justify-content: space-between; align-items: center;
                margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);
            }}
            .title h1 {{ font-size: 1.5rem; font-weight: 600; color: #fff; }}
            .title p {{ color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }}
            
            .stats {{ background: var(--bg-card); padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.9rem; color: var(--text-secondary); }}
            .highlight {{ color: var(--accent-color); font-weight: 600; }}

            /* Controls Bar */
            .controls {{
                display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; align-items: center;
            }}
            
            .btn-back {{
                display: inline-flex; align-items: center; padding: 0.6rem 1rem;
                background-color: var(--bg-card); color: var(--text-primary);
                text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color);
                font-size: 0.9rem; transition: all 0.2s;
            }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}

            .search-box {{ flex: 1; position: relative; max-width: 500px; }}
            .search-box input {{
                width: 100%; padding: 0.6rem 1rem 0.6rem 2.5rem;
                background-color: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 6px; color: var(--text-primary); font-size: 0.9rem;
            }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); pointer-events: none; }}

            .select-box select {{
                padding: 0.6rem; background-color: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 6px; color: var(--text-primary); cursor: pointer;
            }}

            .btn-reset {{
                padding: 0.6rem 1rem; background: transparent; border: 1px solid var(--border-color);
                color: var(--text-secondary); border-radius: 6px; cursor: pointer; transition: 0.2s;
            }}
            .btn-reset:hover {{ background: rgba(255,255,255,0.05); color: #fff; }}

            /* Table */
            .table-container {{
                background-color: var(--bg-card); border-radius: 8px;
                border: 1px solid var(--border-color); overflow: hidden;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }}

            table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }}
            
            th {{
                background-color: rgba(255,255,255,0.03); padding: 1rem; text-align: left;
                font-weight: 500; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);
                cursor: pointer; user-select: none;
            }}
            th:hover {{ color: var(--accent-color); }}
            
            td {{ padding: 0.8rem 1rem; border-bottom: 1px solid var(--border-color); vertical-align: middle; }}
            tbody tr:hover {{ background-color: var(--bg-hover); }}

            /* Column Widths */
            th:nth-child(1) {{ width: 45%; }} /* Arquivo */
            th:nth-child(2) {{ width: 20%; }} /* Local */
            th:nth-child(3) {{ width: 10%; }} /* Remoto */
            th:nth-child(4) {{ width: 25%; }} /* Blob */

            /* Typography */
            .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }}
            .path-text {{ color: #e2e8f0; word-break: break-all; }}
            
            .hash-link {{ color: var(--hash-color); text-decoration: none; }}
            .hash-link:hover {{ text-decoration: underline; }}

            /* Badges */
            .badge {{
                padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700;
                text-transform: uppercase; letter-spacing: 0.05em; display: inline-flex; align-items: center; gap: 5px;
            }}
            .badge-success {{ background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }}
            .badge-missing {{ background: rgba(148, 163, 184, 0.15); color: var(--text-secondary); border: 1px solid rgba(148, 163, 184, 0.3); }}

            .link-icon {{ color: var(--accent-color); text-decoration: none; font-size: 0.9rem; }}
            .link-icon:hover {{ text-decoration: underline; }}

            /* Pagination */
            .pagination-container {{
                display: flex; justify-content: space-between; align-items: center;
                padding: 1rem; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 0.9rem;
            }}
            .page-btn {{
                background: var(--bg-card); border: 1px solid var(--border-color);
                color: var(--text-primary); width: 32px; height: 32px; border-radius: 6px;
                display: flex; align-items: center; justify-content: center;
                cursor: pointer; transition: all 0.2s;
            }}
            .page-btn:hover:not(:disabled) {{ border-color: var(--accent-color); color: var(--accent-color); }}
            .page-btn.active {{ background: var(--accent-color); border-color: var(--accent-color); color: white; }}
            .page-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}

        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div class="title">
                    <h1>Arquivos Recuperados</h1>
                    <p>Índice completo do repositório (.git/index)</p>
                </div>
                <div class="stats">
                    Total: <span class="highlight">{len(rows)}</span> arquivos
                </div>
            </header>

            <div class="controls">
                <a href="report.html" class="btn-back">← Voltar</a>
                
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="q" placeholder="Buscar por nome, extensão ou SHA...">
                </div>

                <div class="select-box">
                    <select id="pageSize">
                        <option value="25">25 por pág</option>
                        <option value="50">50 por pág</option>
                        <option value="100" selected>100 por pág</option>
                        <option value="500">500 por pág</option>
                    </select>
                </div>

                <button id="reset" class="btn-reset">Limpar Filtros</button>
            </div>

            <div class="table-container">
                <table id="tbl">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="path">Nome do Arquivo ↕</th>
                            <th>Status Local</th>
                            <th>Remoto</th>
                            <th class="sortable" data-sort="sha">Blob SHA-1 ↕</th>
                        </tr>
                    </thead>
                    <tbody id="tbody">
                        </tbody>
                </table>
            </div>

            <div class="pagination-container">
                <div id="entriesInfo">Carregando...</div>
                <div style="display:flex; gap:5px;">
                    <button id="prev" class="page-btn">‹</button>
                    <span id="pageDisplay" style="display:flex; align-items:center; padding:0 10px;">1</span>
                    <button id="next" class="page-btn">›</button>
                </div>
            </div>
            
            <p style="text-align:center; color:#555; margin-top:2rem; font-size:0.8rem;">
                Git Leak Explorer • Index Parsing
            </p>
        </div>

        <script>
            const DATA = {data_json};
            
            // Estado
            let filtered = DATA.slice();
            let sortKey = null;
            let sortDir = 1;
            let pageSize = 100;
            let curPage = 1;

            // Elementos DOM
            const tbody = document.getElementById('tbody');
            const q = document.getElementById('q');
            const pageSizeSel = document.getElementById('pageSize');
            const entriesInfo = document.getElementById('entriesInfo');
            const pageDisplay = document.getElementById('pageDisplay');
            const btnPrev = document.getElementById('prev');
            const btnNext = document.getElementById('next');

            function render() {{
                // Lógica de Paginação
                pageSize = parseInt(pageSizeSel.value, 10);
                const total = filtered.length;
                const totalPages = Math.max(1, Math.ceil(total / pageSize));

                if (curPage > totalPages) curPage = totalPages;
                if (curPage < 1) curPage = 1;

                const start = (curPage - 1) * pageSize;
                const end = start + pageSize;
                const slice = filtered.slice(start, end);

                // Render HTML
                tbody.innerHTML = '';
                slice.forEach(r => {{
                    const tr = document.createElement('tr');
                    
                    // Coluna 1: Path
                    const pathHtml = `<span class="path-text mono" title="${{r.path}}">${{r.path}}</span>`;
                    
                    // Coluna 2: Local Status
                    let localHtml = '';
                    if (r.local_exists) {{
                        // Tenta link local (pode ser bloqueado pelo browser), mas visualmente indica sucesso
                        localHtml = `<a href="${{r.local_url}}" target="_blank" style="text-decoration:none"><span class="badge badge-success">✓ RESTORED</span></a>`;
                    }} else {{
                        localHtml = `<span class="badge badge-missing">✖ MISSING</span>`;
                    }}

                    // Coluna 3: Remote
                    const remoteHtml = `<a href="${{r.remote_url}}" target="_blank" class="link-icon">Abrir ↗</a>`;

                    // Coluna 4: SHA
                    const shaHtml = r.sha 
                        ? `<a href="${{r.blob_url}}" target="_blank" class="mono hash-link">${{r.sha}}</a>` 
                        : '<span class="muted">-</span>';

                    tr.innerHTML = `<td>${{pathHtml}}</td><td>${{localHtml}}</td><td>${{remoteHtml}}</td><td>${{shaHtml}}</td>`;
                    tbody.appendChild(tr);
                }});

                // Update Controls
                const startInfo = total === 0 ? 0 : start + 1;
                const endInfo = Math.min(end, total);
                entriesInfo.innerText = `Mostrando ${{startInfo}} a ${{endInfo}} de ${{total}} arquivos`;
                pageDisplay.innerText = `Pág ${{curPage}} / ${{totalPages}}`;

                btnPrev.disabled = curPage === 1;
                btnNext.disabled = curPage === totalPages;
            }}

            function applyFilter() {{
                const term = q.value.trim().toLowerCase();
                
                if (!term) {{
                    filtered = DATA.slice();
                }} else {{
                    filtered = DATA.filter(r => 
                        (r.path || '').toLowerCase().includes(term) || 
                        (r.sha || '').toLowerCase().includes(term)
                    );
                }}

                if (sortKey) {{
                    filtered.sort((a, b) => {{
                        const A = (a[sortKey] || '').toLowerCase();
                        const B = (b[sortKey] || '').toLowerCase();
                        if (A < B) return -1 * sortDir;
                        if (A > B) return 1 * sortDir;
                        return 0;
                    }});
                }}

                curPage = 1;
                render();
            }}

            // Listeners
            q.addEventListener('input', applyFilter);
            
            pageSizeSel.addEventListener('change', () => {{
                curPage = 1;
                render();
            }});

            document.getElementById('reset').addEventListener('click', () => {{
                q.value = '';
                pageSizeSel.value = '100';
                sortKey = null;
                sortDir = 1;
                filtered = DATA.slice();
                curPage = 1;
                render();
            }});

            btnPrev.addEventListener('click', () => {{
                if (curPage > 1) {{ curPage--; render(); }}
            }});

            btnNext.addEventListener('click', () => {{
                const totalPages = Math.ceil(filtered.length / pageSize);
                if (curPage < totalPages) {{ curPage++; render(); }}
            }});

            document.querySelectorAll('th.sortable').forEach(th => {{
                th.addEventListener('click', () => {{
                    const k = th.getAttribute('data-sort');
                    if (sortKey === k) {{
                        sortDir = -sortDir;
                    }} else {{
                        sortKey = k;
                        sortDir = 1;
                    }}
                    applyFilter();
                }});
            }});

            // Init
            render();
        </script>
    </body>
    </html>
    """

    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "listing.html")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    
    success(f"Dashboard de Listagem gerado: {outpath}")


def generate_history_html(in_json: str, out_html: str, site_base: str, base_git_url: str):
    # 1. Carregamento de Dados (Preservando sua lógica)
    import json, os
    
    with open(in_json, 'r', encoding='utf-8') as f: 
        data = json.load(f)
    
    commits = data.get('commits', [])
    head_sha = data.get('head', 'N/A')
    
    # Prepara o JSON para o JavaScript
    commits_json = json.dumps(commits, ensure_ascii=False)

    # Tenta obter URL remota (Sua lógica original)
    intel_path = os.path.join(os.path.dirname(in_json), "intelligence.json")
    remote_url = ""
    if os.path.exists(intel_path):
        with open(intel_path, 'r', encoding='utf-8') as f: 
            remote_url = json.load(f).get("remote_url", "")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Timeline Git - {site_base}</title>
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
                --danger: #ef4444;
                --warning: #f59e0b;
                --hash-color: #ec4899;
            }}

            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
            body {{
                background-color: var(--bg-body);
                color: var(--text-primary);
                font-family: 'Inter', sans-serif;
                min-height: 100vh;
                padding: 2rem;
            }}

            .container {{ max-width: 1600px; margin: 0 auto; }}

            /* Header */
            .header {{
                display: flex; justify-content: space-between; align-items: center;
                margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);
            }}
            .title h1 {{ font-size: 1.5rem; font-weight: 600; color: var(--text-primary); }}
            .title p {{ color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }}
            
            .meta-box {{
                display: flex; gap: 1rem;
            }}
            .stat-badge {{
                background: var(--bg-card); padding: 0.5rem 1rem; border-radius: 6px;
                border: 1px solid var(--border-color); font-size: 0.85rem; color: var(--text-secondary);
            }}
            .highlight {{ color: var(--accent-color); font-weight: 600; }}

            /* Controls */
            .controls {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
            .btn-back {{
                display: inline-flex; align-items: center; padding: 0.6rem 1.2rem;
                background-color: var(--bg-card); color: var(--text-primary);
                text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color);
                font-size: 0.9rem; transition: all 0.2s;
            }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}

            .search-box {{ flex: 1; position: relative; max-width: 500px; }}
            .search-box input {{
                width: 100%; padding: 0.6rem 1rem 0.6rem 2.5rem;
                background-color: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 6px; color: var(--text-primary); font-size: 0.9rem;
            }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); pointer-events: none; }}

            /* Table */
            .table-container {{
                background-color: var(--bg-card); border-radius: 8px;
                border: 1px solid var(--border-color); overflow: hidden;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }}
            table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }}
            
            th {{
                background-color: rgba(255,255,255,0.03); padding: 1rem; text-align: left;
                font-weight: 500; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);
            }}
            
            td {{ padding: 0.8rem 1rem; border-bottom: 1px solid var(--border-color); vertical-align: top; }}
            tbody tr:hover {{ background-color: var(--bg-hover); }}

            /* Colunas */
            th:nth-child(1) {{ width: 12%; }} /* Hash & Status */
            th:nth-child(2) {{ width: 10%; }} /* Data */
            th:nth-child(3) {{ width: 18%; }} /* Autor */
            th:nth-child(4) {{ width: 40%; }} /* Mensagem */
            th:nth-child(5) {{ width: 20%; }} /* Arquivos */

            /* Elementos Internos */
            .mono {{ font-family: 'JetBrains Mono', monospace; }}
            
            .hash-link {{ color: var(--hash-color); text-decoration: none; font-weight: bold; }}
            .hash-link:hover {{ text-decoration: underline; }}

            .badge {{ font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-transform: uppercase; margin-left: 5px; }}
            .badge-log {{ background: rgba(16, 185, 129, 0.15); color: var(--success); }} /* Log = Verde */
            .badge-walk {{ background: rgba(59, 130, 246, 0.15); color: #3b82f6; }}      /* Walk = Azul */
            .badge-err {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); }}

            .author-name {{ color: #fff; font-weight: 500; }}
            .author-email {{ font-size: 0.8rem; color: var(--text-secondary); }}

            .msg-text {{ color: #d1d5db; display: block; margin-bottom: 5px; }}
            .parents-info {{ font-size: 0.75rem; color: #64748b; }}
            .parents-info a {{ color: #64748b; text-decoration: none; }}
            .parents-info a:hover {{ color: var(--accent-color); }}

            /* Files Detail */
            details {{ cursor: pointer; }}
            summary {{ font-weight: 500; color: var(--text-secondary); font-size: 0.85rem; user-select: none; transition: color 0.2s; }}
            summary:hover {{ color: var(--accent-color); }}
            
            .file-list {{ 
                margin-top: 8px; max-height: 200px; overflow-y: auto; 
                background: rgba(0,0,0,0.2); border-radius: 4px; padding: 5px;
            }}
            .file-item {{ display: block; font-size: 0.8rem; color: var(--text-secondary); padding: 2px 5px; border-bottom: 1px solid rgba(255,255,255,0.05); }}
            .file-item:last-child {{ border-bottom: none; }}
            .file-sha {{ color: #555; font-size: 0.75rem; margin-left: 5px; }}
            
            .err-msg {{ color: var(--danger); font-size: 0.8rem; font-style: italic; }}

            /* Pagination */
            .pagination-container {{
                display: flex; justify-content: space-between; align-items: center;
                padding: 1rem; border-top: 1px solid var(--border-color); color: var(--text-secondary);
            }}
            .page-btn {{
                background: var(--bg-card); border: 1px solid var(--border-color);
                color: var(--text-primary); width: 32px; height: 32px; border-radius: 6px;
                cursor: pointer; transition: all 0.2s;
            }}
            .page-btn:hover:not(:disabled) {{ border-color: var(--accent-color); color: var(--accent-color); }}
            .page-btn.active {{ background: var(--accent-color); border-color: var(--accent-color); color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div class="title">
                    <h1>Reconstrução de Histórico</h1>
                    <p>Target: {site_base}</p>
                </div>
                <div class="meta-box">
                    <div class="stat-badge">HEAD: <span class="highlight mono">{head_sha[:8]}</span></div>
                    <div class="stat-badge">Total: <span class="highlight" id="total-count">{len(commits)}</span></div>
                    <div class="stat-badge">Remoto: <span class="highlight">{remote_url or "Local"}</span></div>
                </div>
            </header>

            <div class="controls">
                <a href="report.html" class="btn-back">&larr; Voltar para Relatório</a>
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="q" placeholder="Filtrar por hash, autor, email ou mensagem...">
                </div>
            </div>

            <div class="table-container">
                <table id="commits-table">
                    <thead>
                        <tr>
                            <th>Commit & Status</th>
                            <th>Data</th>
                            <th>Autor</th>
                            <th>Mensagem & Parents</th>
                            <th>Arquivos Alterados</th>
                        </tr>
                    </thead>
                    <tbody id="table-body">
                        </tbody>
                </table>
            </div>

            <div class="pagination-container">
                <div id="entries-info">Carregando...</div>
                <div id="pagination-controls" style="display:flex; gap:5px;"></div>
            </div>
        </div>

        <script>
            // Dados Injetados pelo Python
            const COMMITS = {commits_json};
            const REMOTE_URL = "{remote_url}";

            // Elementos DOM
            const tableBody = document.getElementById('table-body');
            const searchInput = document.getElementById('q');
            const entriesInfo = document.getElementById('entries-info');
            const pgControls = document.getElementById('pagination-controls');
            const totalCountEl = document.getElementById('total-count');

            // Estado
            let filteredCommits = COMMITS;
            let currentPage = 1;
            const itemsPerPage = 20; // Mais itens por página pois é tabela

            // Helpers
            function getLink(sha) {{
                if (!REMOTE_URL) return `<span class="hash-link">${{sha.substring(0,8)}}</span>`;
                const cleanUrl = REMOTE_URL.replace('.git', '');
                return `<a href="${{cleanUrl}}/commit/${{sha}}" target="_blank" class="hash-link">${{sha.substring(0,8)}}</a>`;
            }}

            function safe(str) {{
                if (!str) return '';
                return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
            }}

            // Core Render
            function renderTable() {{
                const totalPages = Math.ceil(filteredCommits.length / itemsPerPage) || 1;
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;

                const start = (currentPage - 1) * itemsPerPage;
                const end = start + itemsPerPage;
                const pageData = filteredCommits.slice(start, end);

                tableBody.innerHTML = '';

                pageData.forEach((c, index) => {{
                    const tr = document.createElement('tr');
                    
                    const sourceBadge = c.source === 'log' 
                        ? '<span class="badge badge-log">LOG</span>' 
                        : '<span class="badge badge-walk">GRAPH</span>';
                    
                    const statusBadge = !c.ok 
                        ? '<span class="badge badge-err">ERR</span>' 
                        : '';

                    const hashHtml = `<div class="mono">${{getLink(c.sha)}}</div><div>${{statusBadge}}${{sourceBadge}}</div>`;

                    const dateHtml = `<div style="color:var(--text-secondary)">${{c.date || '?'}}</div>`;

                    const cleanAuthor = safe(c.author).replace('&lt;', '<br><span class="author-email">').replace('&gt;', '</span>');
                    
                    let parentsHtml = '';
                    if (c.parents && c.parents.length > 0) {{
                        parentsHtml = c.parents.map(p => `<a href="#" onclick="filterBySha('${{p}}'); return false;">${{p.substring(0,8)}}</a>`).join(', ');
                    }}
                    const msgHtml = `
                        <span class="msg-text">${{safe(c.message)}}</span>
                        ${{parentsHtml ? `<div class="parents-info">Parent(s): ${{parentsHtml}}</div>` : ''}}
                        ${{!c.ok ? `<div class="err-msg">Erro: ${{c.error || 'Desconhecido'}}</div>` : ''}}
                    `;

                    let filesHtml = '';
                    if (c.file_collection_error) {{
                        filesHtml = `<span class="err-msg">${{c.file_collection_error}}</span>`;
                    }} else if (c.files && c.files.length > 0) {{
                        // Limita visualização se tiver muitos arquivos
                        const fileListItems = c.files.map(f => 
                            `<div class="file-item mono">${{safe(f.path)}} <span class="file-sha">${{f.sha ? f.sha.substring(0,6) : ''}}</span></div>`
                        ).join('');
                        
                        filesHtml = `
                            <details>
                                <summary>${{c.files.length}} arquivo(s)</summary>
                                <div class="file-list">
                                    ${{fileListItems}}
                                </div>
                            </details>
                        `;
                    }} else {{
                        filesHtml = '<span style="color:#555; font-size:0.8rem">Nenhum/Tree Vazia</span>';
                    }}

                    // Montagem das células
                    tr.innerHTML = `
                        <td>${{hashHtml}}</td>
                        <td>${{dateHtml}}</td>
                        <td>${{cleanAuthor}}</td>
                        <td>${{msgHtml}}</td>
                        <td>${{filesHtml}}</td>
                    `;
                    tableBody.appendChild(tr);
                }});

                const startInfo = filteredCommits.length === 0 ? 0 : start + 1;
                const endInfo = Math.min(end, filteredCommits.length);
                entriesInfo.innerText = `Mostrando ${{startInfo}} a ${{endInfo}} de ${{filteredCommits.length}} commits`;
                
                renderPagination(totalPages);
            }}

            // Filter
            function filterCommits(query) {{
                const q = query.toLowerCase().trim();
                filteredCommits = COMMITS.filter(c => {{
                    return (c.sha || '').toLowerCase().includes(q) ||
                           (c.author || '').toLowerCase().includes(q) ||
                           (c.message || '').toLowerCase().includes(q);
                }});
                currentPage = 1;
                renderTable();
            }}
            
            // Helper para links de parents clicáveis
            window.filterBySha = function(sha) {{
                searchInput.value = sha;
                filterCommits(sha);
            }}

            // Pagination
            function renderPagination(totalPages) {{
                pgControls.innerHTML = '';
                
                const createBtn = (label, page, disabled=false, active=false) => {{
                    const btn = document.createElement('button');
                    btn.className = `page-btn ${{active ? 'active' : ''}}`;
                    btn.innerHTML = label;
                    btn.disabled = disabled;
                    btn.onclick = () => {{ currentPage = page; renderTable(); }};
                    return btn;
                }};

                pgControls.appendChild(createBtn('‹', currentPage - 1, currentPage === 1));

                let startPage = Math.max(1, currentPage - 2);
                let endPage = Math.min(totalPages, startPage + 4);
                if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

                for (let i = startPage; i <= endPage; i++) {{
                    pgControls.appendChild(createBtn(i, i, false, i === currentPage));
                }}

                pgControls.appendChild(createBtn('›', currentPage + 1, currentPage === totalPages));
            }}

            // Events
            searchInput.addEventListener('input', (e) => filterCommits(e.target.value));

            // Init
            renderTable();

        </script>
    </body>
    </html>
    """
    
    try:
        with open(out_html, "w", encoding="utf-8") as f: 
            f.write(html_content)
    except Exception as e:
        print(f"Erro ao salvar HTML de histórico: {e}")
    return


def generate_users_report(outdir: str, authors_stats: Dict[str, int]):
    info("Gerando relatório de usuários (OSINT)...")
    
    users_data = []
    import re
    import json
    import os
    
    sorted_authors = sorted(authors_stats.items(), key=lambda item: item[1], reverse=True)

    for raw_author, count in sorted_authors:
        name = raw_author
        email = ""
        
        # Regex para separar "Nome <email>"
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

    # 2. Salva o JSON bruto (Requisito original)
    files_dir = os.path.join(outdir, "_files")
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, "users.json"), "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

    users_json_str = json.dumps(users_data, ensure_ascii=False)
    total_commits = sum(u['commits'] for u in users_data)

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Identidades Encontradas - OSINT</title>
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
                --info: #3b82f6;
                --warning: #f59e0b;
            }}

            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            
            body {{
                background-color: var(--bg-body);
                color: var(--text-primary);
                font-family: 'Inter', sans-serif;
                min-height: 100vh;
                padding: 2rem;
            }}

            .container {{ max-width: 1200px; margin: 0 auto; }}

            /* Header */
            .header {{
                display: flex; justify-content: space-between; align-items: center;
                margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);
            }}
            .title h1 {{ font-size: 1.5rem; font-weight: 600; color: var(--text-primary); }}
            .title p {{ color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }}
            
            .stats-box {{ display: flex; gap: 1rem; }}
            .stat-badge {{
                background: var(--bg-card); padding: 0.5rem 1rem; border-radius: 6px;
                border: 1px solid var(--border-color); font-size: 0.85rem; color: var(--text-secondary);
            }}
            .highlight {{ color: var(--accent-color); font-weight: 600; }}

            /* Controls */
            .controls {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
            .btn-back {{
                display: inline-flex; align-items: center; padding: 0.6rem 1.2rem;
                background-color: var(--bg-card); color: var(--text-primary);
                text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color);
                font-size: 0.9rem; transition: all 0.2s;
            }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}

            .search-box {{ flex: 1; position: relative; max-width: 450px; }}
            .search-box input {{
                width: 100%; padding: 0.6rem 1rem 0.6rem 2.5rem;
                background-color: var(--bg-card); border: 1px solid var(--border-color);
                border-radius: 6px; color: var(--text-primary); font-size: 0.9rem;
            }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); pointer-events: none; }}

            /* Table */
            .table-container {{
                background-color: var(--bg-card); border-radius: 8px;
                border: 1px solid var(--border-color); overflow: hidden;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }}
            table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }}
            
            th {{
                background-color: rgba(255,255,255,0.03); padding: 1rem; text-align: left;
                font-weight: 500; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);
            }}
            
            td {{ padding: 0.8rem 1rem; border-bottom: 1px solid var(--border-color); vertical-align: middle; }}
            tbody tr:hover {{ background-color: var(--bg-hover); }}

            /* Colunas Específicas */
            th:nth-child(1) {{ width: 25%; }} /* Nome */
            th:nth-child(2) {{ width: 30%; }} /* Email */
            th:nth-child(3) {{ width: 15%; }} /* Commits */
            th:nth-child(4) {{ width: 30%; }} /* Raw */

            /* Elementos UI */
            .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }}
            
            .user-name {{ font-weight: 600; color: #fff; display: flex; align-items: center; gap: 8px; }}
            .user-initial {{ 
                width: 24px; height: 24px; background: rgba(99, 102, 241, 0.2); color: var(--accent-color);
                border-radius: 50%; display: flex; align-items: center; justify-content: center;
                font-size: 0.75rem; font-weight: bold; text-transform: uppercase;
            }}
            
            .email-link {{ color: var(--info); text-decoration: none; }}
            .email-link:hover {{ text-decoration: underline; }}
            
            .commit-badge {{
                background: rgba(16, 185, 129, 0.1); color: var(--success);
                padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem;
                display: inline-block; min-width: 40px; text-align: center;
            }}
            
            .raw-text {{ color: #64748b; font-size: 0.8rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}

            /* Pagination */
            .pagination-container {{
                display: flex; justify-content: space-between; align-items: center;
                padding: 1rem; border-top: 1px solid var(--border-color); color: var(--text-secondary);
            }}
            .page-btn {{
                background: var(--bg-card); border: 1px solid var(--border-color);
                color: var(--text-primary); width: 32px; height: 32px; border-radius: 6px;
                cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center;
            }}
            .page-btn:hover:not(:disabled) {{ border-color: var(--accent-color); color: var(--accent-color); }}
            .page-btn.active {{ background: var(--accent-color); border-color: var(--accent-color); color: white; }}
            .page-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div class="title">
                    <h1>Identidades (OSINT)</h1>
                    <p>Mapeamento de desenvolvedores e emails</p>
                </div>
                <div class="stats-box">
                    <div class="stat-badge">Autores: <span class="highlight">{len(users_data)}</span></div>
                    <div class="stat-badge">Total Commits: <span class="highlight">{total_commits}</span></div>
                </div>
            </header>

            <div class="controls">
                <a href="report.html" class="btn-back">&larr; Voltar ao Painel</a>
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="searchInput" placeholder="Filtrar por nome, email ou domínio...">
                </div>
            </div>

            <div class="table-container">
                <table id="dataTable">
                    <thead>
                        <tr>
                            <th>Nome do Autor</th>
                            <th>E-mail</th>
                            <th>Contribuições</th>
                            <th>Assinatura Bruta (Git)</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                        </tbody>
                </table>
            </div>

            <div class="pagination-container">
                <div id="entriesInfo">Carregando...</div>
                <div id="paginationControls" style="display:flex; gap:5px;"></div>
            </div>
        </div>

        <script>
            // Dados Injetados
            const USERS = {users_json_str};

            // DOM Elements
            const tableBody = document.getElementById('tableBody');
            const searchInput = document.getElementById('searchInput');
            const entriesInfo = document.getElementById('entriesInfo');
            const pgControls = document.getElementById('paginationControls');

            // State
            let filteredUsers = USERS;
            let currentPage = 1;
            const itemsPerPage = 15;

            function renderTable() {{
                const totalPages = Math.ceil(filteredUsers.length / itemsPerPage) || 1;
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;

                const start = (currentPage - 1) * itemsPerPage;
                const end = start + itemsPerPage;
                const pageData = filteredUsers.slice(start, end);

                tableBody.innerHTML = '';

                pageData.forEach(u => {{
                    const tr = document.createElement('tr');
                    
                    // Nome com avatar (inicial)
                    const initial = (u.name || '?').charAt(0).toUpperCase();
                    const nameHtml = `
                        <div class="user-name">
                            <span class="user-initial">${{initial}}</span>
                            ${{u.name || '<span style="color:#666">Desconhecido</span>'}}
                        </div>`;

                    // Email com link
                    const emailHtml = u.email 
                        ? `<a href="mailto:${{u.email}}" class="email-link mono">${{u.email}}</a>`
                        : '<span style="color:#555">-</span>';

                    // Badge de Commits
                    const commitsHtml = `<span class="commit-badge">${{u.commits}}</span>`;

                    // Raw Signature (Muted)
                    const rawHtml = `<div class="raw-text mono" title="${{u.raw}}">${{u.raw}}</div>`;

                    tr.innerHTML = `
                        <td>${{nameHtml}}</td>
                        <td>${{emailHtml}}</td>
                        <td>${{commitsHtml}}</td>
                        <td>${{rawHtml}}</td>
                    `;
                    tableBody.appendChild(tr);
                }});

                // Update Info
                const startInfo = filteredUsers.length === 0 ? 0 : start + 1;
                const endInfo = Math.min(end, filteredUsers.length);
                entriesInfo.innerText = `Mostrando ${{startInfo}} a ${{endInfo}} de ${{filteredUsers.length}} autores`;

                renderPagination(totalPages);
            }}

            function filterUsers(query) {{
                const q = query.toLowerCase().trim();
                filteredUsers = USERS.filter(u => {{
                    return (u.name || '').toLowerCase().includes(q) ||
                           (u.email || '').toLowerCase().includes(q) ||
                           (u.raw || '').toLowerCase().includes(q);
                }});
                currentPage = 1;
                renderTable();
            }}

            function renderPagination(totalPages) {{
                pgControls.innerHTML = '';
                
                const createBtn = (label, page, disabled=false, active=false) => {{
                    const btn = document.createElement('button');
                    btn.className = `page-btn ${{active ? 'active' : ''}}`;
                    btn.innerHTML = label;
                    btn.disabled = disabled;
                    btn.onclick = () => {{ currentPage = page; renderTable(); }};
                    return btn;
                }};

                pgControls.appendChild(createBtn('‹', currentPage - 1, currentPage === 1));

                let startPage = Math.max(1, currentPage - 2);
                let endPage = Math.min(totalPages, startPage + 4);
                if (endPage - startPage < 4) startPage = Math.max(1, endPage - 4);

                for (let i = startPage; i <= endPage; i++) {{
                    pgControls.appendChild(createBtn(i, i, false, i === currentPage));
                }}

                pgControls.appendChild(createBtn('›', currentPage + 1, currentPage === totalPages));
            }}

            // Event Listeners
            searchInput.addEventListener('input', (e) => filterUsers(e.target.value));

            // Init
            renderTable();
        </script>
    </body>
    </html>
    """

    out_html = os.path.join(outdir, "users.html")
    try:
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html)
        success(f"Relatório de usuários salvo: {out_html}")
    except Exception as e:
        warn(f"Erro ao salvar users.html: {e}")


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


def serve_dir(path: str, port: int = 8000, open_file="index.html"):
    import http.server
    import socketserver
    import webbrowser

    if not path or not os.path.isdir(path):
        fail(f"Diretório inválido: {path}")
        return

    os.chdir(path)
    
    Handler = http.server.SimpleHTTPRequestHandler
    socketserver.TCPServer.allow_reuse_address = True
    
    bind_address = "127.0.0.1"
    url = f"http://{bind_address}:{port}/{open_file}"

    try:
        with socketserver.TCPServer((bind_address, port), Handler) as httpd:
            print(f"\n[*] Dashboard Ativo!")
            print(f"    -> Raiz: {path}")
            print(f"    -> URL:  {url}")
            print(f"[*] Pressione CTRL+C para encerrar.")
            
            try:
                webbrowser.open(url)
            except: pass

            httpd.serve_forever()
    except OSError as e:
        fail(f"Erro ao abrir porta {port}: {e}")
    except KeyboardInterrupt:
        print("\nServidor encerrado.")


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
    stash_sha = recover_stash_content(base_url, output_dir, proxies=proxies)
    if stash_sha:
        reconstruct_all(os.path.join(output_dir, "_files", "stash.json"), base_url, os.path.join(output_dir, "stash_restored"), workers=args.workers)
        pass
    
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
    
    # --- ARGUMENTOS ---
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
    p.add_argument("--proxy", help="URL do Proxy (ex: http://127.0.0.1:8080) para Burp/ZAP ou socks5h://127.0.0.1:9150 para rede Tor)")
    p.add_argument("--no-random-agent", action="store_true", help="Desativa a rotação de User-Agents (Usa um fixo)")
    p.add_argument("--secrets", action="store_true", help="Executa scanner de regex/entropia em busca de chaves")

    args = p.parse_args()

    # --- CONFIGURAÇÕES GLOBAIS ---
    global USE_RANDOM_AGENT
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    if args.proxy: info(f"Usando Proxy: {args.proxy}")
    
    USE_RANDOM_AGENT = not args.no_random_agent
    if USE_RANDOM_AGENT: info("Rotação de User-Agents: ATIVADA")

    # --- MODO 1: APENAS SERVIR (Sem scan) ---
    if args.serve and not args.base and not args.scan:
        target_path = args.serve_dir if args.serve_dir else args.output_dir
        if not os.path.exists(target_path):
            fail(f"Diretório não encontrado para servir: {target_path}")
            return
            
        # Verifica se é um Master Dashboard (index.html) ou Single Report
        if os.path.exists(os.path.join(target_path, "index.html")):
            serve_dir(target_path, open_file="index.html")
        else:
            serve_dir(target_path, open_file="report.html")
        return

    # --- MODO 2: PREPARAÇÃO DE ALVOS (Unificada) ---
    targets = []

    if args.scan:
        # Carrega lista do arquivo
        if not os.path.exists(args.scan):
            fail(f"Arquivo de lista não encontrado: {args.scan}")
            return
        try:
            with open(args.scan, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip().replace('\ufeff', '').replace('\x00', '')
                    if clean and not clean.startswith("#"):
                        targets.append(normalize_url(clean))
            if not targets:
                fail("A lista de alvos está vazia.")
                return
            info(f"Modo Multi-Scan: {len(targets)} alvos carregados.")
        except Exception as e:
            fail(f"Erro ao ler lista: {e}")
            return

    elif args.base:
        # Adiciona alvo único na lista
        targets = [normalize_url(args.base)]
        info(f"Modo Single-Target: {targets[0]}")
    
    else:
        # Se não tem nem lista nem base, aí sim mostra erro
        p.print_help()
        print("\n[!] Erro: É necessário fornecer uma URL ou usar --scan <arquivo>.")
        return

    # --- LOOP DE PROCESSAMENTO (Ocorre para 1 ou N alvos) ---
    master_results = []

    for i, target_url in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{'='*60}")
            print(f"[*] PROCESSANDO ALVO [{i}/{len(targets)}]: {target_url}")
            print(f"{'='*60}")

        # 1. Define Pasta Segura
        folder_name = get_safe_folder_name(target_url)
        target_outdir = os.path.join(args.output_dir, folder_name)
        os.makedirs(target_outdir, exist_ok=True)

        try:
            # 2. Roteamento de Ações
            if args.detect_hardening:
                detect_hardening(target_url, target_outdir, proxies=proxies)
            elif args.packfile:
                handle_packfiles(args.packfile, target_url, target_outdir, proxies=proxies)
            elif args.blind:
                blind_recovery(target_url, target_outdir, args.output_index, proxies=proxies)
            elif args.sha1:
                recover_one_sha(target_url, args.sha1, target_outdir, proxies=proxies)
            elif args.parse_index:
                tmp_idx = os.path.join(target_outdir, "_files", "raw_index")
                os.makedirs(os.path.dirname(tmp_idx), exist_ok=True)
                http_get_to_file(target_url + "/.git/index", tmp_idx, proxies=proxies)
                index_to_json(tmp_idx, os.path.join(target_outdir, "_files", args.output_index))
            else:
                # Pipeline Padrão (Full Scan)
                process_pipeline(target_url, target_outdir, args, proxies=proxies)

            # 3. Coleta de Stats para o Dashboard Geral
            stats = {
                "target": target_url,
                "folder_name": folder_name,
                "secrets_count": 0, "files_count": 0, "vuln_count": 0
            }
            # Leitura resiliente dos JSONs gerados
            try:
                s = json.load(open(os.path.join(target_outdir, "_files", "secrets.json")))
                stats["secrets_count"] = len(s)
            except: pass
            
            try:
                d = load_dump_entries(os.path.join(target_outdir, "_files", "dump.json"))
                stats["files_count"] = len(d)
            except: pass
            
            try:
                h = json.load(open(os.path.join(target_outdir, "_files", "hardening_report.json")))
                stats["vuln_count"] = sum(1 for v in h.get("results", {}).values() if v.get("exposed"))
            except: pass

            master_results.append(stats)

        except KeyboardInterrupt:
            print("\n[!] Interrompido pelo usuário.")
            sys.exit(0)
        except Exception as e:
            fail(f"Erro ao processar {target_url}: {e}")
            continue

    # --- PÓS-PROCESSAMENTO FINAL ---
    
    # Gera o index.html (Master Dashboard) na raiz do output
    generate_master_dashboard(args.output_dir, master_results)

    if args.serve:
        print("\n" + "="*60)
        info("Iniciando visualização web...")
        
        # Lógica inteligente para abrir o arquivo certo
        if len(targets) > 1:
            # Vários sites: abre o índice geral
            serve_dir(args.output_dir, open_file="index.html")
        elif len(targets) == 1:
            # Um site: entra na pasta e abre o dashboard dele
            fld = master_results[0]['folder_name']
            path_single = os.path.join(args.output_dir, fld)
            serve_dir(path_single, open_file="report.html")
    else:
        success("Processamento finalizado!")
        if len(targets) > 1:
            print(f"Relatório Mestre: {os.path.join(args.output_dir, 'index.html')}")
        elif len(targets) == 1:
            fld = master_results[0]['folder_name']
            print(f"Relatório: {os.path.join(args.output_dir, fld, 'report.html')}")

if __name__ == "__main__":
    main()