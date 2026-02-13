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
 - --no-random-agent     : desativa a rotação de User-Agents (Usa um fixo)
 - --secrets             : Executa scanner de regex/entropia em busca de chaves
 - --show-dif            : Baixa e exibe as diferenças (diffs) de código no histórico (Pode ser MUITO Lento)
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
import difflib
import glob

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
# Global Session Setup (Performance)
# ---------------------------

requests.packages.urllib3.disable_warnings()
SESSION = requests.Session()
# Aumenta o pool para suportar multithreading pesado
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=1)
SESSION.mount('http://', adapter)
SESSION.mount('https://', adapter)



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

class LocalResponse:
    """Simula um objeto requests.Response para leitura de arquivos locais."""
    def __init__(self, content, status_code):
        self.content = content
        self.status_code = status_code
    def raise_for_status(self):
        if self.status_code != 200:
            raise Exception(f"Erro Local: {self.status_code}")
    @property
    def text(self):
        return self.content.decode(errors='ignore') if self.content else ""

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
    if url.startswith("local://"):
        return url
    
    if os.path.isdir(url):
        return f"local://{os.path.abspath(url).replace('\\', '/')}"

    url = re.sub(r'/\.git(/.*)?$', '', url, flags=re.IGNORECASE).rstrip('/')
    if url.startswith(('http://', 'https://')):
        return url

    print(f"[*] Detectando protocolo para {url}...")
    try:
        resp = requests.get(f"https://{url}", headers=get_random_headers(), timeout=5, verify=False, proxies=proxies)
        return f"https://{url}"
    except requests.RequestException:
        return f"http://{url}"

def http_get_bytes(url: str, timeout: int = 15, proxies: Optional[Dict] = None) -> Tuple[bool, bytes | str]:
    if url.startswith("local://"):
        path = url.replace("local://", "")
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    return True, f.read()
            except Exception as e:
                return False, str(e)
        return False, "404 Not Found"

    try:
        r = SESSION.get(url, timeout=timeout, stream=True, verify=False, headers=get_random_headers(), proxies=proxies)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, r.content
    except Exception as e:
        return False, str(e)


def http_get_to_file(url: str, outpath: str, timeout: int = 15, proxies: Optional[Dict] = None) -> Tuple[bool, str]:
    if url.startswith("local://"):
        path = url.replace("local://", "")
        if os.path.exists(path) and os.path.isfile(path):
            try:
                os.makedirs(os.path.dirname(outpath), exist_ok=True)
                shutil.copy2(path, outpath)
                return True, "ok"
            except Exception as e:
                return False, str(e)
        return False, "404 Not Found"

    try:
        print(f"[!] Baixando {url} ...")
        r = SESSION.get(url, timeout=timeout, stream=True, verify=False, headers=get_random_headers(), proxies=proxies)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        with open(outpath, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk: f.write(chunk)
        return True, "ok"
    except Exception as e:
        return False, str(e)


def http_head_status(url: str, timeout: int = 6, proxies: Optional[Dict] = None) -> Tuple[bool, Optional[int], str]:
    if url.startswith("local://"):
        path = url.replace("local://", "")
        if os.path.exists(path):
            return True, 200, "OK"
        return False, 404, "Not Found"

    try:
        r = SESSION.head(url, timeout=timeout, allow_redirects=True, verify=False, headers=get_random_headers(), proxies=proxies)
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


def compute_diff(base_url, sha_old, sha_new, proxies=None):
    MAX_SIZE = 100 * 10240  # Limite de 1000KB para processar diff
    
    def get_content(sha):
        if not sha: return []
        ok, raw = fetch_object_raw(base_url, sha, proxies)
        if not ok: return None
        
        is_valid, parsed_data = parse_git_object(raw)
        if not is_valid: return None
        
        _, content = parsed_data
        
        # Proteção 1: Se for muito grande, ignora
        if len(content) > MAX_SIZE:
            return ["<Arquivo muito grande para exibir diff>"]
            
        # Proteção 2: Tenta decodificar
        try:
            return content.decode('utf-8').splitlines()
        except UnicodeDecodeError:
            try:
                return content.decode('latin-1').splitlines()
            except:
                return None # Binário

    lines_old = get_content(sha_old)
    lines_new = get_content(sha_new)

    if lines_old is None or lines_new is None:
        return "    (Irrecuperável) Arquivo binário, codificação desconhecida ou dados ausentes/incompletos."
        
    if lines_old == ["<Arquivo muito grande para exibir diff>"] or lines_new == ["<Arquivo muito grande para exibir diff>"]:
        return "    Arquivo excede o limite de tamanho para visualização (100KB)."

    try:
        diff = difflib.unified_diff(
            lines_old, 
            lines_new, 
            fromfile=f'a/{sha_old[:7] if sha_old else "null"}', 
            tofile=f'b/{sha_new[:7] if sha_new else "null"}',
            lineterm=''
        )
        diff_text = '\n'.join(diff)
        
        # Proteção 3: Limite no tamanho do texto final do diff
        if len(diff_text) > MAX_SIZE:
            return diff_text[:MAX_SIZE] + "\n... [Diff truncado por excesso de tamanho]"
            
        return diff_text if diff_text else "Sem alterações textuais visíveis."
    except Exception as e:
        return f"Erro ao calcular diff: {str(e)}"


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


def recover_stash_content(base_git_url: str, outdir: str, workers: int = 10, proxies: Optional[Dict] = None, show_diff: bool = False) -> Optional[str]:
    stash_url = base_git_url.rstrip("/") + "/.git/refs/stash"
    ok, data = http_get_bytes(stash_url, proxies=proxies)
    if not ok: return None
    
    stash_sha = data.decode(errors='ignore').strip()
    if len(stash_sha) != 40: return None

    info(f"[!] STASH DETECTADO: {stash_sha}")
    
    ok_obj, raw_obj = fetch_object_raw(base_git_url, stash_sha, proxies=proxies)
    meta = {}
    if ok_obj:
        _, parsed = parse_git_object(raw_obj)
        meta = parse_commit_content(parsed[1])

    tree_sha = meta.get("tree")
    if not tree_sha: return None

    stash_files = collect_files_from_tree(base_git_url, tree_sha, proxies=proxies, ignore_missing=True)
    
    if stash_files:
        enriched_stash = []
        
        def fetch_stash_item(f_entry):
            diff_content = None
            if show_diff:
                try:
                    diff_content = compute_diff(base_git_url, None, f_entry['sha'], proxies=proxies)
                except:
                    diff_content = "[!] Erro ao processar conteúdo do Stash."
            else:
                diff_content = "[--show-diff não utilizado: Conteúdo omitido]"

            return {
                "path": f_entry['path'], 
                "sha1": f_entry['sha'], 
                "type": "STASHED",
                "diff": diff_content 
            }

        if show_diff:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(fetch_stash_item, f) for f in stash_files]
                for future in as_completed(futures): enriched_stash.append(future.result())
        else:
            for f in stash_files: enriched_stash.append(fetch_stash_item(f))

        stash_json_path = os.path.join(outdir, "_files", "stash.json")
        output = {
            "metadata": {
                "sha": stash_sha,
                "author": meta.get("author", "Unknown"),
                "date": meta.get("date", datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                "message": meta.get("message", "Git Stash Recovery"),
            },
            "entries": enriched_stash
        }
        
        with open(stash_json_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
            
        return stash_sha
    return None


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
    # Cloud & Infra (Alta Confiança com Prefixos)
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com",
    "Heroku API Key": r"(?i)HEROKU_API_KEY\s*=\s*[0-9a-fA-F-]{36}",
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    
    # DevOps & SaaS (Prefixos Específicos)
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-\_]{20}",
    "NPM Access Token": r"npm_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "Stripe Live Key": r"(sk_live|rk_live)_[0-9a-zA-Z]{24,}",
    "Twilio Account SID": r"AC[a-zA-Z0-9]{32}",
    "Telegram Bot Token": r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}",

    # Chaves Privadas (Muito confiável)
    "Private Key (RSA/DSA/EC)": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----",
    "Putty PPK": r"PuTTY-User-Key-File-2",

    # Configurações Críticas (Atribuições Diretas e Explícitas)
    "DB Connection String": r"(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[a-zA-Z0-9\.-]+",
    "Generic API Key (High Prob)": r"(?i)(api_key|access_token|secret_key)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{32,})['\"]"
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
    info("Iniciando Scanner de Segredos (Regex Analysis, alta entropia)...")
    
    scan_root = outdir
    findings = []
    
    # Lista de arquivos gerados pelo próprio script para IGNORAR
    IGNORED_FILES = {
        "report.html", "listing.html", "users.html", 
        "secrets.html", "index.html", "hardening_report.html", "bruteforce_report.html",
        "packfiles.json", "misc_leaks.json", "hardening_report.json", 
        "history.json", "users.json", "dump.json", "stash.json", "secrets.json",
        "intelligence.json"
    }

    # Extensões irrelevantes para busca de segredos
    IGNORED_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", 
        ".exe", ".pack", ".idx", ".css", ".svg", ".woff", ".woff2", ".eot", 
        ".ttf", ".mp4", ".mp3", ".lock"
    }
    
    scanned_count = 0
    
    for root, dirs, files in os.walk(scan_root):
        # Ignora diretório de metadados internos do script
        if "_files" in root and "misc" not in root and "bruteforce" not in root and "stash" not in root:
            continue
            
        for filename in files:
            # 1. Filtro de Arquivos Ignorados (Relatórios)
            if filename in IGNORED_FILES:
                continue
                
            # 2. Filtro de Extensão
            ext = os.path.splitext(filename)[1].lower()
            if ext in IGNORED_EXTS:
                continue
                
            # 3. Filtro de Arquivos Minificados (Muitos falsos positivos)
            if filename.endswith(".min.js") or filename.endswith(".min.css"):
                continue

            filepath = os.path.join(root, filename)
            scanned_count += 1
            
            try:
                # Limite de tamanho (5MB) para não travar em dumps grandes
                if os.path.getsize(filepath) > 5 * 1024 * 1024:
                    continue

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for name, pattern in SECRET_PATTERNS.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            secret_val = match.group(0)
                            
                            # Validação Extra para "Generic API Key"
                            # Se o valor for muito curto ou parecer código HTML/CSS, ignora
                            if "Generic" in name:
                                if " " in match.group(2) or "<" in match.group(2) or ">" in match.group(2):
                                    continue

                            # Mascarar para o log (mas salvar completo no JSON)
                            masked_val = secret_val[:4] + "..." + secret_val[-4:] if len(secret_val) > 10 else "***"
                            
                            # Contexto (pequeno trecho ao redor)
                            start = max(0, match.start() - 30)
                            end = min(len(content), match.end() + 30)
                            context = content[start:end].replace("\n", " ").strip()

                            findings.append({
                                "type": name,
                                "file": os.path.relpath(filepath, outdir),
                                "match": secret_val,
                                "context": context
                            })
                            
                            # Log visual apenas para coisas realmente novas
                            print(f"[!] SEGREDO: {name} em {filename}")

            except Exception:
                pass

    info(f"Scan finalizado. {scanned_count} arquivos analisados.")
    
    if findings:
        success(f"TOTAL DE SEGREDOS ENCONTRADOS: {len(findings)}")
        
        # Salva o JSON
        report_path = os.path.join(outdir, "_files", "secrets.json")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)
        except: pass
            
        # Gera o HTML
        html_path = os.path.join(outdir, "secrets.html")
        generate_secrets_html(findings, html_path)
    else:
        info("Nenhum segredo de alta confiança encontrado.")

def get_safe_folder_name(target_url):
    if target_url.startswith("local://"):
        path = target_url.replace("local://", "").rstrip("/")
        name = os.path.basename(path)
        return f"local_{name}"
    
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
                if not line.strip(): continue
                parts = line.strip().split("\t")
                if len(parts) < 2: continue
                
                meta_info = parts[0].split(" ")
                action_info = parts[1] 

                if len(meta_info) >= 4:
                    old_sha = meta_info[0]
                    new_sha = meta_info[1]
                    ts = meta_info[-2]
                    author_raw = " ".join(meta_info[2:-2])
                    
                    try:
                        dt = datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        dt = ts
                    
                    entries.append({
                        "sha": new_sha, 
                        "old_sha": old_sha, 
                        "author": author_raw, 
                        "date": dt, 
                        "message": action_info,
                        "source": "reflog"
                    })
    except Exception as e:
        print(f"[!] Erro ao analisar Reflog: {e}")
        
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
    
    ok, data = http_get_bytes(base + "/objects/info/packs", proxies=proxies)
    found_packs = []
    if ok:
        try:
            content_text = data.decode(errors='ignore')
            found_packs = [p for p in content_text.split() if p.endswith(".pack")]
        except: pass
            
    found_packs = list(set(found_packs))
    results = []
    
    # Mapa de nomes via árvores do pack (Forense)
    extended_map = {}
    pack_dir = os.path.join(outdir, ".git", "objects", "pack")
    
    for pname in found_packs:
        url_pack = f"{base}/objects/pack/{pname}"
        local_p = os.path.join(pack_dir, pname)
        local_idx = local_p.replace(".pack", ".idx")
        status = "Listado"; count = 0
        
        if mode in ["download", "download-unpack"]:
            ensure_git_repo_dir(outdir)
            os.makedirs(pack_dir, exist_ok=True)
            
            ok_p, err = http_get_to_file(url_pack, local_p, proxies=proxies)
            if not ok_p:
                fail(f"[!] ERRO DOWNLOAD: {pname} -> {err}")
                status = "Falha Download"
                continue
            
            http_get_to_file(url_pack.replace(".pack", ".idx"), local_idx, proxies=proxies)
            status = "Baixado"
            
            if mode == "download-unpack":
                with open(local_p, "rb") as f_in:
                    subprocess.run(["git", "unpack-objects"], cwd=outdir, stdin=f_in, capture_output=True)

                try:
                    v_proc = subprocess.run(["git", "verify-pack", "-v", local_idx], capture_output=True, text=True)
                    trees = re.findall(r"([0-9a-f]{40}) tree", v_proc.stdout)
                    for t_sha in trees:
                        ls = subprocess.run(["git", "ls-tree", "-r", t_sha], cwd=outdir, capture_output=True, text=True)
                        for line in ls.stdout.splitlines():
                            p = line.split(None, 3)
                            if len(p) >= 4: extended_map[p[2]] = p[3]
                except: pass

                extract_root = os.path.join(outdir, "_files", "extracted_packs", pname.replace(".pack", ""))
                blobs = re.findall(r"([0-9a-f]{40}) blob", v_proc.stdout)
                
                for s in blobs:
                    c_proc = subprocess.run(["git", "cat-file", "-p", s], cwd=outdir, capture_output=True)
                    if c_proc.returncode == 0:
                        try:
                            if s in extended_map:
                                fpath = os.path.join(extract_root, "named_restore", extended_map[s])
                            else:
                                fpath = os.path.join(extract_root, "no_name_restore", f"recovered_{s[:8]}")
                            
                            os.makedirs(os.path.dirname(fpath), exist_ok=True)
                            
                            with open(fpath, "wb") as bf:
                                bf.write(c_proc.stdout)
                            count += 1
                        except OSError as e:
                            warn(f"PULADO: Erro de escrita no arquivo {s[:8]} ({e}). Verifique caracteres inválidos.")
                            continue
                        except Exception as e:
                            warn(f"PULADO: Erro inesperado ao restaurar {s[:8]}: {e}")
                            continue
                
                if count > 0:
                    success(f"Pack {pname}: {count} arquivos restaurados fisicamente.")
                    status = "Extraído e Restaurado"
                else:
                    fail(f"[!] ALERTA: Pack {pname} processado, mas nenhum arquivo extraído.")
                    status = "Falha na Extração"
        
        if "unpack" in mode and count > 0:
            folder_to_copy = os.path.abspath(os.path.join(outdir, "_files", "extracted_packs", pname.replace(".pack", "")))
        else:
            folder_to_copy = os.path.abspath(pack_dir)

        pname_clean = pname.replace(".pack", "")
        if "unpack" in mode and count > 0:
            rel_folder = f"_files/extracted_packs/{pname_clean}"
        else:
            rel_folder = ".git/objects/pack"

        results.append({
            "name": pname, 
            "url_pack": url_pack, 
            "status": status, 
            "count": count,
            "mode": mode,
            "local_folder_rel": rel_folder,
            "local_url": f"file://{os.path.abspath(local_p)}" if os.path.exists(local_p) else None
        })

    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    with open(os.path.join(outdir, "_files", "packfiles.json"), "w") as f:
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
    abs_base_path = os.path.abspath(outdir).replace("\\", "/")
    # Helper para carregar JSON com segurança e UTF-8 explícito
    def safe_load_json(filename, default_val):
        path = os.path.join(files_dir, filename)
        if not os.path.exists(path): return default_val
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            # Em caso de erro, imprime para debug mas não quebra o fluxo
            print(f"[!] Erro ao carregar {filename} para o relatório: {e}")
            return default_val

    # Carrega dados usando o helper seguro
    hardening = safe_load_json("hardening_report.json", {})
    misc = safe_load_json("misc_leaks.json", [])
    packs = safe_load_json("packfiles.json", [])
    bruteforce_data = safe_load_json("bruteforce.json", [])
    users_data = safe_load_json("users.json", [])
    secrets_data = safe_load_json("secrets.json", [])
    
    # Carrega Dump (Listing)
    try:
        listing_entries = load_dump_entries(os.path.join(files_dir, "dump.json"))
        listing_count = len(listing_entries)
    except:
        listing_entries = []
        listing_count = 0

    # Carrega Histórico (Ponto Crítico do Erro Anterior)
    history_data = safe_load_json("history.json", {})
    commits = history_data.get('commits', [])
    head_sha = history_data.get('head', 'N/A')

    # Carrega Stash
    try:
        stash_entries = load_dump_entries(os.path.join(files_dir, "stash.json"))
    except: 
        stash_entries = []

    # --- MONTAGEM DO HTML ---

    stash_section = ""
    if stash_entries:
        stash_section = f"""
        <div class="card mb-4" style="border: 1px solid #f59e0b; background: rgba(245, 158, 11, 0.02);">
            <div class="card-header d-flex justify-content-between" style="background: rgba(245, 158, 11, 0.1); color: #f59e0b; border-bottom: 1px solid #f59e0b;">
                <span>💾 Git Stash Recuperado</span>
                <span class="badge bg-warning text-dark">Prioridade Alta</span>
            </div>
            <div class="card-body">
                <p class="small" style="margin-bottom: 15px;">
                    <strong>{len(stash_entries)} arquivos</strong> com modificações pendentes foram detectados. 
                    O conteúdo foi injetado no topo do histórico para análise de Diffs.
                </p>
                <a href="history.html" class="btn btn-warning w-100" style="background:#f59e0b; color:#000; font-weight:bold; border:none; text-transform:uppercase;">
                    Investigar Alterações no Histórico
                </a>
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

    # --- SEÇÃO DE HISTÓRICO ---
    hist_rows = ""
    if commits:
        for c in commits[:6]:
            is_s = c.get('is_stash', False)
            is_o = c.get('is_orphan', False)
            
            sha_color = "#f59e0b" if is_s else ("#ef4444" if is_o else "var(--hash-color)")
            sha_text = "STASH" if is_s else (c.get('sha', '')[:7] if not is_o else "REFLOG")
            
            raw_msg = c.get('message', '')
            msg = (raw_msg.splitlines()[0][:50] if raw_msg else "Sem mensagem").replace("<", "&lt;")
            
            # Badge de Status
            if is_s:
                badge = '<span class="badge bg-warning text-dark">STASH</span>'
            elif is_o:
                badge = '<span class="badge bg-danger">ORPHAN</span>'
            else:
                badge = f'<span class="badge bg-secondary">{str(c.get("date", "")).split(" ")[0]}</span>'
            
            style = 'background: rgba(245, 158, 11, 0.05);' if is_s else ('background: rgba(239, 68, 68, 0.03);' if is_o else '')

            hist_rows += f"""
            <tr style="{style}">
                <td class="mono"><span style="color:{sha_color}; font-weight:bold;">{sha_text}</span></td>
                <td style="{'color:#f59e0b;' if is_s else ''}">{msg}...</td>
                <td class="text-right">{badge}</td>
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
            st = p.get('status', '')
            name = p.get('name', 'pack')
            remote_url = p.get('url_pack', '')
            mode_used = p.get('mode', '')
            rel_path = p.get('local_folder_rel', '')
            cnt = p.get('count', 0)

            if mode_used == "download-unpack":
                cnt_color = "var(--success)" if cnt > 0 else "#f87171"
                cnt_info = f"<b>{cnt}</b> arquivos extraídos" if cnt > 0 else "Nenhum arquivo restaurado (Verificar integridade)"
            else:
                cnt_color = "var(--warning)"
                cnt_info = "Execução em modo list, para extrair os arquivos use: download-unpack"

            if "Listado" in st or mode_used == "list":
                action_html = f"""
                <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 5px;">
                    Apenas listado (para restaurar use download ou donload-unpack), link direto: 
                    <a href="{p.get('url_pack')}" target="_blank" class="btn" style="padding: 2px 8px; background: var(--bg-hover); color: var(--accent-color); border: 1px solid var(--border-color); border-radius: 4px; text-decoration: none; font-size: 0.7rem; margin-left: 5px;">Baixar .pack ↗</a>
                </div>"""
            else:
                action_html = f"""
                <div style="margin-top: 8px; display: flex; align-items: center; gap: 8px;">
                    <button onclick="handlePackAction('{rel_path}', this)" class="btn btn-pack-action" style="padding: 4px 10px; font-size: 0.7rem; background: var(--accent-color); color: #fff; border: none; border-radius: 4px; cursor: pointer;">
                        Carregando...
                    </button>
                </div>"""

            pack_list_items += f"""
            <li style="margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 10px;">
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #fff; opacity: 0.9; margin-bottom: 4px;">{name}</div>
                <div style="font-size: 0.75rem; color: {cnt_color}; margin-bottom: 6px;">{cnt_info}</div>
                {action_html}
            </li>"""
        pack_content = f"<ul style='list-style:none; padding:0; margin:0;'>{pack_list_items}</ul>"

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
        <script>
            function copyPath(text, btn) {{
                navigator.clipboard.writeText(text).then(() => {{
                    const badge = btn.nextElementSibling;
                    const originalBg = btn.style.background;
                    const originalText = btn.innerText;
                    
                    // Feedback Visual
                    btn.innerText = "Caminho Copiado!";
                    btn.style.background = "var(--success)";
                    badge.style.display = "inline";
                    
                    setTimeout(() => {{
                        btn.innerText = originalText;
                        btn.style.background = originalBg;
                        badge.style.display = "none";
                    }}, 2000);
                }}).catch(err => {{
                    console.error('Erro ao copiar: ', err);
                    alert('Caminho: ' + text); 
                }});
            }}
            function copyDynamicPath(relPath, btn) {{
                let currentPath = window.location.pathname;
                let dirPath = currentPath.substring(0, currentPath.lastIndexOf('/'));
                if (dirPath.startsWith('/') && dirPath.includes(':')) {{
                    dirPath = dirPath.substring(1);
                }}
                dirPath = decodeURIComponent(dirPath);
                
                let fullPath = dirPath + '/' + relPath;
                let finalSystemPath = fullPath.split('/').join('\\\\');

                navigator.clipboard.writeText(finalSystemPath).then(() => {{
                    const originalText = btn.innerText;
                    btn.innerText = "Caminho Copiado!";
                    btn.style.background = "#10b981";
                    
                    setTimeout(() => {{
                        btn.innerText = originalText;
                        btn.style.background = "";
                    }}, 2000);
                }});
            }}
            const ABS_BASE_PATH = "{abs_base_path}";
            const isServed = window.location.protocol.startsWith('http');
            function handlePackAction(relPath, btn) {{
                if (isServed) {{
                    window.open(relPath + '/', '_blank');
                }} else {{
                    let fullPath = ABS_BASE_PATH + '/' + relPath;
                    let finalSystemPath = fullPath.split('/').join('\\\\');

                    navigator.clipboard.writeText(finalSystemPath).then(() => {{
                        const originalText = btn.innerText;
                        
                        btn.innerText = "Caminho Copiado!";
                        btn.style.backgroundColor = "var(--success)";
                        
                        setTimeout(() => {{
                            btn.innerText = originalText;
                            btn.style.backgroundColor = "var(--accent-color)";
                        }}, 2000);
                    }}).catch(err => {{
                        console.error('Erro ao copiar:', err);
                        alert('Caminho: ' + finalSystemPath);
                    }});
                }}
            }}
            document.addEventListener('DOMContentLoaded', () => {{
                document.querySelectorAll('.btn-pack-action').forEach(btn => {{
                    btn.innerText = isServed ? "Abrir Pasta ↗" : "Copiar Caminho Local";
                }});
            }});
        </script>
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
    import glob
    rows = []

    for e in entries:
        path = e.get("path", "")
        sha = e.get("sha1", "")
        if not sha: continue
        
        local_path_rel = path.lstrip("/")
        local_full_path = os.path.join(outdir, local_path_rel)
        
        pack_pattern = os.path.join(outdir, "_files", "extracted_packs", "*", "named_restore", local_path_rel)
        pack_matches = glob.glob(pack_pattern)
        
        local_exists = False
        final_url = ""

        if os.path.exists(local_full_path) and os.path.isfile(local_full_path):
            local_exists = True
            final_url = local_path_rel
        elif pack_matches:
            local_exists = True
            final_url = os.path.relpath(pack_matches[0], outdir).replace("\\", "/")

        rows.append({
            "path": path,
            "remote_url": join_remote_file(site_base, path),
            "blob_url": make_blob_url_from_git(base_git_url, sha),
            "sha": sha,
            "local_exists": local_exists,
            "local_url": final_url
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

            /* Estilos do Viewer */
            #fileViewer {{
                display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0,0,0,0.9); z-index: 9999; padding: 2rem;
            }}
            .viewer-content {{
                background: #0d1117; border: 1px solid #30363d; height: 100%;
                border-radius: 8px; display: flex; flex-direction: column;
            }}
            .viewer-header {{
                padding: 1rem; border-bottom: 1px solid #30363d; display: flex;
                justify-content: space-between; align-items: center;
            }}
            .viewer-body {{ flex: 1; overflow: auto; padding: 1rem; background: #0d1117; }}
            #viewerImage {{ display: none; max-width: 100%; height: auto; margin: 0 auto; border: 1px solid #30363d; }}
            #viewerCodeContainer {{ display: block; }}
            
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
                        localHtml = `<button onclick="viewFile('${{r.local_url}}', '${{r.path}}')" class="badge badge-success" style="padding: 3px 8px; font-size: 0.7rem; background: var(--success); color: #000; font-weight: bold; border: none; border-radius: 4px; cursor: pointer;">Restaurado Local</button>`;
                        // localHtml = `<a href="${{r.local_url}}" target="_blank" style="text-decoration:none"><span class="badge badge-success">Restaurado Local</span></a>`;
                    }} else {{
                        localHtml = `<span class="badge badge-missing" style="opacity: 0.5; font-size: 0.7rem;">Apenas remoto</span>`;
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

            async function viewFile(url, filename) {{
                const viewer = document.getElementById('fileViewer');
                const codeArea = document.getElementById('viewerCode');
                const codeContainer = document.getElementById('viewerCodeContainer');
                const imgArea = document.getElementById('viewerImage');
                const title = document.getElementById('viewerTitle');
                
                title.innerText = filename;
                viewer.style.display = 'block';
                
                // Reset visual
                imgArea.style.display = 'none';
                codeContainer.style.display = 'none';
                codeArea.textContent = 'Carregando...';

                const ext = filename.split('.').pop().toLowerCase();
                const isImage = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico'].includes(ext);

                if (isImage) {{
                    imgArea.src = url;
                    imgArea.style.display = 'block';
                }} else {{
                    codeContainer.style.display = 'block';
                    try {{
                        const response = await fetch(url);
                        if (!response.ok) throw new Error('Falha ao ler arquivo.');
                        const text = await response.text();
                        
                        codeArea.textContent = text;
                        
                        // Tenta aplicar o highlight, se falhar, mantém texto plano
                        try {{
                            const langMap = {{ 'cs': 'csharp', 'php': 'php', 'py': 'python', 'js': 'javascript', 'json': 'json', 'env': 'bash' }};
                            codeArea.className = `language-${{langMap[ext] || 'none'}}`;
                            if (window.Prism) Prism.highlightElement(codeArea);
                        }} catch (pErr) {{
                            console.warn("Prism falhou, exibindo texto plano:", pErr);
                            codeArea.className = 'language-none';
                        }}
                    }} catch (err) {{
                        codeArea.textContent = 'Erro ao carregar conteúdo: ' + err.message;
                    }}
                 }}
            }}

            function closeViewer() {{
                document.getElementById('fileViewer').style.display = 'none';
            }}

            // Init
            render();
        </script>
        <div id="fileViewer">
            <div class="viewer-content">
                <div class="viewer-header">
                    <span id="viewerTitle" class="mono"></span>
                    <span class="btn-close" onclick="closeViewer()">&times;</span>
                </div>
                <div class="viewer-body">
                    <img id="viewerImage" src="" alt="Preview">
                    <div id="viewerCodeContainer">
                        <pre><code id="viewerCode" class="language-none"></code></pre>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-csharp.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-php.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
    </body>
    </html>
    """

    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "listing.html")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    
    success(f"Dashboard de Listagem gerado: {outpath}")


def generate_history_html(in_json, out_html, site_base, base_git_url):
    import json, os
    
    with open(in_json, 'r', encoding='utf-8') as f: 
        data = json.load(f)
    
    commits = data.get('commits', [])
    head_sha = data.get('head', 'N/A')
    remote_url = data.get('remote_url', '') 
    
    commits_json = json.dumps(commits, ensure_ascii=True)\
        .replace('<', '\\u003c')\
        .replace('>', '\\u003e')

    remote_html_block = ""
    if remote_url:
        remote_html_block = f'''
        <div class="remote-badge">
            <span style="opacity:0.7">Remoto Detectado:</span> 
            <a href="{remote_url}" target="_blank" style="color:var(--accent-color); font-weight:bold; margin-left:5px;">{remote_url}</a>
        </div>
        '''

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Timeline Git - {site_base}</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{ --bg-body: #0f111a; --bg-card: #1a1d2d; --bg-hover: #23273a; --bg-details: #151824; --text-primary: #e2e8f0; --text-secondary: #94a3b8; --accent-color: #6366f1; --border-color: #2d3748; --success: #10b981; --danger: #ef4444; --warning: #f59e0b; --hash-color: #ec4899; }}
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background-color: var(--bg-body); color: var(--text-primary); font-family: 'Inter', sans-serif; min-height: 100vh; padding: 2rem; }}
            .container {{ max-width: 98%; margin: 0 auto; }}
            
            /* Header Style */
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color); flex-wrap: wrap; gap: 10px; }}
            .title h1 {{ font-size: 1.5rem; font-weight: 600; color: var(--text-primary); }}
            
            /* Stats & Badges */
            .stat-badge {{ background: var(--bg-card); padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.85rem; color: var(--text-secondary); margin-left: 10px; display: inline-block; }}
            .highlight {{ color: var(--accent-color); font-weight: 600; }}
            .remote-badge {{ background: rgba(99, 102, 241, 0.1); padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid rgba(99, 102, 241, 0.3); font-size: 0.9rem; color: #fff; }}

            /* Controls Layout */
            .controls {{ display: grid; grid-template-columns: auto 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; align-items: center; }}
            .btn-back {{ display: inline-flex; align-items: center; padding: 0.7rem 1.2rem; background-color: var(--bg-card); color: var(--text-primary); text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.9rem; height: 42px; }}
            .btn-back:hover {{ border-color: var(--accent-color); color: var(--accent-color); }}
            .search-box input {{ width: 100%; padding: 0.7rem 1rem; background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary); height: 42px; }}
            
            /* Table Styling */
            .table-container {{ background-color: var(--bg-card); border-radius: 8px; border: 1px solid var(--border-color); overflow: hidden; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }}
            th {{ background-color: rgba(255,255,255,0.03); padding: 1rem; text-align: left; font-weight: 500; color: var(--text-secondary); border-bottom: 1px solid var(--border-color); }}
            
            .commit-row {{ cursor: pointer; transition: background 0.1s; }}
            .commit-row:hover {{ background-color: var(--bg-hover); }}
            .commit-row td {{ padding: 1rem; border-bottom: 1px solid var(--border-color); vertical-align: top; }}
            
            .details-row {{ background-color: var(--bg-details); display: none; }}
            .details-row.active {{ display: table-row; }}
            .details-content {{ padding: 10px 0; border-bottom: 1px solid var(--border-color); box-shadow: inset 0 0 10px rgba(0,0,0,0.2); }}

            th:nth-child(1) {{ width: 10%; }} 
            th:nth-child(2) {{ width: 12%; }} 
            th:nth-child(3) {{ width: 15%; }} 
            th:nth-child(4) {{ width: 40%; }} 
            th:nth-child(5) {{ width: 23%; }}

            .mono {{ font-family: 'JetBrains Mono', monospace; }}
            .hash-link {{ color: var(--hash-color); text-decoration: none; font-weight: bold; }}
            .msg-text {{ color: #d1d5db; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }}
            
            /* File Entry Style */
            .file-entry {{ background: var(--bg-card); border: 1px solid var(--border-color); margin-bottom: 15px; border-radius: 6px; overflow: hidden; margin: 10px 20px; }}
            .file-header {{ padding: 8px 15px; display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.02); }}
            .file-path {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #fff; }}
            
            .change-tag {{ font-size: 0.7rem; font-weight: bold; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; margin-right: 10px; }}
            .tag-added {{ background: rgba(46, 160, 67, 0.2); color: #3fb950; }}
            .tag-mod {{ background: rgba(56, 139, 253, 0.2); color: #58a6ff; }}
            .tag-del {{ background: rgba(248, 81, 73, 0.2); color: #ff7b72; }}

            /* === SIDE BY SIDE DIFF === */
            .diff-container {{ display: none; border-top: 1px solid #30363d; background: #0d1117; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; overflow-x: auto; width: 100%; }}
            .diff-container.open {{ display: block; }}
            
            /* Importante: table-layout: fixed para respeitar as larguras do colgroup */
            .diff-table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
            .diff-table td {{ padding: 2px 4px; vertical-align: top; white-space: pre-wrap; word-break: break-all; border-bottom: none; line-height: 1.4; }}
            
            /* Coluna de números (Alvo da correção) */
            /* Largura controlada pelo <col>, aqui apenas alinhamento */
            .diff-num {{
                text-align: right; 
                color: #6e7681; 
                user-select: none; 
                border-right: 1px solid #30363d; 
                background: #0d1117; 
                opacity: 0.6;
                padding-right: 5px;
            }}

            .search-box {{ position: relative; }}
            .search-box input {{ width: 100%; padding: 0.7rem 1rem 0.7rem 2.5rem; background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; height: 42px; }}
            .search-box input:focus {{ outline: none; border-color: var(--accent-color); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); pointer-events: none; }}
            
            .deletion {{ background-color: rgba(248, 81, 73, 0.15); color: #ff7b72; }}
            .addition {{ background-color: rgba(46, 160, 67, 0.15); color: #3fb950; }}
            .empty-cell {{ background-color: #0d1117; }} 

            .btn-toggle-diff {{ background: transparent; border: 1px solid var(--border-color); color: var(--accent-color); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; transition: 0.2s; }}
            .btn-toggle-diff:hover {{ background: var(--accent-color); color: white; }}
            
            .alert-fast-mode {{ color: #ef4444; font-weight: bold; background: rgba(239, 68, 68, 0.1); padding: 4px 8px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.3); font-size: 0.8rem; display: inline-flex; align-items: center; gap: 5px; }}

            /* Pagination */
            .pagination-container {{ display: flex; justify-content: space-between; align-items: center; padding: 1rem; border-top: 1px solid var(--border-color); color: var(--text-secondary); }}
            .page-btn {{ background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-primary); width: 32px; height: 32px; border-radius: 6px; cursor: pointer; }}
            .page-btn.active {{ background: var(--accent-color); border-color: var(--accent-color); color: white; }}
            
            /* Estilo para Linha de Stash */
            .commit-row.is-stash {{ 
                border-left: 4px solid var(--warning) !important;
                background: rgba(245, 158, 11, 0.05);
            }}
            .is-stash .hash-link {{ color: var(--warning) !important; }}
            .is-stash .msg-text {{ color: var(--warning) !important; font-weight: bold; }}
            
            .tag-stashed {{
                background: rgba(245, 158, 11, 0.2); 
                color: var(--warning); 
            }}

            .commit-row.is-orphan {{ 
                border-left: 4px solid var(--danger) !important;
                background: rgba(239, 68, 68, 0.04); 
            }}

            .tag-orphan {{ 
                background: rgba(239, 68, 68, 0.2); 
                color: var(--danger); 
                border: 1px solid rgba(239, 68, 68, 0.3);
            }}

            @media (max-width: 900px) {{
                .controls {{ grid-template-columns: 1fr; }}
                .diff-table td {{ white-space: pre; }} 
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div>
                    <h1>Timeline Git</h1>
                    <p>Target: {site_base}</p>
                </div>
                <div style="display:flex; align-items:center;">
                    {remote_html_block}
                    <span class="stat-badge">HEAD: <span class="highlight mono">{head_sha[:8]}</span></span>
                    <span class="stat-badge">Commits: <span class="highlight">{len(commits)}</span></span>
                </div>
            </header>

            <div class="controls">
                <a href="report.html" class="btn-back">&larr; Voltar ao Painel</a>
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="q-meta" placeholder="Buscar Commit (Hash, Autor, Mensagem)...">
                </div>

                <div class="search-box">
                    <span class="search-icon">📂</span>
                    <input type="text" id="q-files" placeholder="Filtrar Arquivos (Nome, Motivo, Conteúdo Diff)...">
                </div>
            </div>

            <div class="table-container">
                <table id="commits-table">
                    <thead><tr><th>Hash</th><th>Data</th><th>Autor</th><th>Mensagem</th><th>Arquivos</th></tr></thead>
                    <tbody id="table-body"></tbody>
                </table>
            </div>

            <div class="pagination-container">
                <div id="entries-info">Carregando...</div>
                <div id="pagination-controls" style="display:flex; gap:5px;"></div>
            </div>
        </div>

        <script>
            const COMMITS = {commits_json};
            const tableBody = document.getElementById('table-body');
            const searchMeta = document.getElementById('q-meta');
            const searchFiles = document.getElementById('q-files');
            const entriesInfo = document.getElementById('entries-info');
            const pgControls = document.getElementById('pagination-controls');

            let filteredCommits = COMMITS;
            let currentPage = 1;
            const itemsPerPage = 20;
            let currentFileFilter = "";

            function escapeHtml(text) {{
                if (!text) return '';
                return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
            }}

            function toggleDetails(idx) {{
                const row = document.getElementById(`row-${{idx}}`);
                const details = document.getElementById(`details-${{idx}}`);
                if (details.style.display === 'table-row') {{
                    details.style.display = 'none';
                    row.style.background = '';
                }} else {{
                    details.style.display = 'table-row';
                    row.style.background = 'var(--bg-hover)';
                }}
            }}

            function toggleDiff(uid) {{
                const el = document.getElementById(uid);
                el.classList.toggle('open');
            }}
            
            function renderSideBySide(diffText) {{
                if (!diffText || diffText.startsWith('[') || diffText.includes('Irrecuperável')) {{
                    return `
                        <div style="padding: 20px; color: #f87171; background: rgba(239, 68, 68, 0.05); border: 1px dashed rgba(239, 68, 68, 0.3); margin: 10px; border-radius: 6px; font-family: sans-serif;">
                            <strong style="display:block; margin-bottom:5px;">⚠️ Conteúdo Indisponível</strong>
                            <span style="font-size: 0.85rem; opacity: 0.8;">${{escapeHtml(diffText)}}</span>
                        </div>`;
                }}

                const lines = diffText.split(/\\r?\\n/);
                let rows = '';
                
                let oldLineNum = 1;
                let newLineNum = 1;

                for (let i = 0; i < lines.length; i++) {{
                    const line = lines[i];
                    if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('index ')) continue;
                    
                    if (line.startsWith('@@')) {{
                        rows += `<tr style="background:#1c2128; color:#8b949e"><td colspan="4" style="padding:4px 10px; text-align:center; font-size:0.7rem">${{escapeHtml(line)}}</td></tr>`;
                        continue;
                    }}

                    let leftContent = '&nbsp;';
                    let rightContent = '&nbsp;';
                    let leftClass = 'empty-cell';
                    let rightClass = 'empty-cell';
                    let lNum = '';
                    let rNum = '';

                    if (line.startsWith('-')) {{
                        leftContent = escapeHtml(line.substring(1)) || ' ';
                        leftClass = 'deletion';
                        lNum = oldLineNum++;
                        if (i + 1 < lines.length && lines[i+1].startsWith('+')) {{
                            const nextLine = lines[++i];
                            rightContent = escapeHtml(nextLine.substring(1)) || ' ';
                            rightClass = 'addition';
                            rNum = newLineNum++;
                        }}
                    }} else if (line.startsWith('+')) {{
                        rightContent = escapeHtml(line.substring(1)) || ' ';
                        rightClass = 'addition';
                        rNum = newLineNum++;
                    }} else {{
                        const content = escapeHtml(line.substring(1)) || ' ';
                        leftContent = content;
                        rightContent = content;
                        lNum = oldLineNum++;
                        rNum = newLineNum++;
                    }}

                    rows += `
                        <tr>
                            <td class="diff-num">${{lNum}}</td>
                            <td class="${{leftClass}}">${{leftContent}}</td>
                            <td class="diff-num">${{rNum}}</td>
                            <td class="${{rightClass}}">${{rightContent}}</td>
                        </tr>
                    `;
                }}

                return `
                <table class="diff-table">
                    <colgroup>
                        <col style="width: 35px; min-width: 35px;">
                        <col style="width: auto;">
                        <col style="width: 35px; min-width: 35px;">
                        <col style="width: auto;">
                    </colgroup>
                    ${{rows}}
                </table>`;
            }}

            function renderTable() {{
                const totalPages = Math.ceil(filteredCommits.length / itemsPerPage) || 1;
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;
                const start = (currentPage - 1) * itemsPerPage;
                const end = start + itemsPerPage;
                
                tableBody.innerHTML = '';

                filteredCommits.slice(start, end).forEach((c, idx) => {{
                    const trMain = document.createElement('tr');
                    trMain.className = 'commit-row' + (c.is_stash ? ' is-stash' : '');
                    trMain.id = `row-${{idx}}`;
                    trMain.onclick = () => toggleDetails(idx);

                    const realCount = (c.changes && c.changes.length > 0) ? c.changes.length : (c.files ? c.files.length : 0);
                    
                    let filesSummary = '';
                    if (c.fast_mode_skipped) {{
                         filesSummary = `<span class="alert-fast-mode">⚠️ Objetos não listados (Fast Mode). Use --full-history.</span>`;
                    }} else {{
                         filesSummary = `<span class="stat-badge" style="margin:0">${{realCount}} arquivos</span> <span style="font-size:0.8rem">▶</span>`;
                    }}

                    trMain.innerHTML = `
                        <td><span class="hash-link">${{c.sha.substring(0,8)}}</span></td>
                        <td style="color:var(--text-secondary)">${{c.date || '-'}}</td>
                        <td style="color:#fff">${{escapeHtml(c.author)}}</td>
                        <td><div class="msg-text">${{escapeHtml(c.message)}}</div></td>
                        <td>${{filesSummary}}</td>
                    `;

                    const trDetails = document.createElement('tr');
                    trDetails.className = 'details-row';
                    trDetails.id = `details-${{idx}}`;

                    let contentHtml = '';
                    
                    if (c.fast_mode_skipped) {{
                        contentHtml = '<div style="padding:20px; color:#ef4444; font-weight:bold;">⚠️ Detalhes omitidos para otimizar a performance (Fast Mode).<br><span style="font-weight:normal; color:#ccc; margin-top:5px; display:block;">Este commit não foi analisado profundamente. Execute novamente com <code style="background:#333; padding:2px; color:#fff">--full-history</code> para baixar e analisar todos os objetos históricos (processo mais lento).</span></div>';
                    }} else if (c.changes && c.changes.length > 0) {{
                        const filteredChanges = c.changes.filter(ch => !currentFileFilter || (ch.path.toLowerCase().includes(currentFileFilter) || (ch.diff||'').toLowerCase().includes(currentFileFilter)));
                        
                        if (filteredChanges.length > 0) {{
                            const items = filteredChanges.map((ch, fIdx) => {{
                                let tagClass = '';
                                if (ch.type === 'ADDED') tagClass = 'tag-added';
                                else if (ch.type === 'MODIFIED') tagClass = 'tag-mod';
                                else if (ch.type === 'DELETED') tagClass = 'tag-del';
                                else if (ch.type === 'STASHED') tagClass = 'tag-stashed';

                                const uid = `diff-${{idx}}-${{fIdx}}`;
                                let diffHtml = '';
                                let btnHtml = '';

                                if (ch.diff) {{
                                    btnHtml = `<button class="btn-toggle-diff" onclick="event.stopPropagation(); toggleDiff('${{uid}}')">Ver Diff</button>`;
                                    const sideBySide = renderSideBySide(ch.diff);
                                    diffHtml = `<div id="${{uid}}" class="diff-container" onclick="event.stopPropagation()">${{sideBySide}}</div>`;
                                }}

                                return `
                                <div class="file-entry">
                                    <div class="file-header" onclick="event.stopPropagation()">
                                        <div><span class="change-tag ${{tagClass}}">${{ch.type}}</span> <span class="file-path">${{escapeHtml(ch.path)}}</span></div>
                                        ${{btnHtml}}
                                    </div>
                                    ${{diffHtml}}
                                </div>`;
                            }}).join('');
                            contentHtml = `<div class="details-content">${{items}}</div>`;
                        }} else {{
                            contentHtml = '<div class="details-content" style="color:#666; padding-left:20px;">Nenhum arquivo corresponde ao filtro.</div>';
                        }}
                    }} else {{
                        contentHtml = '<div class="details-content" style="color:#666; padding-left:20px;">Nenhuma alteração registrada ou arquivos vazios.</div>';
                    }}

                    trDetails.innerHTML = `<td colspan="5" style="padding:0; border:none;">${{contentHtml}}</td>`;
                    tableBody.append(trMain, trDetails);
                }});

                entriesInfo.innerText = `Página ${{currentPage}} de ${{Math.ceil(filteredCommits.length/itemsPerPage) || 1}}`;
                renderPagination(Math.ceil(filteredCommits.length/itemsPerPage) || 1);
            }}

            function renderPagination(totalPages) {{
                pgControls.innerHTML = '';
                const btnPrev = document.createElement('button');
                btnPrev.className = 'page-btn'; btnPrev.innerText = '‹';
                btnPrev.onclick = () => {{ currentPage--; renderTable(); }};
                if(currentPage===1) btnPrev.disabled = true;
                
                const btnNext = document.createElement('button');
                btnNext.className = 'page-btn'; btnNext.innerText = '›';
                btnNext.onclick = () => {{ currentPage++; renderTable(); }};
                if(currentPage===totalPages) btnNext.disabled = true;

                pgControls.append(btnPrev, btnNext);
            }}

            function applyFilters() {{
                const qM = searchMeta.value.toLowerCase();
                const qF = searchFiles.value.toLowerCase();
                currentFileFilter = qF;

                filteredCommits = COMMITS.filter(c => {{
                    const matchMeta = !qM || (c.sha||'').includes(qM) || (c.author||'').toLowerCase().includes(qM) || (c.message||'').toLowerCase().includes(qM);
                    if (c.fast_mode_skipped) return matchMeta;
                    
                    let matchFiles = true;
                    if (qF) {{
                        matchFiles = c.changes ? c.changes.some(ch => ch.path.toLowerCase().includes(qF)) : false;
                    }}
                    return matchMeta && matchFiles;
                }});
                currentPage = 1;
                renderTable();
            }}

            searchMeta.addEventListener('input', applyFilters);
            searchFiles.addEventListener('input', applyFilters);

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


def generate_stash_html(stash_data: List[Dict[str, Any]], out_html: str, site_base: str):
    import json
    
    fake_commit = [{
        "sha": "STASH",
        "author": "Git Stash Recovery",
        "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "message": "Conteúdo recuperado do Stash (WIP)",
        "changes": stash_data # Lista de arquivos com 'diff' (conteúdo)
    }]
    
    commits_json = json.dumps(fake_commit, ensure_ascii=True)\
        .replace('<', '\\u003c')\
        .replace('>', '\\u003e')

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Stash View - {site_base}</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{ --bg-body: #0f111a; --bg-card: #1a1d2d; --bg-hover: #23273a; --bg-details: #151824; --text-primary: #e2e8f0; --text-secondary: #94a3b8; --accent-color: #f59e0b; --border-color: #2d3748; --success: #10b981; --danger: #ef4444; --warning: #f59e0b; --hash-color: #ec4899; }}
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background-color: var(--bg-body); color: var(--text-primary); font-family: 'Inter', sans-serif; min-height: 100vh; padding: 2rem; }}
            .container {{ max-width: 1400px; margin: 0 auto; }}
            
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color); }}
            .title h1 {{ font-size: 1.5rem; font-weight: 600; color: var(--warning); }}
            .controls {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
            .btn-back {{ display: inline-flex; align-items: center; padding: 0.7rem 1.2rem; background-color: var(--bg-card); color: var(--text-primary); text-decoration: none; border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.9rem; transition: all 0.2s; }}
            .btn-back:hover {{ border-color: var(--warning); color: var(--warning); }}
            .search-box {{ flex: 1; position: relative; }}
            .search-box input {{ width: 100%; padding: 0.7rem 1rem 0.7rem 2.5rem; background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary); }}
            .search-icon {{ position: absolute; left: 0.8rem; top: 50%; transform: translateY(-50%); color: var(--text-secondary); }}

            /* Stash Styles */
            .file-entry {{ background: var(--bg-card); border: 1px solid var(--border-color); margin-bottom: 15px; border-radius: 8px; overflow: hidden; }}
            .file-header {{ padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; background: rgba(245, 158, 11, 0.05); cursor: pointer; }}
            .file-path {{ font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: #fff; font-weight: 500; }}
            .tag-stash {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; margin-right: 10px; }}
            
            .diff-viewer {{ display: none; background: #0d1117; border-top: 1px solid var(--border-color); padding: 10px; overflow-x: auto; }}
            .diff-viewer.open {{ display: block; }}
            .diff-line {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; white-space: pre; line-height: 1.5; color: #e2e8f0; }}
            
            .chevron {{ transition: transform 0.2s; }}
            .file-entry.open .chevron {{ transform: rotate(90deg); }}
            .file-entry.open .file-header {{ background: rgba(245, 158, 11, 0.1); border-bottom: 1px solid var(--border-color); }}
        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div class="title">
                    <h1>💾 Git Stash Recuperado</h1>
                    <p>Target: {site_base}</p>
                </div>
                <div><span class="tag-stash" style="font-size:1rem">{len(stash_data)} Arquivos</span></div>
            </header>

            <div class="controls">
                <a href="report.html" class="btn-back">&larr; Voltar ao Painel</a>
                <div class="search-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="q" placeholder="Filtrar arquivos em Stash por nome ou conteúdo...">
                </div>
            </div>

            <div id="stash-container"></div>
        </div>

        <script>
            const DATA = {commits_json}[0].changes; // Pegamos apenas a lista de arquivos do fake commit

            const container = document.getElementById('stash-container');
            const searchInput = document.getElementById('q');

            function escapeHtml(text) {{
                if (!text) return '';
                return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;").replace(/`/g, "&#96;").replace(/\\${{/g, "&#36;{{");
            }}

            function toggleFile(idx) {{
                const el = document.getElementById(`file-${{idx}}`);
                const viewer = document.getElementById(`viewer-${{idx}}`);
                
                if (viewer.classList.contains('open')) {{
                    viewer.classList.remove('open');
                    el.classList.remove('open');
                }} else {{
                    viewer.classList.add('open');
                    el.classList.add('open');
                }}
            }}

            function render(filterText = '') {{
                container.innerHTML = '';
                const q = filterText.toLowerCase();

                DATA.forEach((file, idx) => {{
                    // Filtro
                    if (q) {{
                        const matchPath = (file.path || '').toLowerCase().includes(q);
                        const matchContent = (file.diff || '').toLowerCase().includes(q);
                        if (!matchPath && !matchContent) return;
                    }}

                    const el = document.createElement('div');
                    el.className = 'file-entry';
                    el.id = `file-${{idx}}`;

                    const safeContent = escapeHtml(file.diff || 'Conteúdo binário ou vazio.');
                    // Renderiza conteúdo como linhas simples (sem diff coloring complexo, apenas display)
                    const lines = safeContent.split(/\\r?\\n/).map(l => `<div class="diff-line">${{l}}</div>`).join('');

                    el.innerHTML = `
                        <div class="file-header" onclick="toggleFile(${{idx}})">
                            <div>
                                <span class="tag-stash">STASHED</span>
                                <span class="file-path">${{escapeHtml(file.path)}}</span>
                            </div>
                            <span class="chevron">▶</span>
                        </div>
                        <div id="viewer-${{idx}}" class="diff-viewer">
                            ${{lines}}
                        </div>
                    `;
                    container.appendChild(el);
                }});
                
                if (container.innerHTML === '') {{
                    container.innerHTML = '<div style="text-align:center; color:#666; padding:20px">Nenhum arquivo encontrado com esse filtro.</div>';
                }}
            }}

            searchInput.addEventListener('input', (e) => render(e.target.value));
            render();
        </script>
    </body>
    </html>
    """
    
    try:
        with open(out_html, "w", encoding="utf-8") as f: 
            f.write(html_content)
    except Exception as e:
        print(f"Erro ao salvar HTML de Stash: {e}")


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
                        show_diff: bool = False, workers: int = 50, proxies: Optional[Dict] = None):
    
    info(f"Reconstruindo histórico. Max: {max_commits} | Full: {full_history} | Diffs: {show_diff}")
    os.makedirs(outdir, exist_ok=True)
    site_base = normalize_site_base(base_git_url)

    tree_cache = {}
    intel_path = os.path.join(outdir, "_files", "intelligence.json")
    intel_logs = []
    remote_url_found = ""

    if os.path.exists(intel_path):
        try:
            with open(intel_path, 'r', encoding='utf-8') as f:
                data_intel = json.load(f)
                intel_logs = data_intel.get("logs", [])
                remote_url_found = data_intel.get("remote_url", "")
            info(f"Logs carregados: {len(intel_logs)} commits disponíveis.")
        except: pass

    all_commits_out = []
    processed_shas = set()

    def get_tree_files_cached(tree_sha):
        if not tree_sha: return {}
        if tree_sha in tree_cache: return tree_cache[tree_sha]
        try:
            files = collect_files_from_tree(base_git_url, tree_sha, proxies=proxies, ignore_missing=True)
            f_map = {f['path']: f['sha'] for f in files}
            tree_cache[tree_sha] = f_map
            return f_map
        except: return {}

    def process_log_entry(log_entry, index):
        try:
            sha = log_entry.get("sha")
            if not sha: return None
            
            commit_data = {
                "sha": sha, "ok": True, "author": log_entry.get("author"), "date": log_entry.get("date"),
                "message": log_entry.get("message"), "source": "log",
                "parents": [log_entry.get("old_sha")] if log_entry.get("old_sha") and log_entry.get("old_sha") != "0"*40 else [],
                "files": [], "changes": [], "file_count": 0, "fast_mode_skipped": False
            }

            heavy_analysis = True if (full_history or index < 20) else False
            if not heavy_analysis:
                commit_data["fast_mode_skipped"] = True
                return commit_data

            ok, raw = fetch_object_raw(base_git_url, sha, proxies=proxies)
            if ok:
                is_valid, parsed_data = parse_git_object(raw)
                if is_valid and parsed_data[0] == "commit":
                    meta = parse_commit_content(parsed_data[1])
                    commit_data["tree"] = meta.get("tree")
                    if meta.get("date"): commit_data["date"] = meta.get("date")

                    if meta.get("tree"):
                        current_files_map = get_tree_files_cached(meta.get("tree"))
                        parent_files_map = {}
                        parents = meta.get("parents", []) or ([log_entry.get("old_sha")] if log_entry.get("old_sha") != "0"*40 else [])
                            
                        if parents:
                            p_ok, p_raw = fetch_object_raw(base_git_url, parents[0], proxies=proxies)
                            if p_ok:
                                p_valid, p_parsed = parse_git_object(p_raw)
                                if p_valid:
                                    p_meta = parse_commit_content(p_parsed[1])
                                    parent_files_map = get_tree_files_cached(p_meta.get("tree"))

                        commit_data["files"] = [{"path": p, "sha": s} for p, s in current_files_map.items()]
                        commit_data["file_count"] = len(commit_data["files"])

                        # Lógica de detecção de alterações (Diff)
                        for path, sha_now in current_files_map.items():
                            sha_old = parent_files_map.get(path)
                            diff_text = None
                            if not sha_old:
                                change_type = "ADDED"
                                if show_diff: diff_text = compute_diff(base_git_url, None, sha_now, proxies)
                            elif sha_old != sha_now:
                                change_type = "MODIFIED"
                                if show_diff: diff_text = compute_diff(base_git_url, sha_old, sha_now, proxies)
                            else: continue
                            commit_data["changes"].append({"path": path, "type": change_type, "diff": diff_text})
                        
                        for path in parent_files_map:
                            if path not in current_files_map:
                                commit_data["changes"].append({"path": path, "type": "DELETED", "diff": None})
            return commit_data
        except: return None

    # 2. Processamento dos logs de histórico comum
    if intel_logs:
        limit = min(len(intel_logs), max_commits)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(process_log_entry, entry, i) for i, entry in enumerate(intel_logs[:limit])]
            for future in as_completed(futures):
                res = future.result()
                if res: 
                    all_commits_out.append(res)
                    processed_shas.add(res['sha'])

    # 3. Ordenação Cronológica (Mais recentes primeiro)
    def parse_date_sort(c):
        try: return datetime.strptime(c.get("date", ""), '%Y-%m-%d %H:%M:%S')
        except: return datetime.min

    all_commits_out.sort(key=parse_date_sort, reverse=True)

    # Injeção de REFLOGS
    if intel_logs:
        orphan_count = 0
        info("Analisando Reflog em busca de evidências suprimidas...")
        
        for entry in intel_logs:
            sha = entry.get("sha")
            if sha and sha not in processed_shas:
                try:
                    orphan_data = process_log_entry(entry, 0) 
                    if orphan_data and orphan_data.get("ok"):
                        orphan_data["is_orphan"] = True
                        orphan_data["message"] = f"🕵️ REFLOG: {orphan_data['message']}"
                        
                        all_commits_out.append(orphan_data)
                        processed_shas.add(sha)
                        orphan_count += 1
                except:
                    pass
        
        if orphan_count > 0:
            success(f"Recuperados {orphan_count} commits órfãos/suprimidos.")
            all_commits_out.sort(key=parse_date_sort, reverse=True)
            
            stash_idx = next((i for i, c in enumerate(all_commits_out) if c.get('is_stash')), None)
            if stash_idx is not None:
                s_obj = all_commits_out.pop(stash_idx)
                all_commits_out.insert(0, s_obj)

    # 4. Injeção Prioritária do STASH no topo da listagem
    stash_json_path = os.path.join(outdir, "_files", "stash.json")
    if os.path.exists(stash_json_path):
        try:
            with open(stash_json_path, 'r', encoding='utf-8') as f:
                s_data = json.load(f)
                s_meta = s_data.get("metadata", {})
                s_entries = s_data.get("entries", [])
                
                if s_entries:
                    real_msg = s_meta.get("message", "").strip()
                    display_msg = real_msg if real_msg else "Trabalho em Progresso (Sem descrição no Stash)"
                    
                    stash_commit = {
                        "sha": s_meta.get("sha", "STASH_REF"),
                        "ok": True,
                        "is_stash": True,
                        "author": s_meta.get("author", "Git Stash"),
                        "date": s_meta.get("date", ""),
                        "message": f"STASH: {display_msg}",
                        "changes": s_entries,
                        "source": "stash",
                        "fast_mode_skipped": False
                    }
                    
                    all_commits_out.insert(0, stash_commit)
                    info(f"Stash injetado com sucesso no topo da timeline.")
        except Exception as e:
            warn(f"Erro ao injetar stash no histórico: {e}")
    
    # 5. Geração de relatórios e exportação
    author_stats = {}
    for c in all_commits_out:
        auth = c.get("author")
        if auth: author_stats[auth.strip()] = author_stats.get(auth.strip(), 0) + 1
    generate_users_report(outdir, author_stats)

    hist_json = os.path.join(outdir, "_files", "history.json")
    try:
        head_sha = all_commits_out[0]['sha'] if all_commits_out else "N/A"
        with open(hist_json, "w", encoding="utf-8") as f:
            json.dump({
                "base": base_git_url, "site_base": site_base, "head": head_sha, 
                "remote_url": remote_url_found, "commits": all_commits_out
            }, f, indent=2, ensure_ascii=False, default=str)
        
        generate_history_html(hist_json, os.path.join(outdir, "history.html"), site_base, base_git_url)
        success(f"Timeline histórica gerada com {len(all_commits_out)} entradas.")
    except Exception as e:
        fail(f"Erro ao persistir history.json: {e}")

    # Retorno obrigatório do número total de commits processados
    return len(all_commits_out)


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


def serve_dir(directory, port=8000, open_file="index.html"):
    import http.server
    import socketserver
    import webbrowser

    os.chdir(directory)
    
    class SmartIndexHandler(http.server.SimpleHTTPRequestHandler):
        def send_head(self):
            if self.path == '/' or self.path.startswith('/index.html'):
                self.index_pages = ['index.html']
            else:
                self.index_pages = [] 
            return super().send_head()

    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", port), SmartIndexHandler) as httpd:
            url = f"http://localhost:{port}/{open_file}"
            success(f"Servidor ativo em: http://localhost:{port}")
            info("Pressione Ctrl+C para encerrar.")
            webbrowser.open(url)
            httpd.serve_forever()
    except Exception as e:
        fail(f"Erro ao iniciar servidor: {e}")


def process_pipeline(base_url: str, output_dir: str, args, proxies: Optional[Dict] = None):
    info(f"=== Iniciando Pipeline em: {base_url} ===")
    info(f"Output: {output_dir}")
    
    os.makedirs(output_dir, exist_ok=True)
    index_json = os.path.join(output_dir, "_files", args.output_index)

    # 1. Index / Blind
    raw_index_path = os.path.join(output_dir, "_files", "raw_index")
    
    if not os.path.exists(raw_index_path):
        print("[*] Baixando .git/index...")
        ok_idx, _ = http_get_to_file(base_url.rstrip("/") + "/.git/index", raw_index_path, proxies=proxies)
    else:
        print("[*] Usando .git/index local existente.")
        ok_idx = True
    
    has_index = False
    if ok_idx:
        print(f"[+] .git/index baixado. Tentando analisar...")
        try:
            index_to_json(raw_index_path, index_json)
            has_index = True
            print("[+] Índice Git analisado com sucesso.")
        except Exception as e:
            warn(f"Aviso: .git/index inválido ou corrompido ({e}).")

    if not has_index:
        info("Index não disponível ou inválido. Ativando modo Blind/Crawling...")
        blind_recovery(base_url, output_dir, args.output_index, proxies=proxies)

    # 2. Hardening & Misc
    detect_hardening(base_url, output_dir, proxies=proxies)
    gather_intelligence(base_url, output_dir, proxies=proxies)
    
    stash_sha = recover_stash_content(
        base_url, 
        output_dir, 
        workers=args.workers, 
        proxies=proxies, 
        show_diff=args.show_diff
    )
    if stash_sha:
        reconstruct_all(os.path.join(output_dir, "_files", "stash.json"), base_url, os.path.join(output_dir, "stash_restored"), workers=args.workers)
    
    if args.full_scan:
        detect_misc_leaks(base_url, output_dir, proxies=proxies)

    if args.bruteforce:
        brute_force_scan(base_url, output_dir, wordlist_path=args.wordlist, proxies=proxies)

    # 3. Reports & Reconstruction
    if args.packfile:
        handle_packfiles(args.packfile, base_url, output_dir, proxies=proxies)
    
    make_listing_modern(index_json, base_url, output_dir)
    
    # --- RECONSTRUÇÃO DE HISTÓRICO ---
    reconstruct_history(
        index_json, base_url, output_dir, 
        max_commits=args.max_commits,
        full_history=args.full_history,
        show_diff=args.show_diff,
        workers=args.workers, 
        proxies=proxies
    )
    
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
    p.add_argument("--show-diff", action="store_true", help="Baixa e exibe as diferenças (diffs) de código no histórico (Pode ser MUITO Lento)")
    p.add_argument('--local', type=str, help='Caminho completo da pasta do projeto local (ex: /home/user/app)')

    args = p.parse_args()
    
    # --- CONFIGURAÇÕES GLOBAIS ---
    global USE_RANDOM_AGENT
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    USE_RANDOM_AGENT = not args.no_random_agent
    
    if USE_RANDOM_AGENT: info("Rotação de User-Agents: ATIVADA")

    # --- MODO 1: APENAS SERVIR (Sem scan) ---
    if args.serve and not args.base and not args.scan and not args.local:
        target_path = args.serve_dir if args.serve_dir else args.output_dir
        if not os.path.exists(target_path):
            fail(f"Diretório não encontrado para servir: {target_path}")
            return
        if os.path.exists(os.path.join(target_path, "index.html")):
            serve_dir(target_path, open_file="index.html")
        else:
            serve_dir(target_path, open_file="report.html")
        return

    # --- MODO 2: PREPARAÇÃO DE ALVOS (Unificada) ---
    targets = []

    if args.local:
        targets = [normalize_url(args.local)]
        info(f"Modo Local-Scan: {targets[0]}")
    elif args.scan:
        if not os.path.exists(args.scan):
            fail(f"Arquivo de lista não encontrado: {args.scan}")
            return
        try:
            if os.path.exists(args.scan):
                with open(args.scan, "r", encoding="utf-8") as f:
                    targets = [normalize_url(l.strip()) for l in f if l.strip() and not l.startswith("#")]
            else:
                fail("A lista de alvos não foi encontrada."); return
            info(f"Modo Multi-Scan: {len(targets)} alvos carregados.")
        except Exception as e:
            fail(f"Erro ao ler lista: {e}")
            return
    elif args.base:
        targets = [normalize_url(args.base)]
        info(f"Modo Single-Target: {targets[0]}")
    
    else:
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
        folder_name = get_safe_folder_name(target_url)
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
                 reconstruct_history(os.path.join(target_outdir, "_files", args.output_index), target_url, target_outdir,
                                    max_commits=args.max_commits, full_history=args.full_history,
                                    show_diff=args.show_diff,
                                    proxies=proxies, workers=args.workers)
            else:
                process_pipeline(target_url, target_outdir, args, proxies=proxies)

            # Coleta de Stats
            stats = {"target": target_url, "folder_name": folder_name, "secrets_count": 0, "files_count": 0, "vuln_count": 0}
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