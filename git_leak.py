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
 - --full-history        : Analisa árvore de arquivos completa de TODOS os commits (lento)
 - --full-scan           : Executa verificação completa de vazamentos (SVN, HG, Env, DS_Store)
 - --report              : gera apenas o relatório final (report.html)
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


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

def normalize_url(url):
    url = url.strip()
    
    url = re.sub(r'/\.git(/.*)?$', '', url, flags=re.IGNORECASE).rstrip('/')

    if url.startswith(('http://', 'https://')):
        return url

    print(f"[*] Detectando protocolo para {url}...")
    try:
        resp = requests.get(f"https://{url}", headers=HEADERS, timeout=5, verify=False)
        print("    -> HTTPS detectado.")
        return f"https://{url}"
    except requests.RequestException:
        print("    -> Falha no HTTPS. Usando HTTP.")
        return f"http://{url}"


def http_get_bytes(url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, bytes | str]:
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.get(url, timeout=timeout, stream=True, verify=False)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, r.content
    except Exception as e:
        return False, str(e)


def http_get_to_file(url: str, outpath: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, str]:
    try:
        requests.packages.urllib3.disable_warnings()
        print(f"[!] Tentando baixar {url}  ...")
        r = requests.get(url, timeout=timeout, stream=True, verify=False, headers=HEADERS)
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


def http_head_status(url: str, timeout: int = 6) -> Tuple[bool, Optional[int], str]:
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
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


def parse_git_index_file(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 12 or data[:4] != b"DIRC":
        raise ValueError("Arquivo não parece ser um .git/index válido (cabecalho DIRC).")
    version = read_u32(data, 4)
    count = read_u32(data, 8)
    offset = 12
    entries = []
    for _ in range(count):
        if offset + 62 > len(data): break
        sha_raw = data[offset + 40:offset + 60]
        sha_hex = sha_raw.hex()
        path_start = offset + 62
        try:
            nul = data.index(b"\x00", path_start)
        except ValueError:
            break
        raw_path = data[path_start:nul]
        try:
            path_str = raw_path.decode("utf-8", errors="ignore")
        except:
            path_str = raw_path.decode("latin1", errors="ignore")
        consumed = 62 + len(raw_path) + 1
        padding = (8 - (consumed % 8)) % 8
        offset = path_start + len(raw_path) + 1 + padding
        entries.append({"path": path_str, "sha1": sha_hex})
        if offset >= len(data): break
    return {"version": version, "declared": count, "found": len(entries), "entries": entries}


def index_to_json(index_path: str, out_json: str) -> str:
    parsed = parse_git_index_file(index_path)
    entries = parsed.get("entries", [])
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"entries": entries}, f, indent=2, ensure_ascii=False)
    success(f"Index convertido -> {out_json} ({len(entries)} entradas)")
    return out_json


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


def recover_one_sha(base_git_url: str, sha: str, outdir: str, original_path: Optional[str] = None) -> bool:
    tmpdir = os.path.join(outdir, "__tmp")
    os.makedirs(tmpdir, exist_ok=True)
    tmpfile = os.path.join(tmpdir, sha)
    blob_url = make_blob_url_from_git(base_git_url, sha)
    info(f"Recuperando SHA1: {sha}")

    ok, data = http_get_to_file(blob_url, tmpfile)
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


def fetch_object_raw(base_git_url: str, sha: str) -> Tuple[bool, bytes | str]:
    url = make_blob_url_from_git(base_git_url, sha)
    return http_get_bytes(url)


def collect_files_from_tree(base_git_url: str, tree_sha: str, ignore_missing: bool = True) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    stack: List[Tuple[str, str]] = [("", tree_sha)]
    while stack:
        prefix, sha = stack.pop()
        ok, raw = fetch_object_raw(base_git_url, sha)
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


# ---------------------------
# Misc Leaks (Full Scan)
# ---------------------------
MISC_SIGNATURES = {
    "svn": {"path": "/.svn/wc.db", "magic": b"SQLite format 3", "desc": "Repositório SVN (wc.db)"},
    "hg": {"path": "/.hg/store/00manifest.i", "magic": b"\x00\x00\x00\x01", "desc": "Repositório Mercurial"},
    "ds_store": {"path": "/.DS_Store", "magic": b"\x00\x00\x00\x01", "desc": "Metadados macOS (.DS_Store)"},
    "env": {"path": "/.env", "regex": br"^\s*[A-Z_0-9]+\s*=", "desc": "Variáveis de Ambiente (.env)"}
}


def generate_misc_html(out_html: str, title: str, content_data: str, is_text: bool):
    display_content = f"<pre>{content_data}</pre>" if is_text else f"<p>Arquivo binário detectado e salvo.<br>Consulte a pasta <code>_files/misc</code>.</p>"
    html = f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><title>{title}</title><style>body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}.wrap{{max-width:1000px;margin:0 auto;}}h1{{color:#6be;}}pre{{background:#1a1c1d;padding:15px;border-radius:6px;overflow-x:auto;border:1px solid #333;}}p.meta{{font-size:13px;color:#779;margin-top:20px;text-align:center;}}</style></head><body><div class='wrap'><h1>⚠️ Vazamento Detectado: {title}</h1>{display_content}<p class="meta">Gerado por Git Leak Explorer</p></div></body></html>"""
    with open(out_html, "w", encoding="utf-8") as f: f.write(html)


def detect_misc_leaks(base_url: str, outdir: str) -> List[Dict[str, Any]]:
    info("Iniciando varredura completa (Full Scan) de outros vazamentos...")
    base = base_url.rstrip("/")
    if base.endswith("/.git"): base = base[:-5]

    misc_dir = os.path.join(outdir, "_files", "misc")
    os.makedirs(misc_dir, exist_ok=True)
    findings = []

    for key, sig in MISC_SIGNATURES.items():
        target_url = base + sig["path"]
        ok, data = http_get_bytes(target_url)

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
                if key == "env":
                    filename = ".env"
                elif key == "svn":
                    filename = "wc.db"

                with open(os.path.join(misc_dir, filename), "wb") as f:
                    f.write(data)

                html_name = f"{key}_report.html"
                is_text = key == "env"
                content_display = data.decode("utf-8", "ignore") if is_text else ""
                generate_misc_html(os.path.join(outdir, html_name), sig['desc'], content_display, is_text)

                findings.append({"type": key, "desc": sig["desc"], "url": target_url, "report_file": html_name, "dump_file": filename})

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


def gather_intelligence(base_git_url: str, outdir: str) -> Dict[str, Any]:
    info("Coletando inteligência (Config, Logs, Refs)...")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"

    meta_dir = os.path.join(outdir, "_files", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    intel = {"remote_url": None, "logs": [], "packed_refs": []}

    ok, data = http_get_bytes(base + "/config")
    if ok:
        cfg_path = os.path.join(meta_dir, "config");
        with open(cfg_path, "wb") as f:
            f.write(data)
        intel["remote_url"] = parse_git_config_file(cfg_path)
        if intel["remote_url"]: success(f"Remote Origin detectado: {intel['remote_url']}")

    ok, data = http_get_bytes(base + "/logs/HEAD")
    if ok:
        log_path = os.path.join(meta_dir, "logs_HEAD");
        with open(log_path, "wb") as f: f.write(data)
        intel["logs"] = parse_git_log_file(log_path)
        success(f"Logs de histórico recuperados: {len(intel['logs'])} entradas.")

    ok, data = http_get_bytes(base + "/packed-refs")
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
def find_candidate_shas(base_git_url: str) -> List[Dict[str, str]]:
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"
    candidates = {}

    head_urls = [base + "/HEAD"]
    for url in head_urls:
        ok, data = http_get_bytes(url)
        if not ok: continue
        text = data.decode(errors="ignore").strip()
        if all(c in "0123456789abcdef" for c in text.lower()) and len(text.strip()) == 40:
            candidates[text.strip()] = {"sha": text.strip(), "ref": "HEAD", "source": url}
        elif text.startswith("ref:"):
            ref = text.split(":", 1)[1].strip()
            for ref_url in [base + "/" + ref]:
                ok2, data2 = http_get_bytes(ref_url)
                if ok2:
                    sha = data2.decode(errors="ignore").strip().splitlines()[0].strip()
                    if len(sha) == 40:
                        candidates[sha] = {"sha": sha, "ref": ref, "source": ref_url}
                        break
    ok, data = http_get_bytes(base + "/packed-refs")
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
        ok, data = http_get_bytes(base + "/" + ref)
        if ok:
            sha = data.decode(errors="ignore").strip().splitlines()[0].strip()
            if len(sha) == 40 and sha not in candidates: candidates[sha] = {"sha": sha, "ref": ref,
                                                                            "source": base + "/" + ref}

    return list(candidates.values())


def blind_recovery(base_git_url: str, outdir: str, output_index_name: str) -> bool:
    info("Iniciando MODO BLIND (Reconstrução sem index)...")
    gather_intelligence(base_git_url, outdir)
    candidates = find_candidate_shas(base_git_url)
    if not candidates: fail("Modo Blind falhou: Nenhum SHA inicial."); return False

    start_sha = candidates[0]['sha']
    info(f"Ponto de partida encontrado: {start_sha} ({candidates[0]['ref']})")

    ok, raw = fetch_object_raw(base_git_url, start_sha)
    if not ok: fail("Falha ao baixar commit inicial"); return False
    ok2, parsed = parse_git_object(raw)
    if not ok2 or parsed[0] != "commit": fail("Objeto inicial inválido"); return False

    commit_meta = parse_commit_content(parsed[1])
    root_tree_sha = commit_meta.get("tree")
    if not root_tree_sha: fail("Sem tree associada"); return False

    info(f"Root Tree encontrada: {root_tree_sha}. Crawling...")
    all_files = collect_files_from_tree(base_git_url, root_tree_sha, ignore_missing=True)

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
def detect_hardening(base_git_url: str, outdir: str) -> Dict[str, Any]:
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
                ok_status, code, _ = http_head_status(u)
                if ok_status:
                    status["exposed"] = True; status["positive_urls"].append(
                        {"url": u, "status_code": code, "method": "HEAD"})
                else:
                    ok_get, _ = http_get_bytes(u)
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


def handle_packfiles(mode: str, base_git_url: str, outdir: str):
    info(f"Iniciando manuseio de Packfiles em modo: {mode}")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"
    info_packs_url = base + "/objects/info/packs"
    ok, data = http_get_bytes(info_packs_url)
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
            ok_p, _ = http_get_to_file(url_pack, local_pack_path)
            ok_i, _ = http_get_to_file(url_idx, local_idx_path)
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

    # 4. Packfiles Section
    packfiles_html = f"<h3>4. Packfiles Encontrados</h3><p>Total Encontrado: {len(packs)}</p>"
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

    # 5. Misc Section (Full Scan)
    misc_html = "<h3>5. Outros Vazamentos (Full Scan)</h3>"
    if misc:
        misc_html += "<ul>"
        for m in misc:
            # Usa o nome real do arquivo se disponível (ex: .env), senão usa o padrão _dump
            dump_file = m.get('dump_file', f"{m['type']}_dump")
            misc_html += f"<li><b>{m['type']}</b>: {m['desc']} (<a href='_files/misc/{dump_file}' target='_blank'>Dump</a> | <a href='{m['report_file']}' target='_blank'>Relatório</a>)</li>"
        misc_html += "</ul>"
    else:
        misc_html += "<p class='muted'>Nenhum outro vazamento detectado ou varredura não executada.</p>"

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
    {packfiles_html}
    <hr>
    {misc_html}
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
  </style>
</head>
<body>
<div class='wrap'>
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

    # Template padrão
    html_content = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Git History</title><style>body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}.wrap{{max-width:1200px;margin:0 auto;}}h1{{color:#6be;}}.commit-card{{border:1px solid #333;margin-bottom:15px;padding:15px;border-radius:6px;background:#161819;}}.sha{{font-weight:bold;color:#6be;}}.message{{margin-top:5px;white-space:pre-wrap;font-size:14px;}}.meta{{font-size:12px;color:#779;}}.files{{margin-top:10px;border-top:1px solid #333;padding-top:10px;}}.file-item{{display:block;margin-bottom:3px;}}.error{{color:#ff5252;}}.ok{{color:#6f6;}}a{{color:#6be;}}.source-tag{{font-size:10px;padding:2px 5px;border-radius:4px;margin-left:10px;}}.source-log{{background:#2a3;color:#fff;}}.source-walk{{background:#444;color:#ddd;}}#commits-container>div:nth-child(1) .commit-card{{border-color:#6be;box-shadow:0 0 5px rgba(102,187,238,0.3);}}.filter-header{{display:flex;align-items:center;gap:20px;margin-bottom:20px;}}input[type=text]{{padding:8px;width:100%;max-width:420px;border-radius:6px;border:1px solid #333;background:#071117;color:#dff;}}details{{margin-top:10px;cursor:pointer;}}summary{{font-weight:bold;}}.remote-info{{margin-bottom:20px;padding:10px;background:#1a1c1d;border-radius:6px;border-left:4px solid #6be;}}</style></head><body><div class='wrap'><h1>Reconstrução de Histórico para {site_base}</h1><div class="remote-info"><p class="meta">Referência HEAD: <span class='sha'>{head_sha}</span></p><p class="meta">Origem Remota: <b>{remote_url or "Não detectado"}</b></p><p class="meta">Total: <b>{len(commits)}</b></p></div><div class="filter-header"><input id='q' type='text' placeholder='Filtrar por SHA, autor ou mensagem...'><span id="result-count" class="meta"></span></div><div id='commits-container'></div></div><script>const COMMITS={commits_json};const container=document.getElementById('commits-container');const qInput=document.getElementById('q');const resultCount=document.getElementById('result-count');const remoteUrl="{remote_url}";function getCommitLink(sha){{if(!remoteUrl)return sha;let cleanUrl=remoteUrl.replace('.git','');return `<a href="${{cleanUrl}}/commit/${{sha}}" target="_blank">${{sha}}</a>`;}}function renderCommits(list){{container.innerHTML='';resultCount.textContent=`Exibindo ${{list.length}} commits.`;list.forEach(c=>{{const cardWrapper=document.createElement('div');const card=document.createElement('div');card.className='commit-card';let parentsHtml=c.parents.map(p=>`<a href='#${{p}}'>${{p.substring(0,10)}}</a>`).join(', ');let contentHtml='';let statusBadge='';const statusClass=c.ok?'ok':'error';const shaDisplay=getCommitLink(c.sha);const sourceTag=c.source==='log'?'<span class="source-tag source-log">VIA LOGS</span>':'<span class="source-tag source-walk">VIA GRAFO</span>';if(!c.ok){{let err='Indisponível';statusBadge='ERRO';if(c.error)err=c.error;contentHtml=`<p class='error'>[FALHA] ${{err}}</p>`;}}else{{statusBadge='OK';let filesHtml='';if(c.file_collection_error){{filesHtml=`<span class="error">${{c.file_collection_error}}</span>`;}}else if(c.files&&c.files.length>0){{filesHtml=c.files.map(f=>`<span class='file-item'>${{f.path}} (SHA: ${{f.sha.substring(0,8)}})</span>`).join('');}}else{{filesHtml='<span class="meta">Sem arquivos ou tree vazia.</span>';}}contentHtml=`<p><span class='ok'>[OK]</span> ${{c.message}}</p><p class='meta'>Data: ${{c.date||'?'}}</p><details><summary>Arquivos (${{c.file_count}})</summary><div class='files'>${{filesHtml}}</div></details>`;}}card.innerHTML=`<div><b>${{list.indexOf(c)+1}}.</b> ${{shaDisplay}} <span class='${{statusClass}}'>${{statusBadge}}</span> ${{sourceTag}}</div><div class='meta'>Autor: ${{c.author.replace('<', ' - ').replace('>', ' ')||'N/A'}} — Pais: ${{parentsHtml||'Nenhum'}}</div>${{contentHtml}}`;cardWrapper.appendChild(card);container.appendChild(cardWrapper);}});}}qInput.addEventListener('input',()=>{{const q=qInput.value.toLowerCase().trim();renderCommits(COMMITS.filter(c=>(c.sha||'').toLowerCase().includes(q)||(c.author.replace('<', ' - ').replace('>', ' ')||'').toLowerCase().includes(q)||(c.message||'').toLowerCase().includes(q)));}});renderCommits(COMMITS);</script></body></html>"""
    with open(out_html, "w", encoding="utf-8") as f: f.write(html_content)


def reconstruct_history(input_json: str, base_git_url: str, outdir: str, max_commits: int = 200,
                        ignore_missing: bool = True, strict: bool = False, full_history: bool = False,
                        workers: int = 10):
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

        ok, raw = fetch_object_raw(base_git_url, sha)
        if ok:
            ok2, parsed = parse_git_object(raw)
            if ok2 and parsed[0] == "commit":
                meta = parse_commit_content(parsed[1])
                commit_data["tree"] = meta.get("tree")
                if meta.get("date"): commit_data["date"] = meta.get("date")
                if meta.get("tree"):
                    try:
                        files = collect_files_from_tree(base_git_url, meta.get("tree"), ignore_missing=True)
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
        candidate_shas = find_candidate_shas(base_git_url)
        queue = [c['sha'] for c in candidate_shas];
        visited = set(queue)
        while queue and len(all_commits_out) < max_commits:
            cur = queue.pop(0)
            ok, raw = fetch_object_raw(base_git_url, cur)
            if not ok: continue
            ok2, parsed = parse_git_object(raw)
            if not ok2 or parsed[0] != 'commit': continue
            meta = parse_commit_content(parsed[1])
            files = []
            if len(all_commits_out) < 10 and meta.get("tree"):
                try:
                    files = collect_files_from_tree(base_git_url, meta.get("tree"), ignore_missing=True)
                except:
                    pass
            all_commits_out.append({
                "sha": cur, "ok": True, "tree": meta.get("tree"), "parents": meta.get("parents", []),
                "author": meta.get("author"), "date": meta.get("date"), "message": meta.get("message"),
                "files": files, "file_count": len(files), "source": "graph"
            })
            for p in meta.get("parents", []):
                if p not in visited: queue.append(p); visited.add(p)

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


def main():
    p = argparse.ArgumentParser(prog="git_leak.py", description="Git Leak Explorer - Ferramenta de Análise Forense")
    p.add_argument("base", nargs="?", help="URL base alvo (ex: http://site.com/.git/ ou site.com)")
    p.add_argument("--output-index", default="dump.json",
                   help="Nome do arquivo de saída para o índice JSON (padrão: dump.json)")
    p.add_argument("--output-dir", default="./repo",
                   help="Diretório de saída para os arquivos recuperados (padrão: ./repo)")
    p.add_argument("--serve-dir", nargs="?", help="Diretório específico para servir via HTTP (opcional)")
    p.add_argument("--default", action="store_true",
                   help="Executa o pipeline padrão (scan, hardening, listagem, histórico e relatórios)")
    p.add_argument("--report", action="store_true",
                   help="Gera apenas o relatório unificado a partir dos dados já baixados")
    p.add_argument("--parse-index", action="store_true", help="Apenas baixa e converte o .git/index remoto para JSON")
    p.add_argument("--blind", action="store_true", help="Ativa modo Blind (Crawling) se o index não estiver acessível")
    p.add_argument("--list", action="store_true", help="Gera a listagem visual de arquivos (listing.html)")
    p.add_argument("--reconstruct-history", action="store_true",
                   help="Reconstrói o histórico de commits (apenas metadados/visualização)")
    p.add_argument("--max-commits", type=int, default=200,
                   help="Limite de commits a analisar no histórico (padrão: 200)")
    p.add_argument("--ignore-missing", action="store_true",
                   help="Ignora erros de objetos ausentes durante a reconstrução")
    p.add_argument("--strict", action="store_true", help="Aborta a operação ao encontrar erros críticos")
    p.add_argument("--sha1", help="Baixa e restaura um objeto específico pelo Hash SHA1")
    p.add_argument("--detect-hardening", action="store_true",
                   help="Verifica configurações de segurança e exposição do .git")
    p.add_argument("--packfile", choices=['list', 'download', 'download-unpack'],
                   help="Gerencia arquivos .pack (list, download, download-unpack)")
    p.add_argument("--serve", action="store_true", help="Inicia um servidor web local para visualizar os relatórios")
    p.add_argument("--workers", type=int, default=10, help="Número de threads para downloads paralelos (padrão: 10)")
    p.add_argument("--scan", help="Lista de URLs (arquivo) para varredura em massa")
    p.add_argument("--check-public", action="store_true",
                   help="Verifica se os arquivos listados estão acessíveis publicamente (HEAD request)")
    p.add_argument("--full-history", action="store_true",
                   help="Analisa árvore de arquivos completa de TODOS os commits (lento)")
    p.add_argument("--full-scan", action="store_true",
                   help="Executa verificação completa de vazamentos (SVN, HG, Env, DS_Store)")

    args = p.parse_args()

    base_url = normalize_url(args.base);
    
    print(f"[*] URL alvo normalizada: {base_url}")

    output_dir = args.output_dir;
    index_name = args.output_index

    actions = [args.scan, args.serve, args.report, args.packfile, args.blind, args.sha1, args.default, args.parse_index,
               args.list, args.reconstruct_history, args.detect_hardening, args.full_scan]
    if args.full_scan:
        args.default = True  # --full-scan : default pipeline
    elif base_url and not any(actions):
        args.default = True  # auto default

    if args.scan: scan_urls(args.scan); return
    if args.serve: serve_dir(args.serve_dir if args.serve_dir else output_dir); return
    if args.report:
        if not base_url: fail("Requer URL base."); return
        generate_unified_report(output_dir, base_url);
        return
    if args.packfile:
        if not base_url: fail("Requer URL base."); return
        handle_packfiles(args.packfile, base_url, output_dir);
        return
    if args.blind:
        if not base_url: fail("Requer URL base."); return
        blind_recovery(base_url, output_dir, index_name);
        return
    if args.sha1:
        if not base_url: fail("Requer URL base."); return
        os.makedirs(output_dir, exist_ok=True);
        resolved_path = None
        try:
            dump_path = os.path.join(output_dir, "_files", index_name)
            if os.path.exists(dump_path):
                for e in load_dump_entries(dump_path):
                    if e.get('sha1') == args.sha1: resolved_path = e.get('path'); break
        except:
            pass
        if not resolved_path:
            try:
                hist_path = os.path.join(output_dir, "_files", "history.json")
                if os.path.exists(hist_path):
                    with open(hist_path, 'r', encoding='utf-8') as f:
                        for c in json.load(f).get('commits', []):
                            for file in c.get('files', []):
                                if file.get('sha') == args.sha1: resolved_path = file.get('path'); break
                            if resolved_path: break
            except:
                pass
        if not resolved_path:
            info("Tentando resolver nome do arquivo via .git/index remoto...")
            tmp_idx = os.path.join(output_dir, "__temp_index_lookup");
            idx_url = base_url.rstrip("/")
            if not idx_url.endswith(".git"): idx_url += "/.git"
            idx_url += "/index"
            ok_idx, _ = http_get_to_file(idx_url, tmp_idx)
            if ok_idx:
                try:
                    for e in parse_git_index_file(tmp_idx).get("entries", []):
                        if e.get("sha1") == args.sha1: resolved_path = e.get("path"); info(
                            f"Encontrado no índice remoto: {resolved_path}"); break
                except:
                    pass
                finally:
                    if os.path.exists(tmp_idx): os.remove(tmp_idx)
        recover_one_sha(base_url, args.sha1, output_dir, resolved_path);
        return

    if args.default:
        if not base_url: fail("Requer URL."); return
        info(f"Pipeline em {base_url}...");
        os.makedirs(output_dir, exist_ok=True)
        index_json = os.path.join(output_dir, "_files", args.output_index)

        # 1. Index / Blind
        ok_idx, _ = http_get_to_file(base_url.rstrip("/") + "/.git/index",
                                     os.path.join(output_dir, "_files", "raw_index"))
        if ok_idx:
            print(f"[+] Tentando analisar o índice Git em {output_dir}...")

            try:
                index_to_json(os.path.join(output_dir, "_files", "raw_index"), index_json)
                print("[+] Índice Git analisado com sucesso.")

            except ValueError as e:
                print(
                    f"[-] Aviso: Não foi possível processar o .git/index. O repositório pode não estar exposto ou é inválido.")
                print(f"    Detalhe do erro: {e}")

            except Exception as e:
                print(f"[-] Erro inesperado ao processar Git: {e}")

            print("[*] Continuando para a geração do relatório final...")
        else:
            blind_recovery(base_url, output_dir, args.output_index)

        # 2. Hardening & Misc
        detect_hardening(base_url, output_dir);
        gather_intelligence(base_url, output_dir)
        if args.full_scan: detect_misc_leaks(base_url, output_dir)

        # 3. Reports
        handle_packfiles('list', base_url, output_dir)
        make_listing_modern(index_json, base_url, output_dir)
        reconstruct_history(index_json, base_url, output_dir, max_commits=args.max_commits,
                            full_history=args.full_history, workers=args.workers)
        generate_unified_report(output_dir, base_url)
        serve_dir(output_dir)
        return


if __name__ == "__main__":
    main()