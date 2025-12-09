#!/usr/bin/env python3
"""
git_leak.py — Conjunto completo de ferramentas em arquivo único para recuperação e análise forense de vazamentos do Git.

Principais funcionalidades implementadas:
 - --parse-index         : baixa .git/index e converte para JSON
 - --blind               : Blind mode: Rastrear commits/árvores quando .git/index está ausente/403
 - reconstruct (default) : Baixa os blobs do dump.json e reconstrói o diretório .git/objects localmente.
 - --list                : gera listing.html (UI simplificada) dos arquivos encontrados no indice, com links
 - --serve               : abre um servidor http para visualização dos relatórios
 - --sha1                : baixa um objeto único pelo SHA
 - --reconstruct-history : reconstrói cadeia de commits somente como interface do usuário (history.json + history.html)
 - --detect-hardening    : verificações de exposição e gera os arquivos hardening_report.json e hardening_report.html.
 - --packfile [MODE]     : manuseio de packfiles (modes: list, download, download-unpack)
 - --scan                : roda scan em multiplos albos em busca de .git/HEAD exposure
 - --default             : roda parse-index, detect-hardening, packfile(list), list, reconstruct-history e serve
 - --report              : gera apenas o relatório final (report.html)
 - options: --max-commits, --ignore-missing, --strict, --workers, --output-index, --output-dir, --serve-dir
 - Todos os arquivos de saída são armazenados no diretório externo fornecido: arquivos HTML na raiz, arquivos JSON/outros arquivos em outdir/_files.

Utilize de forma responsável e somente em sistemas que você esteja autorizado a testar.
"""

from __future__ import annotations
import os
import sys
import json
import argparse
import requests
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


def http_get_bytes(url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, bytes | str]:
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, r.content
    except Exception as e:
        return False, str(e)


def http_head_status(url: str, timeout: int = 6) -> Tuple[bool, Optional[int], str]:
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        code = getattr(r, "status_code", None)
        if code and 200 <= code < 300:
            return True, code, "OK"
        else:
            return False, code, f"HTTP {code}"
    except Exception as e:
        return False, None, str(e)


def http_get_to_file(url: str, outpath: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, str]:
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        with open(outpath, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
        return True, "ok"
    except Exception as e:
        return False, str(e)


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
    info(f"Recuperando \"{original_path or '(sem path)'}\" SHA1: {sha}")
    ok, data = http_get_to_file(blob_url, tmpfile)
    if not ok:
        warn(f"Falha ao baixar: {data}")
        return False
    try:
        ensure_git_repo_dir(outdir)
        dest_dir = os.path.join(outdir, ".git", "objects", sha[:2])
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(tmpfile, os.path.join(dest_dir, sha[2:]))
        success(f"\"{original_path or sha}\" OK.")
        return True
    except Exception as e:
        warn(f"Falha ao mover objeto: {e}")
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
    except Exception:
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
    info = {"tree": None, "parents": [], "author": None, "committer": None, "message": ""}
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            i += 1;
            break
        if line.startswith("tree "):
            info["tree"] = line.split()[1].strip()
        elif line.startswith("parent "):
            info["parents"].append(line.split()[1].strip())
        elif line.startswith("author "):
            info["author"] = line[7:].strip()
        elif line.startswith("committer "):
            info["committer"] = line[10:].strip()
        i += 1
    info["message"] = "\n".join(lines[i:]).strip()
    return info


def parse_tree(content_bytes: bytes) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    i = 0
    b = content_bytes
    L = len(b)
    while i < L:
        j = b.find(b' ', i)
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
# Intelligence Gathering & Parsing
# ---------------------------
def parse_git_log_file(file_path: str) -> List[Dict[str, Any]]:
    """Lê o arquivo logs/HEAD e retorna lista estruturada."""
    entries = []
    if not os.path.exists(file_path): return entries
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) < 1: continue
                meta = parts[0].split(" ")
                message = parts[1] if len(parts) > 1 else ""

                # Format: old_sha new_sha Author <email> timestamp tz
                if len(meta) >= 4:
                    old_sha = meta[0]
                    new_sha = meta[1]
                    # Encontrar timestamp (últimos 2 campos são timestamp e tz)
                    ts = meta[-2]
                    tz = meta[-1]
                    author_raw = " ".join(meta[2:-2])

                    try:
                        dt = datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        dt = ts

                    entries.append({
                        "sha": new_sha,
                        "old_sha": old_sha,
                        "author": author_raw,
                        "date": dt,
                        "message": message,
                        "source": "log"
                    })
    except Exception as e:
        warn(f"Erro ao parsear log: {e}")
    # Retorna do mais recente para o mais antigo
    return entries[::-1]


def parse_git_config_file(file_path: str) -> Optional[str]:
    """Extrai URL do remote origin do config."""
    if not os.path.exists(file_path): return None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            # Regex simples para pegar url = ...
            m = re.search(r'url\s*=\s*(.*)', content)
            if m:
                return m.group(1).strip()
    except:
        pass
    return None


def gather_intelligence(base_git_url: str, outdir: str) -> Dict[str, Any]:
    """Baixa arquivos estruturais (config, logs, refs) para enriquecer o relatório."""
    info("Coletando inteligência (Config, Logs, Refs)...")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"): base += "/.git"

    meta_dir = os.path.join(outdir, "_files", "metadata")
    os.makedirs(meta_dir, exist_ok=True)

    intel = {
        "remote_url": None,
        "logs": [],
        "packed_refs": []
    }

    # 1. Config
    ok, data = http_get_bytes(base + "/config")
    if ok:
        cfg_path = os.path.join(meta_dir, "config")
        with open(cfg_path, "wb") as f:
            f.write(data)
        intel["remote_url"] = parse_git_config_file(cfg_path)
        if intel["remote_url"]: success(f"Remote Origin detectado: {intel['remote_url']}")

    # 2. Logs/HEAD
    ok, data = http_get_bytes(base + "/logs/HEAD")
    if ok:
        log_path = os.path.join(meta_dir, "logs_HEAD")
        with open(log_path, "wb") as f: f.write(data)
        intel["logs"] = parse_git_log_file(log_path)
        success(f"Logs de histórico recuperados: {len(intel['logs'])} entradas.")

    # 3. Packed-refs
    ok, data = http_get_bytes(base + "/packed-refs")
    if ok:
        pr_path = os.path.join(meta_dir, "packed-refs")
        with open(pr_path, "wb") as f:
            f.write(data)
        # Parse simples
        refs = []
        for line in data.decode(errors='ignore').splitlines():
            if not line.startswith("#") and " " in line:
                sha, ref = line.split(" ", 1)
                refs.append({"sha": sha, "ref": ref})
        intel["packed_refs"] = refs

    # Salvar intel para uso posterior
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

    # 1. HEAD
    info("  -> 1. Tentando HEAD...")
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
    # 2. packed-refs
    info("  -> 2. Tentando packed-refs...")
    ok, data = http_get_bytes(base + "/packed-refs")
    if ok:
        txt = data.decode(errors="ignore")
        for line in txt.splitlines():
            if line.startswith("#") or not line.strip(): continue
            parts = line.split(" ", 1)
            if len(parts) == 2:
                sha, ref = parts[0].strip(), parts[1].strip()
                if len(sha) == 40 and sha not in candidates:
                    candidates[sha] = {"sha": sha, "ref": ref, "source": base + "/packed-refs"}

    # 3. Common refs
    common_refs = ["refs/heads/master", "refs/heads/main", "refs/heads/develop", "refs/heads/staging",
                   "refs/remotes/origin/master"]
    for ref in common_refs:
        ok, data = http_get_bytes(base + "/" + ref)
        if ok:
            sha = data.decode(errors="ignore").strip().splitlines()[0].strip()
            if len(sha) == 40 and sha not in candidates:
                candidates[sha] = {"sha": sha, "ref": ref, "source": base + "/" + ref}

    return list(candidates.values())


def blind_recovery(base_git_url: str, outdir: str, output_index_name: str) -> bool:
    """Executa o modo BLIND: Acha HEAD -> Acha Tree -> Crawl recursivo -> Gera Index falso."""
    info("Iniciando MODO BLIND (Reconstrução sem index)...")

    # 1. Metadados
    gather_intelligence(base_git_url, outdir)

    # 2. Achar Commit Inicial
    candidates = find_candidate_shas(base_git_url)
    if not candidates:
        fail("Modo Blind falhou: Não foi possível encontrar nenhum Commit SHA inicial.")
        return False

    # Usa o primeiro candidato (geralmente HEAD)
    start_sha = candidates[0]['sha']
    info(f"Ponto de partida encontrado: {start_sha} ({candidates[0]['ref']})")

    # 3. Baixar Commit para pegar a Tree
    ok, raw = fetch_object_raw(base_git_url, start_sha)
    if not ok:
        fail(f"Não foi possível baixar o commit inicial {start_sha}")
        return False

    ok2, parsed = parse_git_object(raw)
    if not ok2 or parsed[0] != "commit":
        fail("Objeto inicial não é um commit válido.")
        return False

    commit_meta = parse_commit_content(parsed[1])
    root_tree_sha = commit_meta.get("tree")

    if not root_tree_sha:
        fail("Commit não tem tree associada.")
        return False

    info(f"Root Tree encontrada: {root_tree_sha}. Iniciando crawler recursivo...")

    # 4. Crawl Recursivo
    all_files = collect_files_from_tree(base_git_url, root_tree_sha, ignore_missing=True)

    # 5. Gerar JSON de Index Sintético
    synthetic_json = {"entries": []}
    for f in all_files:
        synthetic_json["entries"].append({
            "path": f["path"],
            "sha1": f["sha"]
        })

    out_path = os.path.join(outdir, "_files", output_index_name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(synthetic_json, f, indent=2)

    success(f"Modo Blind concluído! Index sintético gerado com {len(all_files)} arquivos.")
    return True


# ---------------------------
# History HTML & Reports (UI)
# ---------------------------
def generate_history_html(in_json: str, out_html: str, site_base: str, base_git_url: str):
    """Gera um HTML navegável a partir do history.json."""
    with open(in_json, 'r', encoding='utf-8') as f:
        data = json.load(f)

    commits = data.get('commits', [])
    commits_json = json.dumps(commits, ensure_ascii=False)
    head_sha = data.get('head', 'N/A')

    # Tenta carregar inteligência para enriquecer a UI
    intel_path = os.path.join(os.path.dirname(in_json), "intelligence.json")
    remote_url = ""
    if os.path.exists(intel_path):
        with open(intel_path, 'r', encoding='utf-8') as f:
            intel = json.load(f)
            remote_url = intel.get("remote_url", "")

    html_content = f"""
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Git History Explorer - {site_base}</title>
    <style>
        body{{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}}
        .wrap{{max-width:1200px;margin:0 auto;}}
        h1{{color:#6be;}}
        .commit-card{{border:1px solid #333;margin-bottom:15px;padding:15px;border-radius:6px;background:#161819;}}
        .sha{{font-weight:bold;color:#6be;font-family:monospace;}}
        .message{{margin-top:5px;white-space:pre-wrap;font-size:14px;}}
        .meta{{font-size:12px;color:#779;}}
        .files{{margin-top:10px;border-top:1px solid #333;padding-top:10px;}}
        .file-item{{display:block;margin-bottom:3px;}}
        .error{{color:#ff5252;}}
        .ok{{color:#6f6;font-weight:bold;}}
        a{{color:#6be;text-decoration:none;}} a:hover{{text-decoration:underline;}}
        .source-tag {{ font-size: 10px; padding: 2px 5px; border-radius: 4px; margin-left: 10px; }}
        .source-log {{ background: #2a3; color: #fff; }}
        .source-walk {{ background: #444; color: #ddd; }}
        #commits-container > div:nth-child(1) .commit-card {{ border-color: #6be; box-shadow: 0 0 5px rgba(102,187,238,0.3); }}
        .filter-header {{ display: flex; align-items: center; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }}
        input[type=text] {{ padding: 8px; width: 100%; max-width:420px; border-radius: 6px; border: 1px solid #333; background: #071117; color: #dff; }}
        details {{ margin-top: 10px; cursor: pointer; }}
        summary {{ font-weight: bold; }}
        .remote-info {{ margin-bottom: 20px; padding: 10px; background: #1a1c1d; border-radius: 6px; border-left: 4px solid #6be; }}
    </style>
</head>
<body>
<div class='wrap'>
    <h1>Reconstrução de Histórico para {site_base}</h1>

    <div class="remote-info">
        <p class="meta">Referência HEAD: <span class='sha'>{head_sha}</span></p>
        <p class="meta">Origem Remota: <b>{remote_url or "Não detectado"}</b></p>
        <p class="meta">Total de Commits Encontrados: <b>{len(commits)}</b></p>
    </div>

    <div class="filter-header">
        <input id='q' type='text' placeholder='Filtrar por SHA, autor ou mensagem...'>
        <span id="result-count" class="meta"></span>
    </div>

    <div id='commits-container'></div>
    <p class="meta" style="text-align:center; margin-top:20px;">Gerado por Git Leak Explorer</p>
</div>

<script>
    const COMMITS = {commits_json};
    const container = document.getElementById('commits-container');
    const qInput = document.getElementById('q');
    const resultCount = document.getElementById('result-count');
    const baseGitUrl = "{base_git_url}";
    const remoteUrl = "{remote_url}";

    function getCommitLink(sha) {{
        if (!remoteUrl) return sha;
        // Tenta adivinhar formato GitHub/GitLab
        let cleanUrl = remoteUrl.replace('.git', '');
        return `<a href="${{cleanUrl}}/commit/${{sha}}" target="_blank">${{sha}}</a>`;
    }}

    function renderCommits(list) {{
        container.innerHTML = '';
        resultCount.textContent = `Exibindo ${{list.length}} commits.`;

        list.forEach(c => {{
            const cardWrapper = document.createElement('div');
            const card = document.createElement('div');
            card.className = 'commit-card';

            let parentsHtml = c.parents.map(p => `<a href='#${{p}}'>${{p.substring(0, 10)}}</a>`).join(', ');
            let contentHtml = '';
            let statusBadge = ''; 
            const statusClass = c.ok ? 'ok' : 'error'; 

            // Link externo se disponível
            const shaDisplay = getCommitLink(c.sha);

            // Tag de origem (Log vs Walk)
            const sourceTag = c.source === 'log' 
                ? '<span class="source-tag source-log">VIA LOGS</span>' 
                : '<span class="source-tag source-walk">VIA GRAFO</span>';

            if (!c.ok) {{
                let errorStatus = 'Indisponível';
                statusBadge = 'ERRO';
                if (c.error && c.error.includes('HTTP 404')) {{
                    errorStatus = 'Commit não encontrado (404)';
                }} else if (c.error) {{
                    errorStatus = c.error;
                }}

                contentHtml = `
                    <p class='error'>[FALHA] Status: ${{errorStatus}}</p>
                    <details>
                        <summary>Detalhes do Erro</summary>
                        <p class='meta'>SHA: ${{c.sha}}</p>
                        <p class='meta'>Mensagem de Erro: ${{c.error}}</p>
                    </details>
                `;
            }} else {{
                statusBadge = 'OK';
                let filesHtml = '';

                if (c.file_collection_error) {{
                    filesHtml = `<span class="error">FALHA NA COLETA DE ARQUIVOS. ${{c.file_collection_error}}</span>`;
                }}
                else if (c.files && c.files.length > 0) {{
                    filesHtml = c.files.map(f => {{
                        return `<span class='file-item'>${{f.path}} (SHA: <span class='sha' style='font-size:0.9em'>${{f.sha.substring(0, 8)}}</span> - <a href="${{f.blob_url}}" target="_blank">blob</a>)</span>`;
                    }}).join('');
                }} else {{
                    filesHtml = '<span class="meta">Nenhum arquivo indexado neste tree. (Commit vazio?)</span>';
                }}

                contentHtml = `
                    <p><span class='ok'>[OK]</span> Mensagem do Commit:</p>
                    <div class='message'>${{c.message}}</div>
                    <p class='meta'>Data: ${{c.date || 'Desconhecida'}}</p>
                    <details>
                        <summary>Arquivos do Snapshot (${{c.file_count}})</summary>
                        <div class='files'>${{filesHtml}}</div>
                    </details>
                `;
            }}

            const header = `<div><b>${{list.indexOf(c) + 1}}.</b> ${{shaDisplay}} <span class='${{statusClass}}'>${{statusBadge}}</span> ${{sourceTag}}</div>`;
            const meta = `<div class='meta'>Autor: ${{c.author || 'N/A'}} — Pais: ${{parentsHtml || 'Nenhum'}} — Arquivos: ${{c.file_count||0}}</div>`;

            card.id = c.sha;
            card.innerHTML = header + meta + contentHtml; 

            cardWrapper.appendChild(card);
            container.appendChild(cardWrapper);
        }});
    }}

    function filterCommits() {{
        const query = qInput.value.toLowerCase().trim();
        let filtered = COMMITS;

        if (query) {{
            filtered = COMMITS.filter(c => 
                (c.sha || '').toLowerCase().includes(query) ||
                (c.author || '').toLowerCase().includes(query) ||
                (c.message || '').toLowerCase().includes(query)
            );
        }}

        renderCommits(filtered);
    }}

    qInput.addEventListener('input', filterCommits);
    renderCommits(COMMITS);
</script>
</body>
</html>
    """
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_content)


def reconstruct_history(input_json: str, base_git_url: str, outdir: str, max_commits: int = 200,
                        ignore_missing: bool = True, strict: bool = False):
    info(
        f"Reconstruindo histórico com inteligência aumentada. max_commits={max_commits}")
    os.makedirs(outdir, exist_ok=True)
    site_base = normalize_site_base(base_git_url)

    # 1. Carregar Intel (Logs já processados)
    intel_path = os.path.join(outdir, "_files", "intelligence.json")
    intel_logs = []
    if os.path.exists(intel_path):
        try:
            with open(intel_path, 'r', encoding='utf-8') as f:
                intel_data = json.load(f)
                intel_logs = intel_data.get("logs", [])
                info(f"Carregados {len(intel_logs)} commits a partir de logs/HEAD.")
        except:
            pass

    # 2. Inicializar lista de commits
    # Se temos logs, eles são a fonte da verdade cronológica.
    # Se não temos, fazemos o "Walk" tradicional.

    all_commits_out = []
    processed_shas = set()

    # Adicionar commits do Log primeiro (são ricos em metadados)
    for log_entry in intel_logs:
        sha = log_entry.get("sha")
        if sha in processed_shas: continue

        # Tentar baixar detalhes do arquivo para este commit (Tree Walking)
        # para popular files e file_count, mesmo que já tenhamos a msg do log.

        commit_data = {
            "sha": sha,
            "ok": True,
            "author": log_entry.get("author"),
            "date": log_entry.get("date"),
            "message": log_entry.get("message"),
            "source": "log",
            "parents": [log_entry.get("old_sha")] if log_entry.get(
                "old_sha") != "0000000000000000000000000000000000000000" else [],
            "files": [],
            "file_count": 0
        }

        # Opcional: Baixar Tree para listar arquivos (Enriquece o Log)
        # Se max_commits permitir, fazemos o fetch real
        if len(all_commits_out) < max_commits:
            ok, raw = fetch_object_raw(base_git_url, sha)
            if ok:
                ok2, parsed = parse_git_object(raw)
                if ok2 and parsed[0] == "commit":
                    meta = parse_commit_content(parsed[1])
                    # Atualiza dados com o que está no objeto real (pode ser mais preciso)
                    commit_data["tree"] = meta.get("tree")
                    if meta.get("tree"):
                        try:
                            files = collect_files_from_tree(base_git_url, meta.get("tree"), ignore_missing=True)
                            commit_data["files"] = files
                            commit_data["file_count"] = len(files)
                        except:
                            pass
            else:
                commit_data["ok"] = False  # Log diz que existe, mas blob não baixou
                commit_data["error"] = "Objeto não encontrado no servidor (visto em logs)"

        all_commits_out.append(commit_data)
        processed_shas.add(sha)

    # 3. Se não atingimos max_commits ou não tínhamos logs, fazemos Graph Walk tradicional
    if len(all_commits_out) < max_commits:
        candidate_shas = find_candidate_shas(base_git_url)
        queue = []
        visited_walk = set(processed_shas)  # Não re-visitar o que veio do log

        for candidate in candidate_shas:
            sha = candidate['sha']
            if sha not in visited_walk:
                queue.append(sha)
                visited_walk.add(sha)

        while queue and len(all_commits_out) < max_commits:
            cur = queue.pop(0)

            # Fetch normal
            ok, raw = fetch_object_raw(base_git_url, cur)
            if not ok: continue  # Pula erros no walk

            ok2, parsed = parse_git_object(raw)
            if not ok2 or parsed[0] != "commit": continue

            meta = parse_commit_content(parsed[1])

            files = []
            try:
                if meta.get("tree"):
                    files = collect_files_from_tree(base_git_url, meta.get("tree"), ignore_missing=ignore_missing)
            except:
                pass

            commit_entry = {
                "sha": cur,
                "ok": True,
                "tree": meta.get("tree"),
                "parents": meta.get("parents", []),
                "author": meta.get("author"),
                "committer": meta.get("committer"),
                "message": meta.get("message"),
                "file_count": len(files),
                "files": files,
                "source": "graph",
                "fetched_at": datetime.utcnow().isoformat() + "Z"
            }
            all_commits_out.append(commit_entry)
            processed_shas.add(cur)

            for p_sha in (meta.get("parents") or []):
                if p_sha not in visited_walk:
                    queue.append(p_sha)
                    visited_walk.add(p_sha)

    # Output
    head_sha_reference = "N/A"  # Difícil definir um único HEAD se mesclamos logs

    history_json_path = os.path.join(outdir, "_files", "history.json")
    os.makedirs(os.path.dirname(history_json_path), exist_ok=True)

    try:
        with open(history_json_path, "w", encoding="utf-8") as f:
            json.dump(
                {"base": base_git_url, "site_base": site_base, "head": head_sha_reference, "commits": all_commits_out},
                f,
                indent=2, ensure_ascii=False)
        success(f"history.json gravado: {history_json_path} ({len(all_commits_out)} commits)")
    except Exception as e:
        fail(f"Falha ao gravar history.json: {e}")
        return

    history_html_path = os.path.join(outdir, "history.html")
    try:
        generate_history_html(history_json_path, history_html_path, site_base, base_git_url)
        success(f"history.html gravado: {history_html_path}")
    except Exception as e:
        fail(f"Falha ao gerar history.html: {e}")


# ---------------------------
# Detect hardening/exposure + generate HTML report
# ---------------------------
def detect_hardening(base_git_url: str, outdir: str) -> Dict[str, Any]:
    info("Detectando exposição de .git e configuração de hardening...")
    base = base_git_url.rstrip("/")
    candidates = {
        "HEAD": [base + "/HEAD", base + "/.git/HEAD"],
        "refs_heads": [base + "/refs/heads/", base + "/.git/refs/heads/"],
        "packed_refs": [base + "/packed-refs", base + "/.git/packed-refs"],
        "index": [base + "/index", base + "/.git/index"],
        "objects_root": [base + "/objects/", base + "/.git/objects/"],
        "logs": [base + "/logs/HEAD", base + "/.git/logs/HEAD"],
        "config": [base + "/config", base + "/.git/config"]
    }
    report = {"base": base_git_url, "checked_at": datetime.utcnow().isoformat() + "Z", "results": {}}
    for name, urls in candidates.items():
        status = {"exposed": False, "positive_urls": []}
        for u in urls:
            try:
                r = requests.head(u, timeout=6, allow_redirects=True)
                code = getattr(r, "status_code", None)
                if code and code < 400:
                    status["exposed"] = True
                    status["positive_urls"].append({"url": u, "status_code": code, "method": "HEAD"})
                else:
                    # try GET fallback for some servers that don't respond to HEAD
                    ok, data = http_get_bytes(u)
                    if ok:
                        status["exposed"] = True
                        status["positive_urls"].append({"url": u, "status_code": 200, "method": "GET"})
            except Exception:
                try:
                    ok, data = http_get_bytes(u)
                    if ok:
                        status["exposed"] = True
                        status["positive_urls"].append({"url": u, "status_code": 200, "method": "GET"})
                except Exception:
                    pass
        report["results"][name] = status

    # Save JSON
    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    outjson = os.path.join(outdir, "_files", "hardening_report.json")
    with open(outjson, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    success(f"Relatório salvo em: {outjson}")

    # Generate HTML
    out_html = os.path.join(outdir, "hardening_report.html")
    generate_hardening_html(report, out_html)
    success(f"hardening_report.html gravado em: {out_html}")
    return report


def generate_hardening_html(report: Dict[str, Any], out_html: str):
    # Build rows for template: category, description, status (BAD/WARNING/OK), evidence
    rows = []
    descr_map = {
        "HEAD": ".git/HEAD acessível",
        "refs_heads": ".git/refs/heads/ acessível",
        "packed_refs": ".git/packed-refs acessível",
        "index": ".git/index acessível",
        "objects_root": ".git/objects/ acessível (objetos expostos)",
        "logs": ".git/logs/ acessível",
        "config": ".git/config acessível"
    }
    for k, v in report.get("results", {}).items():
        exposed = v.get("exposed", False)
        evidence = "; ".join([f"{p.get('method', '?')} {p.get('url')} ({p.get('status_code', '?')})" for p in
                              v.get("positive_urls", [])]) or "-"
        status = "OK"
        if exposed:
            # critical if index or objects_root or config exposed
            if k in ("index", "objects_root", "config"):
                status = "CRÍTICO"
            else:
                status = "ATENÇÃO"
        rows.append({"category": k, "description": descr_map.get(k, k), "status": status, "evidence": evidence})
    # build HTML injecting rows JSON
    data_json = json.dumps(rows, ensure_ascii=False)
    html = (
            "<!DOCTYPE html>\n<html lang='pt-BR'>\n<head>\n<meta charset='utf-8'>\n<title>Hardening Report</title>\n"
            "<style>"
            "body{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;padding:20px}"
            ".wrap{max-width:1200px;margin:0 auto;}"
            "h1{color:#6be;}"
            "input{padding:8px;width:360px;border-radius:6px;border:1px solid #333;background:#071117;color:#dff;margin-bottom:12px;}"
            "table{width:100%;border-collapse:collapse;margin-top:10px}"
            "th,td{padding:10px;text-align:left;border-bottom:1px solid #222;}"
            "th{color:#6be;font-weight:bold;border-bottom:1px solid #444;}"
            ".ok{color:#6f6;font-weight:bold;}"
            ".warning{color:#ff9800;font-weight:bold;}"
            ".bad{color:#ff5252;font-weight:bold;}"
            ".meta{font-size:13px;color:#779;margin-top:20px;}"
            "#summary{margin-bottom:15px;padding:10px;border:1px solid #333;border-radius:6px;background:#161819;}"
            "</style>\n"
            "</head>\n<body>\n"
            "<div class='wrap'>\n"
            "<h1>🛡 Hardening Report</h1>\n"
            "<div id='summary'></div>\n"
            "<input id='search' placeholder='Filtrar resultados...'>\n"
            "<table id='tbl'><thead><tr><th>Categoria</th><th>Descrição</th><th>Status</th><th>Evidência</th></tr></thead><tbody id='tbody'></tbody></table>\n"
            "<p class=\"meta\">Gerado por Git Leak Explorer</p>\n"
            "</div>\n"
            "<script>\nconst ROWS = " + data_json + ";\nconst tbody=document.getElementById('tbody'); const search=document.getElementById('search');\nfunction render(){ tbody.innerHTML=''; let score=0; for(const r of ROWS){ let cls=''; if(r.status==='OK') cls='ok'; else if(r.status==='ATENÇÃO') cls='warning'; else if(r.status==='CRÍTICO') cls='bad'; if(r.status==='CRÍTICO') score+=5; if(r.status==='ATENÇÃO') score+=2; tbody.innerHTML += `<tr><td>${r.category}</td><td>${r.description}</td><td class='${cls}'>${r.status}</td><td>${r.evidence}</td></tr>`;} let risk='🔍 Indeterminado'; let riskColor=''; if(score===0){ risk='🟢 Seguro'; riskColor='#6f6';} else if(score<10){ risk='🟡 Moderado'; riskColor='#ff9800';} else{ risk='🔴 Crítico'; riskColor='#ff5252';} document.getElementById('summary').innerHTML = `<span style='font-size:16px; font-weight:bold;'>Status Geral: <span style='color:${riskColor}'>${risk}</span></span> — Pontuação: ${score} — Verificações: ${ROWS.length}`; }\nsearch.addEventListener('input', ()=>{ const q=search.value.toLowerCase(); const filtered = ROWS.filter(r=> JSON.stringify(r).toLowerCase().includes(q)); tbody.innerHTML=''; for(const r of filtered){ let cls=''; if(r.status==='OK') cls='ok'; else if(r.status==='ATENÇÃO') cls='warning'; else if(r.status==='CRÍTICO') cls='bad'; tbody.innerHTML += `<tr><td>${r.category}</td><td>${r.description}</td><td class='${cls}'>${r.status}</td><td>${r.evidence}</td></tr>`;} });\nrender();\n</script>\n</body>\n</html>\n"
    )
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


# ---------------------------
# Packfile Handling
# ---------------------------
def handle_packfiles(mode: str, base_git_url: str, outdir: str):
    info(f"Iniciando manuseio de Packfiles em modo: {mode}")
    base = base_git_url.rstrip("/")
    if not base.endswith("/.git"):
        base += "/.git"

    # 1. Identificar Packfiles via objects/info/packs
    info_packs_url = base + "/objects/info/packs"
    info(f"Buscando lista de packs em: {info_packs_url}")

    ok, data = http_get_bytes(info_packs_url)
    found_packs = []

    if ok:
        try:
            content = data.decode(errors='ignore')
            for line in content.splitlines():
                line = line.strip()
                if not line: continue
                # Formato comum: "P pack-sha1.pack"
                parts = line.split()
                for p in parts:
                    if p.endswith(".pack"):
                        pack_name = p
                        # Às vezes vem caminho relativo? Geralmente é só o nome.
                        found_packs.append(pack_name)
        except Exception as e:
            warn(f"Erro ao parsear info/packs: {e}")
    else:
        warn(f"Não foi possível acessar objects/info/packs ({data}). Tentando heurística de logs/packed-refs...")

    found_packs = list(set(found_packs))
    info(f"Packfiles encontrados: {len(found_packs)}")

    results = []

    # Preparar diretório para download/unpack se necessário
    pack_dir = os.path.join(outdir, ".git", "objects", "pack")

    if mode in ["download", "download-unpack"]:
        ensure_git_repo_dir(outdir)  # Garante que .git existe
        os.makedirs(pack_dir, exist_ok=True)

    for pname in found_packs:
        # Pname é 'pack-XYZ.pack'
        # URLs
        url_pack = f"{base}/objects/pack/{pname}"
        url_idx = url_pack.replace(".pack", ".idx")

        status = "Listado"
        local_pack_path = os.path.join(pack_dir, pname)
        local_idx_path = local_pack_path.replace(".pack", ".idx")

        # Download
        if mode in ["download", "download-unpack"]:
            info(f"Baixando {pname}...")
            ok_p, _ = http_get_to_file(url_pack, local_pack_path)
            ok_i, _ = http_get_to_file(url_idx, local_idx_path)

            if ok_p:
                status = "Baixado"
                if ok_i:
                    success(f"Pack e Index baixados: {pname}")
                else:
                    warn(f"Pack baixado, mas Index falhou: {pname}")

                # Unpack
                if mode == "download-unpack":
                    info(f"Tentando descompactar {pname} (git unpack-objects)...")
                    # git unpack-objects lê do stdin
                    try:
                        with open(local_pack_path, "rb") as f_in:
                            # Executar dentro do repo para que os objetos vão para .git/objects
                            proc = subprocess.run(["git", "unpack-objects"], cwd=outdir, stdin=f_in,
                                                  capture_output=True)
                            if proc.returncode == 0:
                                success(f"Descompactado com sucesso: {pname}")
                                status = "Extraído (Unpacked)"
                            else:
                                fail(f"Falha ao descompactar {pname}: {proc.stderr.decode()}")
                                status = "Falha na Extração"
                    except Exception as e:
                        fail(f"Erro executando git unpack-objects: {e}")
                        status = "Erro (Execução)"
            else:
                fail(f"Falha ao baixar pack: {pname}")
                status = "Falha Download"

        results.append({
            "name": pname,
            "url_pack": url_pack,
            "status": status
        })

    # Salvar JSON de resultado
    os.makedirs(os.path.join(outdir, "_files"), exist_ok=True)
    out_json = os.path.join(outdir, "_files", "packfiles.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


# ---------------------------
# Serve directory
# ---------------------------
def serve_dir(path: str):
    if not path:
        fail("Argumento --serve requer o diretório de saída (ex: repo/).")
        return
    p = os.path.abspath(path)
    if not os.path.isdir(p):
        fail(f"Diretório '{p}' não existe.")
        return
    info(f"Servindo '{p}' em http://127.0.0.1:8000")
    os.chdir(p)
    HTTPServer(("0.0.0.0", 8000), SimpleHTTPRequestHandler).serve_forever()


# ---------------------------
# Scanner for list of URLs
# ---------------------------
def scan_urls(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    except Exception as e:
        fail(f"Erro ao ler arquivo de scan: {e}")
        return
    info(f"Escaneando {len(urls)} alvos...")
    for u in urls:
        test = u.rstrip("/") + "/.git/HEAD"
        try:
            ok, data = http_get_bytes(test)
            if ok and b"ref:" in data.lower():
                print(f"[⚠] Vulnerável: {u}")
            else:
                print(f"[OK] Seguro: {u}")
        except Exception as e:
            print(f"[X] Falha: {u} ({e})")


# ---------------------------
# Listing
# ---------------------------
def make_listing_modern(json_file: str, base_git_url: str, outdir: str):
    info(f"Gerando listagem simplificada para {json_file}")

    entries = []
    try:
        entries = load_dump_entries(json_file)
    except Exception as e:
        warn(f"Não foi possível carregar index para listing ({e}). Gerando HTML vazio.")
        # Não retorna, permite gerar o HTML vazio para não quebrar links

    site_base = normalize_site_base(base_git_url)
    rows: List[Dict[str, Any]] = []

    for e in entries:
        path = e.get("path", "")
        sha = e.get("sha1", "")
        if not sha:
            continue

        rows.append({
            "path": path,
            "remote_url": join_remote_file(site_base, path),
            "blob_url": make_blob_url_from_git(base_git_url, sha),
            "sha": sha,
            "local_exists": os.path.exists(os.path.join(outdir, path.lstrip("/"))),
            "local_url": f"file://{os.path.abspath(os.path.join(outdir, path.lstrip('/')))}"
        })

    # outpath DEVE estar na raiz do diretório de saída
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "listing.html")
    data_json = json.dumps(rows, ensure_ascii=False)

    html = (
            "<!doctype html>\n"
            "<html lang=\"pt-BR\">\n"
            "<head>\n"
            "  <meta charset=\"utf-8\">\n"
            "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
            "  <title>Git Leak Explorer - Arquivos</title>\n"
            "  <style>\n"
            "    body{font-family:Inter,Segoe UI,Roboto,monospace;background:#0f1111;color:#dff;}\n"
            "    .wrap{max-width:1200px;margin:20px auto;padding:12px}\n"
            "    header{display:flex;gap:10px;align-items:center}\n"
            "    input[type=text]{padding:8px;width:420px;border-radius:6px;border:1px solid #333;background:#071117;color:#dff}\n"
            "    table{width:100%;border-collapse:collapse;margin-top:12px}\n"
            "    th,td{padding:8px;border-bottom:1px solid #222;text-align:left;font-size:13px}\n"
            "    th.sortable{cursor:pointer}\n"
            "    a{color:#6be}\n"
            "    .muted{color:#779}\n"
            "    .pager{margin-top:12px;display:flex;gap:8px;align-items:center}\n"
            "    .btn{padding:6px 10px;border-radius:6px;background:#213;color:#dff;border:none;cursor:pointer}\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "<div class='wrap'>\n"
            "  <h1>Git Leak Explorer</h1>\n"
            f"  <p class='muted'>Total de arquivos: <b>{len(rows)}</b></p>\n"
            "  <header>\n"
            "    <input id='q' type='text' placeholder='Buscar por path ou SHA (ex: assets/, config.ini, eee5c9...)'>\n"
            "    <label> Itens por pág:\n"
            "      <select id='pageSize'>\n"
            "        <option>25</option><option>50</option><option selected>100</option><option>250</option><option>500</option>\n"
            "      </select>\n"
            "    </label>\n"
            "    <button id='reset' class='btn'>Limpar</button>\n"
            "  </header>\n"
            "  <table id='tbl'>\n"
            "    <thead>\n"
            "      <tr>\n"
            "        <th class='sortable' data-sort='path'>Arquivo</th>\n"
            "        <th>Local</th>\n"
            "        <th>Remoto</th>\n"
            "        <th class='sortable' data-sort='sha'>Blob (SHA)</th>\n"
            "      </tr>\n"
            "    </thead>\n"
            "    <tbody id='tbody'></tbody>\n"
            "  </table>\n"
            "  <div class='pager'>\n"
            "    <button id='prev' class='btn'>« Anterior</button>\n"
            "    <span class='muted'>Página <span id='cur'>1</span> / <span id='total'>1</span></span>\n"
            "    <button id='next' class='btn'>Próximo »</button>\n"
            "    <span style='flex:1'></span>\n"
            "    <span class='muted'>Resultados: <span id='count'>0</span></span>\n"
            "  </div>\n"
            "  <p class='muted' style='text-align:center; margin-top:30px; font-size:12px;'>Gerado por Git Leak Explorer</p>\n"
            "</div>\n"
            "<script>\n"
            "const DATA = " + data_json + ";\n"
                                          "let filtered = DATA.slice();\n"
                                          "let sortKey = null, sortDir = 1, pageSize = 100, curPage = 1;\n"
                                          "const tbody = document.getElementById('tbody');\n"
                                          "const q = document.getElementById('q');\n"
                                          "const pageSizeSel = document.getElementById('pageSize');\n"
                                          "const curSpan = document.getElementById('cur');\n"
                                          "const totalSpan = document.getElementById('total');\n"
                                          "const countSpan = document.getElementById('count');\n"
                                          "\n"
                                          "function render(){\n"
                                          "  pageSize = parseInt(pageSizeSel.value,10);\n"
                                          "  const total = filtered.length;\n"
                                          "  const pages = Math.max(1, Math.ceil(total/pageSize));\n"
                                          "  if(curPage>pages) curPage = pages;\n"
                                          "  const start = (curPage-1)*pageSize; const slice = filtered.slice(start, start+pageSize);\n"
                                          "  tbody.innerHTML = '';\n"
                                          "  for(const r of slice){\n"
                                          "    const tr = document.createElement('tr');\n"
                                          "    tr.innerHTML = `\n"
                                          "      <td>${r.path}</td>\n"
                                          "      <td>${ r.local_exists ? `<a href=\"${r.local_url}\" target=\"_blank\">Abrir (local)</a>` : '<span class=\"muted\">Não restaurado</span>' }</td>\n"
                                          "      <td><a href=\"${r.remote_url}\" target=\"_blank\">Abrir (remoto)</a></td>\n"
                                          "      <td>${ r.sha ? `<a href=\"${r.blob_url}\" target=\"_blank\">${r.sha}</a>` : '<span class=\"muted\">sem SHA</span>' }</td>\n"
                                          "    `;\n"
                                          "    tbody.appendChild(tr);\n"
                                          "  }\n"
                                          "  curSpan.textContent = curPage; totalSpan.textContent = pages; countSpan.textContent = total;\n"
                                          "}\n"
                                          "\n"
                                          "function applyFilter(){\n"
                                          "  const qv = q.value.trim().toLowerCase();\n"
                                          "  if(!qv){ filtered = DATA.slice(); }\n"
                                          "  else{ filtered = DATA.filter(r => (r.path||'').toLowerCase().includes(qv) || (r.sha||'').toLowerCase().includes(qv)); }\n"
                                          "  if(sortKey){ filtered.sort((a,b)=>{ const A=(a[sortKey]||'').toLowerCase(); const B=(b[sortKey]||'').toLowerCase(); if(A<B) return -1*sortDir; if(A>B) return 1*sortDir; return 0; }); }\n"
                                          "  curPage = 1; render();\n"
                                          "}\n"
                                          "\n"
                                          "q.addEventListener('input', ()=> applyFilter());\n"
                                          "pageSizeSel.addEventListener('change', ()=> { curPage=1; render(); });\n"
                                          "document.getElementById('reset').addEventListener('click', ()=>{ q.value=''; pageSizeSel.value='100'; sortKey=null; sortDir=1; filtered = DATA.slice(); curPage=1; render(); });\n"
                                          "document.getElementById('prev').addEventListener('click', ()=>{ if(curPage > 1){ curPage--; render(); } });\n"
                                          "document.getElementById('next').addEventListener('click', ()=>{ const pages = Math.ceil(filtered.length/pageSize); if(curPage < pages){ curPage++; render(); } });\n"
                                          "document.querySelectorAll('th.sortable').forEach(th=>{ th.addEventListener('click', ()=>{ const k = th.getAttribute('data-sort'); if(sortKey===k){ sortDir = -sortDir; } else{ sortKey = k; sortDir = 1; } applyFilter(); }); });\n"
                                          "\n"
                                          "filtered = DATA.slice(); render();\n"
                                          "</script>\n"
                                          "</body>\n"
                                          "</html>\n"
    )

    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)

    ok(f"Listing simplificado salvo: {outpath} ({len(rows)} entradas)")


# ---------------------------
# Report
# ---------------------------
def generate_unified_report(outdir: str, base_url: str):
    info("Gerando Relatório Técnico Unificado (report.html)...")

    files_dir = os.path.join(outdir, "_files")

    # Paths dos JSONs
    hardening_path = os.path.join(files_dir, "hardening_report.json")
    index_path = os.path.join(files_dir, "dump.json")
    history_path = os.path.join(files_dir, "history.json")
    packfiles_path = os.path.join(files_dir, "packfiles.json")
    intel_path = os.path.join(files_dir, "intelligence.json")

    # Carregar Inteligência se existir
    remote_url = ""
    if os.path.exists(intel_path):
        try:
            with open(intel_path, 'r', encoding='utf-8') as f:
                intel_data = json.load(f)
                remote_url = intel_data.get("remote_url", "")
        except:
            pass

    # 1. Carregar Hardening Report
    hardening_html = ""
    try:
        with open(hardening_path, 'r', encoding='utf-8') as f:
            hardening_data = json.load(f).get('results', {})

        hardening_html = "<h3>1. Verificação de Hardening (.git Exposure)</h3>"
        hardening_html += "<table style='width: 100%;'><thead><tr><th>Componente</th><th>Status</th><th>Evidência</th></tr></thead><tbody>"

        score = 0
        for name, data in hardening_data.items():
            exposed = data.get('exposed', False)
            status_text = "EXPOSTO" if exposed else "OK"
            status_class = "error" if exposed else "ok"
            evidence = "; ".join([p.get('url', '?') for p in data.get('positive_urls', [])]) or "N/A"
            if exposed:
                score += 5  # Simplificação da pontuação

            hardening_html += f"<tr><td>{name}</td><td class='{status_class}'>{status_text}</td><td>{evidence}</td></tr>"

        hardening_html += f"</tbody></table><p>Risco de Exposição Geral: {'Crítico' if score >= 15 else ('Moderado' if score > 0 else 'Seguro')}</p>"

    except FileNotFoundError:
        hardening_html = "<p class='error'>1. Relatório de Hardening não encontrado. Execute --detect-hardening ou --default.</p>"

    # 2. Carregar Listing de Arquivos
    listing_html = ""
    try:
        entries = load_dump_entries(index_path)

        listing_html = "<h3>2. Arquivos Encontrados (.git Index Dump)</h3>"
        listing_html += f"<p>Total de Arquivos Listados: {len(entries)}</p>"
        listing_html += "<table style='width: 100%;'><thead><tr><th>Caminho</th><th>SHA (Blob)</th><th>Link Remoto</th></tr></thead><tbody>"

        # Gerar linhas de listagem (Top 10)
        for e in entries[:10]:
            path = e.get('path', 'N/A')
            sha = e.get('sha1', 'N/A')
            blob_url = make_blob_url_from_git(base_url, sha)

            listing_html += f"<tr><td>{path}</td><td>{sha[:12]}...</td><td><a href='{blob_url}' target='_blank'>Ver Blob</a></td></tr>"

        if len(entries) > 10:
            listing_html += f"<tr><td colspan='3' class='meta'>... e mais {len(entries) - 10} entradas. Consulte listing.html para o relatório completo.</td></tr>"

        listing_html += "</tbody></table>"

    except FileNotFoundError:
        listing_html = "<p class='error'>2. Dados do Index (dump.json) não encontrados. Execute --parse-index ou --default.</p>"

    # 3. Carregar Histórico de Commits
    history_summary = ""
    try:
        with open(history_path, 'r', encoding='utf-8') as f:
            history_data = json.load(f)

        commits = history_data.get('commits', [])
        total_commits = len(commits)

        history_summary = "<h3>3. Histórico de Commits (Análise de Tree)</h3>"

        # Inserir contexto extra se disponível
        if remote_url:
            history_summary += f"<p><b>Origem Remota:</b> {remote_url}</p>"

        history_summary += f"<p>HEAD Inicial: {history_data.get('head', 'N/A')}</p>"
        history_summary += f"<p>Total de Commits Processados: {total_commits}</p>"

        history_summary += "<details><summary>Detalhes dos Últimos 5 Commits</summary><ol>"

        for commit in commits[:5]:
            status = "OK" if commit.get('ok') else "FALHA"
            status_class = "ok" if commit.get('ok') else "error"
            message = commit.get('message', 'N/A').splitlines()[0]
            files_count = commit.get('file_count', 0)

            # Formatar link se houver remote url
            sha_display = commit['sha'][:10]
            if remote_url:
                clean_url = remote_url.replace('.git', '')
                sha_display = f"<a href='{clean_url}/commit/{commit['sha']}' target='_blank'>{sha_display}</a>"

            history_summary += f"<li><span class='{status_class}'>[{status}]</span> {sha_display}: {message} ({files_count} arquivos)</li>"

        history_summary += "</ol><p class='meta'>Consulte history.html para o histórico completo e detalhes de arquivos.</p></details>"

    except FileNotFoundError:
        history_summary = "<p class='error'>3. Dados de Histórico (history.json) não encontrados. Execute --reconstruct-history ou --default.</p>"

    # 4. Packfiles
    packfiles_html = ""
    try:
        with open(packfiles_path, 'r', encoding='utf-8') as f:
            packs = json.load(f)
        packfiles_html = f"<h3>4. Packfiles Encontrados</h3><p>Total Encontrado: {len(packs)}</p>"
        if packs:
            packfiles_html += "<table style='width: 100%;'><thead><tr><th>Nome</th><th>Status</th><th>URL</th></tr></thead><tbody>"
            for p in packs:
                status_class = "ok" if "Extraído" in p['status'] or "Baixado" in p['status'] else "muted"
                packfiles_html += f"<tr><td>{p['name']}</td><td class='{status_class}'>{p['status']}</td><td><a href='{p['url_pack']}' target='_blank'>Download</a></td></tr>"
            packfiles_html += "</tbody></table>"
        else:
            packfiles_html += "<p class='muted'>Nenhum packfile detectado em objects/info/packs.</p>"
    except FileNotFoundError:
        packfiles_html = "<p class='muted'>4. Verificação de Packfiles não executada ou sem resultados.</p>"

    # Montar o HTML Final
    final_html = f"""
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Relatório Técnico Unificado - {base_url}</title>
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

    <p class='muted'>Para visualização interativa do histórico e da listagem completa, inicie o servidor: <code>python git_leak.py --serve --output-dir {outdir}</code></p>
    <p class='meta' style='text-align:center; margin-top:30px;'>Gerado por Git Leak Explorer</p>
</div>
</body>
</html>
    """

    report_path = os.path.join(outdir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(final_html)

    success(f"Relatório unificado gerado em: {report_path}")


# ---------------------------
# CLI wiring
# ---------------------------
def main():
    p = argparse.ArgumentParser(prog="git_leak.py",
                                description="Recover Git leaks and generate navigable forensic output.")

    # ARGUMENTO POSICIONAL ÚNICO (URL Base, opcional se nenhum comando de rede for usado)
    p.add_argument("base", nargs="?", help="Base URL of remote .git (eg https://site.com/.git/ )")

    p.add_argument("--output-index", default="dump.json",
                   help="Output filename for the index JSON dump, or input JSON file for reconstruction (default: dump.json)")
    p.add_argument("--output-dir", default="./repo",  # ALTERADO PARA ./repo
                   help="Output directory for reconstructions, listings, and reports (default: ./repo)")

    p.add_argument("--serve-dir", nargs="?",
                   help="Directory to serve when using --serve.")

    p.add_argument("--default", action="store_true",
                   help="Run a sequence of default tasks: parse-index, detect-hardening, list, reconstruct-history, and serve.")

    p.add_argument("--report", action="store_true",
                   help="Generate a single unified technical report (report.html) from existing JSON data.")

    p.add_argument("--parse-index", action="store_true",
                   help="Download and convert remote .git/index to JSON (requires base)")
    p.add_argument("--list", action="store_true",
                   help="Generate modern listing (UI) in outdir (Simplified list: public+blob)")
    p.add_argument("--reconstruct-history", action="store_true",
                   help="Reconstruct commit history (UI-only snapshots: history.json + history.html)")
    p.add_argument("--max-commits", type=int, default=200, help="Max commits to walk for history")
    p.add_argument("--ignore-missing", action="store_true", help="Ignore missing objects when reconstructing history")
    p.add_argument("--strict", action="store_true", help="Abort on first error when reconstructing history")
    p.add_argument("--sha1", help="Recover a single object by SHA1 (requires base)")
    p.add_argument("--detect-hardening", action="store_true",
                   help="Detect exposure of .git components and produce a report")
    p.add_argument("--packfile", choices=['list', 'download', 'download-unpack'],
                   help="Handle packfiles (list, download, or download-unpack)")
    p.add_argument("--serve", action="store_true",
                   help="Serve a directory via HTTP (pass directory using --serve-dir)")
    p.add_argument("--workers", type=int, default=10, help="Concurrency for downloads / checks")
    p.add_argument("--scan", help="Scan a list of URLs for .git exposure (file)")
    p.add_argument("--check-public", action="store_true",
                   help="When generating listing, perform HEAD requests to check public link (ignored in current simplified --list).")

    p.add_argument("--blind", action="store_true", help="Ativa modo blind (crawl) se index não existir")

    args = p.parse_args()

    # --- Lógica de Execução ---

    base_url = args.base
    output_dir = args.output_dir
    index_name = args.output_index

    # 0. SCAN (Único que não precisa de base_url)
    if args.scan:
        scan_urls(args.scan)
        return

    # 0.1 Serve isolado
    if args.serve:
        serve_dir(args.serve_dir if args.serve_dir else output_dir)
        return

    # 1. Tratar a flag --report
    if args.report:
        if not base_url:
            fail("O comando --report requer a URL base do .git para geração de links no relatório.")
            return
        # Apenas carrega os dados e gera o HTML
        generate_unified_report(output_dir, base_url)
        return

    # 1.1 --packfile isolado
    if args.packfile:
        if not base_url:
            fail("O comando --packfile requer a URL base.")
            return
        handle_packfiles(args.packfile, base_url, output_dir)
        return

    # 1.2 --blind isolado
    if args.blind:
        if not base_url:
            fail("O comando --blind requer a URL base.")
            return
        blind_recovery(base_url, output_dir, index_name)
        return

    # 2. Tratar o modo --default, seja por flag ou implicitamente no final
    if args.default:
        if not base_url:
            fail("O modo --default requer a URL base do .git.")
            return

        # Caminho completo para o JSON (sempre dentro de _files)
        index_json_path = os.path.join(output_dir, "_files", index_name)

        info(f"Iniciando pipeline (--default) em {base_url} -> {output_dir}/ usando index: {index_name}")

        os.makedirs(output_dir, exist_ok=True)

        # PASSO 1: TENTAR BAIXAR INDEX OU USAR BLIND MODE
        info("PASSO 1/7: Tentando obter índice...")
        tmpf = "__downloaded_index_tmp"
        candidates = [base_url.rstrip("/") + "/.git/index", base_url.rstrip("/") + "/index"]
        idx_ok = False

        os.makedirs(os.path.join(output_dir, "_files"), exist_ok=True)

        for c in candidates:
            ok_s, d = http_get_bytes(c)
            if ok_s:
                with open(tmpf, "wb") as f:
                    f.write(d)
                try:
                    index_to_json(tmpf, index_json_path)
                    os.remove(tmpf)
                    idx_ok = True
                    break
                except:
                    pass

        if not idx_ok:
            warn("Index não acessível (403/404). Tentando MODO BLIND automaticamente...")
            if not blind_recovery(base_url, output_dir, index_name):
                fail("Falha Crítica no PASSO 1: Não foi possível baixar index nem executar modo blind.")
                return

        # PASSO 2: HARDENING + INTELLIGENCE
        info("PASSO 2/7: Executando --detect-hardening e Coletando Inteligência...")
        detect_hardening(base_url, output_dir)
        # Sempre chamamos gather_intelligence para ter certeza que temos logs e config
        gather_intelligence(base_url, output_dir)

        # PASSO 3: PACKFILES (List only)
        info("PASSO 3/7: Verificando Packfiles (list only)...")
        handle_packfiles('list', base_url, output_dir)

        # PASSO 4: LISTING HTML
        info("PASSO 4/7: Executando --list (gerando listing.html)...")
        # make_listing_modern já trata exceções internamente agora para não travar
        make_listing_modern(index_json_path, base_url, output_dir)

        # PASSO 5: HISTÓRICO
        info("PASSO 5/7: Executando --reconstruct-history (gerando history.html)...")
        reconstruct_history(index_json_path, base_url, output_dir, max_commits=args.max_commits,
                            ignore_missing=args.ignore_missing, strict=args.strict)

        # PASSO 6: REPORT
        info("PASSO 6/7: Gerando Relatório Unificado (report.html)...")
        generate_unified_report(output_dir, base_url)

        # PASSO 7: SERVE
        info("PASSO 7/7: Executando --serve...")
        info("Análise completa. Servindo o diretório de saída (Ctrl+C para parar)...")
        serve_dir(output_dir)
        return

    # 3. Comandos que requerem URL base (validate)
    if args.parse_index or args.detect_hardening or args.reconstruct_history or args.list or args.sha1:
        if not base_url:
            fail(f"O comando requer a URL base do .git (argumento posicional).")
            return

    # 4. Comandos Singulares

    json_path_root = os.path.join(output_dir, "_files")
    input_json_path = os.path.join(json_path_root, index_name)

    # serve
    if args.serve:
        dir_to_serve = args.serve_dir if args.serve_dir else output_dir
        serve_dir(dir_to_serve)
        return

    # parse-index
    if args.parse_index:
        # Same logic as default...
        pass

        # detect-hardening
    if args.detect_hardening:
        detect_hardening(base_url, output_dir)
        gather_intelligence(base_url, output_dir)
        return

    # sha1
    if args.sha1:
        ok_status = recover_one_sha(base_url, args.sha1, output_dir, args.sha1)
        if ok_status:
            success("Objeto recuperado.")
        else:
            warn("Falha ao recuperar objeto.")
        return

    # reconstruct-history
    if args.reconstruct_history:
        reconstruct_history(input_json_path, base_url, output_dir, max_commits=args.max_commits,
                            ignore_missing=args.ignore_missing, strict=args.strict)
        return

    # list
    if args.list:
        make_listing_modern(input_json_path, base_url, output_dir)
        return

    # 5. Comportamento Padrão: Reconstrução de objetos (Comando legado)
    if base_url:
        info("Nenhuma flag de ação detectada. Usando o pipeline de análise --default.")

        # Simular a execução do --default
        args.default = True
        return main()

    # default: Mensagem de ajuda quando URL base NÃO é fornecida
    if not base_url:
        print(
            "Uso: git_leak.py <base_git_url> [--output-index dump.json] [--output-dir ./repo] [FLAGS...]")
        return


if __name__ == "__main__":
    main()