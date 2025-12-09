# 🕵️ Git Leak Explorer

> **Ferramenta simplificada de análise forense e recuperação de repositórios Git expostos publicamente via HTTP.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success)]()

O **Git Leak Explorer** é uma ferramenta "tudo-em-um" projetada para pesquisadores de segurança e administradores de sistemas. Ela permite identificar, baixar, reconstruir e analisar artefatos de pastas `.git` expostas inadvertidamente em servidores web.

A ferramenta vai além do download simples, oferecendo reconstrução de histórico de commits, detecção de riscos de segurança (hardening), suporte a *packfiles* e uma interface visual moderna (Dark Mode) para análise de dados.

## ⚠️ Aviso Legal
Esta ferramenta foi desenvolvida para fins educacionais e de auditoria autorizada. O acesso a sistemas de terceiros sem permissão explícita é ilegal e antiético. O desenvolvedor não se responsabiliza pelo mau uso deste software.


---

## ✨ Funcionalidades Principais

* **👁️ Blind Mode (Novo):** Recuperação inteligente mesmo quando o arquivo `.git/index` está ausente ou bloqueado (403/404), utilizando "Crawling" da árvores e commits.
* **🔍 Reconstrução de Artefatos:** Baixa e reconstrói arquivos localmente a partir do `.git/index` remoto.
* **📜 Histórico de Commits:** Reconstrói a árvore de commits (mensagens, autores, timestamps) sem precisar clonar o repositório inteiro via `git clone`.
* **🛡️ Análise de Hardening:** Verifica a exposição de arquivos sensíveis (`config`, `HEAD`, `logs`, etc.) e gera um relatório de risco (Crítico/Atenção).
* **📦 Suporte a Packfiles:** Detecta, baixa e extrai arquivos `.pack` (Git objects comprimidos) automaticamente.
* **📊 Relatórios Unificados:** Gera um painel HTML interativo (`report.html`) contendo listagem de arquivos, histórico, hardening e status de packfiles.
* **🎨 Interface Moderna:** Todos os relatórios HTML possuem tema escuro (Dark UI), busca em tempo real e paginação.
* **🚀 Alta Performance:** Utiliza *multi-threading* para downloads paralelos de objetos.

---

<img width="1220" height="855" alt="image" src="https://github.com/user-attachments/assets/c5165d09-f341-450f-afcc-ab7086b4e553" />


---

<img width="1226" height="779" alt="image" src="https://github.com/user-attachments/assets/9103cf7d-b51a-4baa-878d-23f09987dc10" />

---

<img width="1227" height="510" alt="image" src="https://github.com/user-attachments/assets/462ebb53-1a08-40ce-8e5a-4042b4cb3b56" />



## 🚀 Instalação e Configuração

Certifique-se de ter o **Python 3.8+** e o **Git** instalados no sistema (necessário para descompactação de objetos).

### Opção 1: Pip (Padrão)
```
pip install -r requirements.txt
```


### Opção 2: Pipenv
```
pipenv install requests
pipenv shell
python git_leak.py --help
```


### Opção 3: Poetry
```
poetry init -n
poetry add requests
poetry run python git_leak.py --help
```

### Opção 4: 🐳 Docker
```shell
docker build -t gitlieak_explorer .
docker run -v $(pwd)/repo:/app/repo gitleak_explorer http://alvo.com/.git --default --output-dir /app/repo
```

### Opção 5: 📦 Compilação para .EXE (Windows)
Para criar um executável portátil (standalone):
1. Instale o PyInstaller:
```
pip install pyinstaller
```
2. Compile o script:
```
pyinstaller --onefile --name "GitLeakExplorer" git_leak.py
```

## 📖 Como Usar

Modo Automático (Recomendado)
Executa todo o pipeline: baixa índice, verifica segurança, procura packfiles, reconstrói histórico e gera o relatório final.

```
python git_leak.py http://exemplo.com/.git --default
```

### Comandos Específicos
- Apenas Gerar Relatório Unificado (se já houver dados):

```
python git_leak.py http://exemplo.com/.git --report
```

- Recuperar um objeto diretamente pelo SHA
```
python git_leak.py http://exemplo.com/.git  --sha1 138605f2337271f004c5d18cf3158fce3f4a4b16 
```

- Gerenciar Packfiles (Listar/Baixar/Extrair):
```
# Apenas listar packfiles encontrados
python git_leak.py http://exemplo.com/.git --packfile list

# Baixar e tentar extrair (requer git instalado no sistema)
python git_leak.py http://exemplo.com/.git --packfile download-unpack
```

- Escanear Lista de URLs (Mass Scan):
```
python git_leak.py --scan alvos.txt
```

- Servir Relatórios Localmente:
```
python git_leak.py --serve --output-dir ./repo
```



