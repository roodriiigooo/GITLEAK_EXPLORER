# 🕵️ Git Leak Explorer




<div align="center">

   **Ferramenta avançada de análise forense, recuperação de repositórios Git e outros artefatos expostos publicamente na web via HTTP com saída visual, perfeita para aquele recon de respeito**

<img width="1111" height="428" alt="_multi_menu" src="https://github.com/user-attachments/assets/c748af6a-3aa8-43a7-9690-8813f0cc16ab" />


 [Sobre](#sobre) | [Aviso Legal](#%EF%B8%8F-aviso-legal) | [Funcionalidades](#-funcionalidades-principais) | [Screenshots](#screenshots) | [Instalação](#-instalação-e-configuração) | [Como Usar](#-como-usar) | [Agradecimentos](#tophat-obrigado-)

<br>

[Têm uma demonstração do relatório aqui](https://rodrigo.londrina.br/GITLEAK_EXPLORER/)

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

## Sobre
O **Git Leak Explorer** é uma ferramenta "tudo-em-um" projetada para pesquisadores de segurança e administradores de sistemas. Ela permite identificar, baixar, reconstruir e analisar artefatos de pastas `.git` expostas inadvertidamente em servidores web.

A ferramenta vai além do download simples, oferecendo reconstrução de histórico de commits, detecção de riscos de segurança (hardening), suporte a *packfiles* e uma interface visual moderna (com Dark Mode) para análise dos dados. Opcionalmente suporta também busca de vazamentos de artefatos SVN, HG, Env e DS_Store. Também possui a habilidade de scan massivo em lista de alvos e efetuar bruteforce com wordlist em busca de artefatos de interesse.

Tudo isso em um só projeto. Leve, direto e brasileiro.

> Ajude a desenvolver este projeto
>> Sinta-se a vontade para contribuir, enviar sugestões e suas pull requests :D


---


## ⚠️ Aviso Legal
Esta ferramenta foi desenvolvida para fins profissionais éticos, educacionais e de auditoria autorizada. O acesso a sistemas de terceiros sem permissão explícita é ilegal,  antiético e passível de punições legais. 

# O desenvolvedor não se responsabiliza pelo mau uso deste software.


---

## ✨ Funcionalidades Principais

* **👁️ Blind Mode:** Recuperação inteligente mesmo quando o arquivo `.git/index` está ausente ou bloqueado (403/404), utilizando "Crawling" da árvores e commits.
* **🔍 Reconstrução de Artefatos:** Baixa e reconstrói arquivos localmente a partir do `.git/index` remoto.
* **📜 Histórico de Commits:** Reconstrói a árvore de commits (mensagens, autores, timestamps) sem precisar clonar o repositório inteiro via `git clone`.
* **🛡️ Análise de Hardening:** Verifica a exposição de arquivos sensíveis (`config`, `HEAD`, `logs`, etc.) e gera um relatório de risco (Crítico/Atenção).
* **📦 Suporte a Packfiles:** Detecta, baixa e extrai arquivos `.pack` (Git objects comprimidos) automaticamente.
* **📊 Relatórios Unificados:** Gera um painel HTML interativo (`report.html`) contendo listagem de arquivos, histórico, hardening e status de packfiles.
* **🎨 Interface Moderna:** Todos os relatórios HTML possuem tema escuro (Dark UI), busca em tempo real e paginação.
* **🚀 Alta Performance:** Utiliza *multi-threading* para downloads paralelos de objetos.
* **🔍 Suporte Adicional:** Efetua buscas por artefatos SVN, HG, Env e DS_Store.
* **💪 Suporte a Brute Force:** Habilidade de utilizar wordlists contendo artefatos de interesse e seus respectivos paths de busca.
* **:earth_americas: Suporte a Proxy:** Conecte-se com o Proxy que desejar, incluindo a rede Tor.
* **:busts_in_silhouette: Random User-Agents:** User-Agentes simulados por default.

---

## Screenshots

<details>
  <summary># Visão Geral - Multi Scan</summary>
  <img width="1111" height="660" alt="_multi_menu" src="https://github.com/user-attachments/assets/ef41828a-980f-4d8c-a72b-40945cb49a20" />
</details>

<details>
  <summary># Visão Geral - Alvo</summary>
  <img width="1349" height="1798" alt="_principal_demo" src="https://github.com/user-attachments/assets/5f032547-9480-4ea6-ad1e-565119a738c9" />
</details>

<details>
  <summary># Secrets</summary>
  <img width="1466" height="767" alt="_secrets" src="https://github.com/user-attachments/assets/67241847-3ef3-4e46-81e9-1eb25918418d" />
</details>

<details>
  <summary># Hardening</summary>
  <img width="1284" height="963" alt="_hardening" src="https://github.com/user-attachments/assets/34ecb782-f030-45cb-b7e7-2eeb1fd0b4e1" />
</details>

<details>
  <summary># Usuarios - baseado em histórico</summary>
  <img width="1284" height="963" alt="_users" src="https://github.com/user-attachments/assets/d757b98a-011e-4d4d-be90-637afaca9f1e" />
</details>

<details>
  <summary># Reconsrução de histórico</summary>
  <img width="1903" height="1487" alt="_history" src="https://github.com/user-attachments/assets/bb890f7f-e82c-4e8a-b18d-d0a980cecfe4" />
</details>

<details>
  <summary># Listagem de arquivos - com filtro</summary>
  <img width="1641" height="1231" alt="_listing" src="https://github.com/user-attachments/assets/2084abe1-9f68-4a37-a91a-5a2dc4c66730" />
</details>

<details>
  <summary># Bruteforce & Path traversal - com filtro</summary>
  <img width="1512" height="822" alt="_brute_traversal" src="https://github.com/user-attachments/assets/e0d348c5-86ab-4494-84a7-a3f25643f32d" />
</details>

<details>
  <summary># Outros</summary>
  <img width="1136" height="852" alt="_outros" src="https://github.com/user-attachments/assets/1fd48b68-66c1-4791-9498-169bb6099967" />
</details>



## 🚀 Instalação e Configuração

> [!TIP]
> ESTE REPOSITÓRIO POSSUI UMA BUILD STANDALONE PARA WINDOWS, se preferir utilizar ao invés do python.
> >  Apenas copie o arquivo em um path que você desejar e registre-o no sistema para ser reconhecido como um cmdlet e pule os próximos passos.
> > > Não exclui a necessidade de ter o Git instalado no sistema.

<br>

Certifique-se de ter os seguintes requisitos instalados: [**Python 3.8+**](https://www.python.org/downloads/) e [**Git**](https://desktop.github.com/download/) (necessário para descompactação de objetos):

[![Python](https://img.shields.io/badge/Python-Download-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![GitHub Desktop](https://img.shields.io/badge/GitHub_Desktop-Download-181717?logo=github&logoColor=white)](https://desktop.github.com/download/)



<br>



### Opção 1: Pip (Padrão)
```sql
pip install -r requirements.txt
```


### Opção 2: Pipenv
```sql
pipenv install requests
pipenv shell
python git_leak.py --help
```


### Opção 3: Poetry
```sql
poetry init -n
poetry add requests
poetry run python git_leak.py --help
```

### Opção 4: 🐳 Docker
```sql
docker build -t gitleak_explorer .
docker run -v $(pwd)/repo:/app/repo gitleak_explorer http://alvo.com/.git --default --output-dir /app/repo
```

### Opção 5: 📦 Compilação para .EXE (Windows)
Para criar um executável portátil (standalone):
1. Instale o PyInstaller:
```sql
pip install pyinstaller
```
2. Compile o script:
```sql
pyinstaller --onefile --name "git_leak" git_leak.py
```

## 📖 Como Usar

> [!TIP]
> >  Se estiver utilizando a versão RELEASE (Windows), considere usar `git_leak.exe` ao invés de `python git_leak.py`.

```terminal
git_leak.py — Conjunto completo de ferramentas em arquivo único para recuperação e análise forense de vazamentos do Git.

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
 - options: --max-commits, --ignore-missing, --strict, --workers, --output-index, --output-dir, --serve-dir
 

 - Todos os arquivos de saída são armazenados no diretório externo fornecido: arquivos HTML na raiz, arquivos JSON/outros arquivos em outdir/_files.


Utilize de forma responsável e somente em sistemas que você esteja autorizado a testar.
```


Modo Automático (Recomendado)
Executa todo o pipeline: baixa índice, verifica segurança, procura packfiles, reconstrói histórico e gera o relatório final.

```sql
python git_leak.py http://exemplo.com
# ou
python git_leak.py http://exemplo.com/.git --default
```

Modo Adicional `--full-scan`
Executa além do modo padrão, outros vazamentos (SVN, HG, Env, DS_Store)

```sql
python git_leak.py http://exemplo.com/.git --full-scan
```

Modo lento `--full-history`
Executa em modo padrão ou modo adicional, mas tenta reconstruir o history de commits analisando todos os registros encontrados

```sql
python git_leak.py http://exemplo.com/.git --full-history
```


### Comandos Específicos
- Apenas Gerar Relatório Unificado (se já houver dados baixados anteriormente) `--report`:

```sql
python git_leak.py http://exemplo.com/.git --report
```

- Habilitar servidor http para visualizar relatorios ou servir outros arquivos `--serve`:
```sql
python git_leak.py http://exemplo.com/.git --serve
# ou em conjunto com --output-dir para servir um diretório especifico
python git_leak.py --serve --output-dir temp/arquivos/
```


- Recuperar um objeto diretamente pelo SHA `--sha1`
```sql
python git_leak.py http://exemplo.com/.git  --sha1 138605f2337271f004c5d18cf3158fce3f4a4b16
# Pode ser usado em conjunto com --output-dir
python git_leak.py http://exemplo.com/.git  --sha1 138605f2337271f004c5d18cf3158fce3f4a4b16 --output-dir temp/arquivos/
```


- Gerenciar Packfiles (Listar/Baixar/Extrair) `--packfile`:
```sql
# Apenas listar packfiles encontrados
python git_leak.py http://exemplo.com/.git --packfile list

# Baixar e tentar extrair (requer git instalado no sistema)
python git_leak.py http://exemplo.com/.git --packfile download-unpack
```

- Escanear Lista de URLs (Mass Scan) `--scan`:
```sql
python git_leak.py --scan alvos.txt
```

- Servir Relatórios Localmente:
```sql 
python git_leak.py --serve --output-dir repo/temp
```

- Executar scan massivo de alvos utilizando bruteforce de objetos de interesse através de lista personalizada com resultado organizado em pastas distintas:
```sql
python git_leak.py --scan alvos-exemplo.txt --output-dir pasta-alvos  --full-scan --bruteforce --wordlist wordlist-exemplo.txt --serve
```

- Caso executado apenas com `--brute-force`, o bruteforce utilizará uma lista hardcoded:
```sql
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
```

- Modo completo com Proxy:
```sql
python git_leak.py exemplo.com --output-dir teste_proxy --proxy 127.0.0.1:8080 --full-scan --bruteforce --serve
# ou rede Tor (SOCKS5)
python git_leak.py exemplo.com --output-dir teste_proxy --proxy socks5h://127.0.0.1:9150 --full-scan --bruteforce --serve

```
- Desativa User-Agents aleatórios:
```sql
python git_leak.py exemplo.com --output-dir sua_pasta --proxy 127.0.0.1:8080 --no-random-agent --serve
```



## :tophat: Obrigado ♥
Err.. ninguém contribuiu ainda :(


## :sparkling_heart: Support Me 
<a href="https://www.buymeacoffee.com/rodrigoo" target="_blank"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-5C3317?style=for-the-badge&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me A Coffee" target="_blank"></a>
<!-- <a href="https://www.paypal.com/donate/?business=RNSQFDU927P8A&no_recurring=0&item_name=Every+penny+donated+is+an+investment+not+only+in+me+but+also+in+fulfilling+dreams+and+creating+opportunities.&currency_code=BRL" target="_blank"><img src="https://img.shields.io/badge/Paypal%20%28BRL%29-4287f5?style=for-the-badge&logo=paypal&logoColor=white" alt="Paypal" target="_blank"></a> -->







