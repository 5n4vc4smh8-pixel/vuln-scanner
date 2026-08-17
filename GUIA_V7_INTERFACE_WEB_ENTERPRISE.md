# Vuln-Scanner v7 — Interface Web Enterprise

A v7 adiciona o **Painel Web Enterprise**: uma interface no navegador para gerenciar varreduras de vulnerabilidades, com autenticação, dashboard em tempo real, histórico de scans e a seção de **Threat Intelligence** integrada — tudo usando o mesmo motor Rust já validado (precisão 5/5, sem falsos positivos).

---

## O que há de novo

| Recurso | Descrição |
|---------|-----------|
| **Login seguro** | Autenticação com JWT (hash SHA-256). Credencial padrão: `admin` / `enterprise2026` |
| **Dashboard** | Cards com totais de severidade (críticas, altas, médias, baixas) e nº de scans |
| **Novo Scan** | Campo de alvo + checkbox "Modo agressivo"; o scan roda em segundo plano e a tabela atualiza a cada 5s |
| **Histórico de Scans** | Alvo, horários, total/crítica/alta/média, status (Em execução, Concluído, Erro) e botão **Abrir** do relatório |
| **Relatório no navegador** | O relatório completo com a seção de Threat Intelligence (grupos emergentes, CISA KEV, correlação alvo × grupo) abre dentro do painel |
| **Sair** | Logout que invalida a sessão do navegador |

---

## Instalação no teu Windows

**1)** Copia os arquivos do pacote `vuln-scanner-v7` para o teu projeto `C:\vuln-scanner`, sobrescrevendo os existentes e criando as pastas novas:

```
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\main.rs" src\
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\cli.rs" src\
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\scanner\engine.rs" src\scanner\
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\scanner\reporter.rs" src\scanner\

mkdir src\web 2>nul
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\web\*" src\web\

mkdir src\utils 2>nul
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\utils\*" src\utils\

mkdir src\security 2>nul
xcopy /y "C:\Users\jose\Downloads\vuln-scanner-v7\src\security\*" src\security\
```

> **Atenção:** se o teu projeto já tiver `src\utils\` e `src\security\` (módulos existentes da v6), **NÃO sobrescreva** — copia apenas os arquivos que estão no pacote v7 dentro dessas pastas. Se aparecer `Acesso negado` ou "substituir (Sim/Não)?", responde `S`.

**2)** Atualiza o `Cargo.toml` — adiciona estas linhas dentro da seção `[dependencies]` (onde já estão `reqwest`, `tokio`, `chrono`):

```toml
axum = { version = "0.7", features = ["json"] }
tower-http = { version = "0.5", features = ["cors"] }
jsonwebtoken = "9.3"
```

Depois sincroniza:
```
cargo build --release
```

**3)** Inicia o painel web:
```
cargo run --release -- --web-server 3000
```

(Ouve a mensagem: `Painel Enterprise iniciado em http://0.0.0.0:3000`)

**4)** Abre no navegador:
```
http://localhost:3000
```

**5)** Entra com:
- **Usuário:** `admin`
- **Senha:** `enterprise2026`

**6)** No campo "Alvo", digita `http://127.0.0.1:59599` (ou qualquer outro alvo), marca **Modo agressivo** e clica **Iniciar Scan**. A tabela atualiza sozinha a cada 5 segundos; quando ficar verde (**Concluído**), clica **Abrir** para ver o relatório com a seção de Threat Intelligence.

---

## Usar o modo linha de comando (nada muda)

O comando clássico continua funcionando normalmente:

```
cargo run --release -- --target "http://127.0.0.1:59599" --aggressive
```

O `--web-server` é um novo modo: sem `--target`, ele inicia o painel.

---

## Personalizar credenciais e porta

Use variáveis de ambiente **antes** de iniciar o painel:

```
set ADMIN_USER=teu_usuario
set ADMIN_PASS=tua_senha_forte
set JWT_SECRET=chave_secreta_bem_longa_e_aleatoria
cargo run --release -- --web-server 3000
```

> **Nunca use admin/enterprise2026 em produção.** Troque antes de expor o painel na rede.

---

## Arquivos da v7

| Arquivo | Função |
|---------|--------|
| `src/main.rs` | Registra o módulo web e o flag `--web-server` |
| `src/cli.rs` | Campos `web_server` / `web_port` |
| `src/web/mod.rs` | Tipos compartilhados (sessões, status de scan) |
| `src/web/auth.rs` | Autenticação JWT + hash de senha |
| `src/web/api.rs` | Estado compartilhado + handlers da API |
| `src/web/server.rs` | Servidor axum (rotas, CORS, página embutida) |
| `src/web/dashboard.html` | Página do painel (login, dashboard, histórico) |
| `src/scanner/engine.rs` | `generate_report` agora retorna o caminho real do arquivo |
| `src/scanner/reporter.rs` | Mesmo — retorna o caminho absoluto do relatório |

---

## Resolução de problemas

| Sintoma | Solução |
|---------|---------|
| `cargo build` falha com erros do axum | As novas dependências caíram na seção `[dependencies]`, não em `[dev-dependencies]` |
| Painel não responde | Verifica se a porta 3000 está livre: `netstat -aon findstr ":3000"`; senão usa outra porta: `--web-server 3001` |
| Login não funciona | Confirma o usuário/senha no `set ADMIN_USER/ADMIN_PASS` ou usa o padrão |
| "Erro ao ler relatório" | Inicia o painel a partir de `C:\vuln-scanner` (o relatório é gravado no diretório de trabalho atual) |
| Scan fica eternamente "Em execução" | Confere se o alvo está de pé (o scan expira após 10 minutos e marca Erro) |
