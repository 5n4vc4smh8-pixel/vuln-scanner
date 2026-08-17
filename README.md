# vuln-scanner

**Scanner de vulnerabilidades web de alta precisão, escrito em Rust.**

Detecta, valida e relata vulnerabilidades em aplicações web com detecção comportamental (não apenas assinatura de payload), relatórios profissionais em Markdown e correlação com Threat Intelligence (grupos de ransomware emergentes e CVEs com exploração ativa do CISA KEV).

| | |
|---|---|
| **Linguagem** | Rust (zero dependências de runtime) |
| **Detecções** | SQL Injection, XSS, LFI, SSTI, SSRF, Command Injection, Open Redirect, Path Traversal, e mais |
| **Precisão** | Foco em minimizar falsos positivos com análise comportamental e de contexto |
| **Relatórios** | Markdown executivo, CWE mapeado, evidências e remediação |
| **Threat Intel** | Correlação com grupos emergentes de ransomware e catálogo CISA KEV |
| **Interface** | CLI de linha de comando + painel web Enterprise (autenticação JWT) |
| **Crawleamento** | Discovery real de links, formulários e parâmetros (profundidade configurável) |
| **IDOR** | Detecção de Insecure Direct Object Reference por comparação comportamental de recursos |
| **Licença** | AGPL-3.0 (ver `LICENSE`) |

## Por que Rust?

Scanners de segurança executam milhares de requisições por segundo. Rust entrega **performance nativa**, **segurança de memória** e **binários estáticos** que rodam em qualquer máquina sem instalar runtime — o mesmo binário funciona em Windows, Linux e macOS (via builds multiplataforma).

## Instalação

### Do código-fonte

```bash
git clone https://github.com/5n4vc4smh8-pixel/vuln-scanner.git
cd vuln-scanner
cargo build --release
```

O binário estará em `target/release/vuln-scanner` (Windows: `vuln-scanner.exe`).

### Usando o binário pré-compilado

Baixe o release mais recente em [Releases](https://github.com/5n4vc4smh8-pixel/vuln-scanner/releases) e execute diretamente. Nenhuma instalação de runtime é necessária.

## Uso rápido

```bash
# Scan básico
./vuln-scanner --target http://seu-alvo.com.br

# Modo agressivo (mais payloads, detecção profunda)
./vuln-scanner --target http://seu-alvo.com.br --aggressive

# Crawleamento com profundidade 3 e rate limit de 100ms entre requisições
./vuln-scanner --target http://seu-alvo.com.br --crawl --crawl-depth 3 --rate-limit 100

# Relatório em PDF (ou "both" para Markdown + PDF)
./vuln-scanner --target http://seu-alvo.com.br --report-format pdf

# Iniciar o painel web Enterprise na porta 3000
./vuln-scanner --web-server 3000
```

> O flag `--crawl` está habilitado por padrão. Use `--rate-limit <ms>` para controlar a velocidade das requisições em ambientes de produção e `--crawl-depth <n>` para limitar a profundidade de navegação.

> **⚠️ Uso ético:** este scanner deve ser utilizado apenas em sistemas próprios ou com autorização explícita e por escrito do proprietário. Scan não autorizado em sistemas de terceiros é crime (no Brasil, Lei 12.737/2012 e Lei 14.155/2021; em outros países, Computer Fraud and Abuse Act, GDPR, entre outros).

## Painel Web Enterprise

A versão Enterprise inclui um painel web completo com autenticação JWT:

- Dashboard com visão geral de scans e vulnerabilidades
- Gerenciamento de alvos e scans em background
- Histórico de relatórios acessível pelo navegador (Markdown e PDF)
- Credenciais configuráveis via `ADMIN_USER` e `ADMIN_PASS`

```bash
cargo run --release -- --web-server 3000
# Acesse http://localhost:3000 (padrão: admin / enterprise2026)
```

## Detecção comportamental

Diferente de scanners baseados apenas em listas de payloads, o `vuln-scanner` analisa o **comportamento da resposta**:

1. **Injeção de sentinela** — cada teste usa um token único e verificável, nunca um payload genérico
2. **Análise de contexto** — SQLi diferencia entre erro real de banco e reflexão de payload em campos diferentes (correção v6.2)
3. **Corroboração multi-prova** — uma vulnerabilidade só é reportada quando múltiplos sinais comportamentais convergem
4. **Contexto de execução** — Command Injection distingue o resultado real da execução do eco do payload
5. **Heurística anti-falso-positivo** — IDOR e outros testes comportamentais usam limiares diferenciados por tipo de página

## Benchmark oficial de precisão

O repositório inclui uma suíte de benchmark automatizada (`benchmarks/run_benchmark.py`) que executa o scanner contra aplicações Python reais com banco SQLite — alvos com falhas autênticas de código e um alvo limpo sem nenhuma vulnerabilidade. A matriz é recalculada a cada build:

| Alvo | Falhas reais | Detectadas | Falsos positivos |
|------|--------------|------------|------------------|
| Loja Tech (SQLi, XSS, LFI, CMDi, Open Redirect) | 6 | 6 | 0 |
| Alvo de reflexão + IDOR | 2 | 2 | 0 |
| Alvo limpo | 0 | 0 | 0 |

**Resultado oficial: precisão 100% | recall 100% | 0 falsos positivos** (executado 2x com resultado idêntico). A verificação completa está em `BENCHMARK.md`.

## Estrutura do relatório

Cada relatório em Markdown (ou PDF) contém: sumário executivo por severidade, detalhamento de cada vulnerabilidade (ID, CWE, URL, parâmetro, descrição, remediação e **evidência real capturada**), seção de Threat Intelligence com correlação a grupos de ransomware emergentes e CVEs do CISA KEV, e recomendações priorizadas.

## Testando em ambiente próprio

O repositório inclui `target_real/alvo_real.py`, uma aplicação de loja virtual **com falhas reais de código** (SQL Injection por concatenação, XSS por reflexão, LFI por leitura de arquivo, Command Injection por `shell=True` e Open Redirect), além de uma suíte de benchmark completa em `benchmarks/` com três alvos automatizados.

```bash
# Terminal 1: alvo de teste (no Windows, a porta 8080 é reservada — use outra porta)
python target_real/alvo_real.py 59599

# Terminal 2: scan
./vuln-scanner --target http://127.0.0.1:59599 --aggressive

# Ou rode a suíte de benchmark completa (Linux/macOS)
python3 benchmarks/run_benchmark.py
```

## Roadmap

| Versão | Objetivo |
|--------|----------|
| v6.2 | Detecção comportamental estável, Threat Intel, painel web |
| v7.0 | Painel web consolidado, Threat Intel com grupos emergentes |
| v8.0 | Crawleamento real, detecção de IDOR, relatórios PDF, rate limiting, suíte de benchmark |
| v8.1 | Feeds de CTI automatizados (OTX, MISP), crawleamento com autenticação |
| v9.0 | Modo "assistido por IA" para sugestão de patches (experimental) |

## Contribuindo

Contribuições são bem-vindas! Veja [CONTRIBUTING.md](CONTRIBUTING.md). Para vulnerabilidades no próprio scanner, siga [SECURITY.md](SECURITY.md).

## Aviso legal

Esta ferramenta é fornecida "como está" para fins de auditoria de segurança autorizada. O mantenedor não se responsabiliza por uso indevido ou não autorizado.
