# Changelog

## [9.2.1] - 2026-08-21

### Adicionado
- **WAF Bypass v2.1**: Implementação de variantes ofuscadas (double-encode, case-mixing, comments, tabs) no fluxo de retry.
- **Variante %252F**: Adição de double-encode específico para burlar WAFs que decodificam a URL antes da inspeção.
- **Cache de Respostas Normais**: Implementação de cache `Arc<Mutex<HashMap>>` para evitar requisições redundantes, acelerando o scan em até 10x em modo agressivo.
- **Detector Open Redirect JSON**: Fallback para detecção de redirecionamento em corpos de resposta JSON (comum em SPAs).

### Corrigido
- **Bug de LFI/SQLi**: Refinamento da lógica de detecção para evitar falsos negativos quando o payload é refletido em mensagens de erro ou logs.
- **Deadlock de Threads**: Correção no `waf_bypass.rs` que causava travamento do scanner em alvos com rate-limit agressivo.
- **Auto-Threads**: Ajuste automático para 2 threads em modo bypass para manter a furtividade e evitar bloqueios 429 persistentes.
- **Alvo de Teste**: `alvo_hard.py` agora é thread-safe, permitindo testes realistas sem estourar o backlog do socket.

### Segurança
- **Stealth Mode**: Redução do budget de candidatos ocultos e payloads em modo bypass para priorizar a qualidade da detecção sobre a quantidade de requisições.
