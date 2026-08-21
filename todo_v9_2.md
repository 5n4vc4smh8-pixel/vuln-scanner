# TODO vuln-scanner v9.2

- [x] Alvo_hard.py corrigido (ThreadingHTTPServer + SO_REUSEADDR + timeout)
- [x] Bypass v2: throttle adaptativo + rotação de User-Agent + slot-lock global (limite rate-limit)
- [x] Integração do retry ofuscado no http_client (variante 1 já era testada)
- [x] Fix: consumir TODAS as variantes ofuscadas antes de desistir (loop MAX_RETRY+6)
- [x] Fix: backoff teto 1500ms + recuperação ÷3 (evita scan "travado" em 3s/req)
- [x] Variante double-encode da query RAW (%252F) — passa no WAF de assinatura
- [x] Stealth payloads (~45 vs ~150) quando --waf-bypass ativo
- [x] Find_hidden budget 60 em modo bypass
- [x] Threads auto 2 quando --waf-bypass (evita 429 em cascata)
- [x] OpenRedirect detector com fallback body/JSON
- [ ] Confirmar detecção de LFI via %252F no relatório final (s134 em andamento)
- [ ] Confirmar detecção de SQLi via case-mix no relatório final
- [ ] Versionar v9.2.0 e preparar release para GitHub
- [ ] Preparar post Show HN (Hacker News)
