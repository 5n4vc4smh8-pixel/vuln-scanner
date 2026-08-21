# Vuln-Scanner v9.2.1 🛡️

O **Vuln-Scanner** é um scanner de vulnerabilidades web moderno escrito em Rust, focado em performance, furtividade e correlação com inteligência de ameaças (CTI).

## Novidades da v9.2.1

Esta versão traz avanços significativos em **WAF Bypass** e **Performance**:

- **Bypass Ofuscativo Avançado**: O scanner agora gera variantes inteligentes de payloads (como double-encode `%252F`, case-mixing e injeção de comentários) automaticamente quando detecta um bloqueio de WAF.
- **Motor de Cache Inteligente**: Um novo sistema de cache de respostas normais reduz drasticamente o tráfego de rede, tornando o scan agressivo muito mais rápido e menos ruidoso.
- **Correlação CTI SudOeste**: O relatório agora correlaciona falhas detectadas com padrões de ataque de grupos de ransomware emergentes, priorizando o que realmente importa para a defesa.

## Como Executar

Para rodar o scanner contra um alvo de teste:

```bash
# Compilar
cargo build --release

# Executar scan agressivo com bypass de WAF
./target/release/vuln-scanner --target http://seu-alvo.com --aggressive --waf-bypass
```

## Arquitetura

O scanner é dividido em motores modulares:
- **Discovery**: Mapeamento de endpoints e parâmetros ocultos.
- **Bypass**: Gerenciamento de rate-limit, User-Agents e ofuscação.
- **Detection**: Motores especializados para SQLi, XSS, LFI, IDOR, etc.
- **CTI**: Módulo de correlação com feeds de inteligência de ameaças.

---
*Desenvolvido com ❤️ em Rust para a comunidade de segurança.*
