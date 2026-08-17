# Guia de Contribuição

Obrigado por considerar contribuir com o `vuln-scanner`! Este guia ajuda a manter o projeto consistente e de alta qualidade.

## Código de conduta

Este projeto adota um ambiente colaborativo e respeitoso. Tratamos todos os contribuidores com cortesia profissional, independentemente de nível de experiência.

## Como contribuir

### Reportando bugs

Abra uma issue com o template de bug incluindo: versão do scanner, sistema operacional, alvo (descrição, nunca credenciais), comandos executados e o relatório gerado.

### Sugerindo melhorias

Abra uma issue com o template de feature request descrevendo o caso de uso e o comportamento esperado.

### Enviando código

1. Faça um fork do repositório e crie um branch a partir de `main`: `git checkout -b feature/minha-feature`
2. Mantenha commits focados e com mensagens descritivas (padrão: tipo: descrição, ex. `fix: corrige falso positivo em SQLi`)
3. Teste suas mudanças localmente, incluindo o alvo de teste `target_real/alvo_real.py`
4. Envie o pull request descrevendo o que mudou e por quê

### Padrões do projeto

- Código em Rust 2021 edition, sem warnings (execute `cargo build` e corrija todos)
- Documente módulos públicos com doc comments
- Novas detecções devem incluir testes no alvo real e evitar falsos positivos por design
- Relatórios em Markdown devem manter o formato estabelecido (sumário executivo + detalhamento + threat intel)

### O que não fazer

- Nunca enviar payloads reais contra sites de terceiros nos exemplos
- Nunca incluir credenciais, chaves ou dados sensíveis no código
- Nunca abrir issues públicas sobre vulnerabilidades de segurança (veja `SECURITY.md`)

## Dúvidas?

Abra uma issue de discussão ou entre em contato pelo e-mail do repositório.
