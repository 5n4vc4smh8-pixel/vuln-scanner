# Benchmark Oficial — vuln-scanner v8.0

Matriz de precisão e recall executada automaticamente contra alvos com falhas reais.

| Alvo | Status | Detectadas | Precisão | Recall | Falsos Positivos |
|------|--------|------------|----------|--------|------------------|
| alvo_real (Loja Tech — falhas reais) | OK | 6/6 | 100% | 100% | 0 FP |
| alvo_xss (reflexão + IDOR) | OK | 2/2 | 100% | 100% | 0 FP |
| alvo_limpo (zero falsos positivos) | OK | 0/0 | 0% | 0% | 0 FP |

**Geral:** precisão **100%** | recall **100%** | falsos positivos totais: **0**

Metodologia: cada alvo é um app Python real com banco SQLite e falhas autênticas (não simuladas). O scanner é executado com `--aggressive` apontando apenas para a raiz do alvo; o discovery/crawler deve encontrar os endpoints sozinho. Um alvo sem nenhuma vulnerabilidade valida a taxa de falsos positivos.

