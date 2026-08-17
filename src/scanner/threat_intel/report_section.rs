/// Gera a seção "Inteligência de Ameaças" do relatório Markdown.
use super::CorrelationResult;

/// Gera as linhas da seção de Threat Intelligence. Retorna `Ok(texto)` ou erro.
pub fn generate_threat_intel_section(result: &CorrelationResult) -> String {
    let mut out = String::new();

    out.push_str("## Inteligência de Ameaças (Threat Intelligence)\n\n");
    out.push_str("Esta seção cruza as vulnerabilidades detectadas com o comportamento conhecido de **grupos de ransomware \
emergentes** monitorados por fontes públicas de CTI (Critical Intel, Cyble, Proven Data, Ransom Database, Halcyon AI, \
PICUS Security) e com o catálogo **CISA KEV** (CVEs com exploração ativa).\n\n");

    // --- Correlações ---
    if result.correlations.is_empty() {
        out.push_str("**Nenhuma correlação direta com grupos monitorados.** As vulnerabilidades encontradas não casam \
com os padrões de exploração dos grupos emergentes rastreados. Isso não significa ausência de risco: manter \
varreduras periódicas e aplicar patches segue sendo essencial.\n\n");
    } else {
        out.push_str("### Correlação: alvo × grupos emergentes\n\n");
        out.push_str("| Grupo | Risco (0-100) | Vulnerabilidades casadas | Público brasileiro já publicado? |\n");
        out.push_str("|-------|---------------|--------------------------|----------------------------------|\n");
        for c in &result.correlations {
            out.push_str(&format!("| **{}** | {} | {} | {} |\n",
                c.group.name,
                c.risk_priority,
                {
                    let mut seen = std::collections::HashSet::new();
                    c.matched_vulns.iter().map(|m| m.vuln_name.as_str()).filter(|n| seen.insert(*n)).collect::<Vec<_>>().join(", ")
                },
                if c.group.brazil_flagged { "SIM ⚠️" } else { "Não" },
            ));
        }
        out.push('\n');

        for c in &result.correlations {
            out.push_str(&format!("#### Grupo: {} — prioridade de risco {}/100\n\n", c.group.name, c.risk_priority));
            out.push_str(&format!("**Situação:** {}\n\n", c.rationale));
            out.push_str(&format!("**Perfil:** {}\n\n", c.group.summary));
            out.push_str(&format!("**Operação:** {}\n\n", c.group.model));
            out.push_str(&format!("**Vetores de acesso típicos:** {}\n\n", c.group.initial_access.join("; ")));
            out.push_str(&format!("**Indicadores técnicos conhecidos:** {}\n\n",
                c.group.technical_indicators.join("; ")));
            out.push_str(&format!("**Vítimas publicadas:** {} | **Desde:** {} | **Última verificação:** {}\n\n",
                c.group.victims_published, c.group.since, c.group.last_verified));

            if !c.group.source_urls.is_empty() {
                out.push_str("**Fontes:**\n\n");
                for u in &c.group.source_urls {
                    out.push_str(&format!("- {}\n", u));
                }
                out.push('\n');
            }

            out.push_str("**Vulnerabilidades do alvo casadas com este grupo:**\n\n");
            for m in &c.matched_vulns {
                out.push_str(&format!("- **{}** (severidade {:?}) em `{}`{}\n",
                    m.vuln_name, m.severity, m.url,
                    m.parameter.as_ref().map(|p| format!(" (parâmetro `{}`)", p)).unwrap_or_default()));
            }
            out.push('\n');
        }
    }

    // --- CISA KEV ---
    out.push_str("### CVEs com exploração ativa (CISA KEV)\n\n");
    if result.kevs_loaded {
        out.push_str(&format!("Catálogo carregado: versão {}, **{} entradas** (recuperado em {}).\n\n",
            result.kev_catalog_version, result.kev_count, "consulta ao feed oficial CISA"));
        out.push_str("Destaques priorizados para infraestrutura web (ordem de relevância para ecossistema de \
ransomware):\n\n");
        out.push_str("| CVE | Produto | Vulnerabilidade | Data no KEV |\n");
        out.push_str("|-----|---------|-----------------|-------------|\n");
        for kev in &result.kev_prioritized {
            let name = kev.vulnerability_name.replace('\n', " ");
            out.push_str(&format!("| {} | {} | {} | {} |\n",
                kev.cve_id, kev.product, name, kev.date_added));
        }
        out.push('\n');
        out.push_str("> O catálogo completo de CVEs explorados ativamente está em \
https://www.cisa.gov/known-exploited-vulnerabilities-catalog . Verifique se algum software presente na sua \
infraestrutura aparece na lista e aplique o patch correspondente como prioridade máxima.\n\n");
    } else {
        out.push_str("**Não foi possível carregar o feed CISA KEV nesta execução** (rede/proxy indisponível). \
Consultar manualmente: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n\n");
    }

    // --- Recomendações ---
    out.push_str("### Recomendações priorizadas\n\n");
    for rec in &result.top_recommendations {
        out.push_str(&format!("- {}\n", rec));
    }
    out.push('\n');

    // --- Nota metodológica ---
    out.push_str("**Nota metodológica:** as publicações de vítimas em leak sites são alegações dos próprios \
criminosos e não constituem confirmação de incidentes. A base de grupos é atualizada manualmente com base em \
fontes públicas; em operações de produção, recomenda-se integrar um feed de CTI (MITRE ATT&CK, AlienVault OTX, \
MISP) para atualização automática.\n\n");

    out
}
