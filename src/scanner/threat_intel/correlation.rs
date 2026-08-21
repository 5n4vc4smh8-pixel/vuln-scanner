/// Motor de correlação: cruza as vulnerabilidades detectadas no scan com o
/// comportamento conhecido dos grupos de ransomware emergentes.
///
/// Regra central de CTI: vulnerabilidade = porta de entrada potencial para
/// ransomware. O motor calcula a exposição ao risco de extorsão cruzando:
///   1. Tipos de vulnerabilidade detectados (nome da falha no relatório)
///   2. Perfil de exploração de cada grupo (exploited_vuln_types)
///   3. Peso da severidade das vulnerabilidades correlacionadas
///   4. Flag de organização brasileira já publicada (aumenta urgência no contexto BR)
use super::groups::{emerging_groups, RansomwareGroup};
use crate::scanner::{DetectedVuln, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCorrelation {
    pub group: RansomwareGroup,
    /// Vulnerabilidades detectadas que casam com o perfil de exploração do grupo.
    pub matched_vulns: Vec<MatchedVuln>,
    /// Severidade máxima entre as vulnerabilidades correlacionadas.
    pub max_severity: Severity,
    /// Prioridade calculada: quanto este grupo representa risco para o alvo.
    pub risk_priority: u8, // 0-100
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedVuln {
    pub vuln_name: String,
    pub parameter: Option<String>,
    pub severity: Severity,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub correlations: Vec<GroupCorrelation>,
    pub kevs_loaded: bool,
    pub kev_count: usize,
    pub kev_catalog_version: String,
    pub kev_prioritized: Vec<super::cve_feed::CisaKevEntry>,
    pub top_recommendations: Vec<String>,
}

impl CorrelationResult {
    /// Executa a correlação dos achados do scan contra a base de grupos emergentes
    /// e o catálogo CISA KEV. Falhas de rede no KEV são toleradas (continua com os grupos).
    pub async fn correlate(results: &[DetectedVuln]) -> Self {
        let groups = emerging_groups();
        let mut correlations = Vec::new();

        for group in groups {
            let mut matched = Vec::new();
            for vuln in results {
                let name = &vuln.vulnerability.name;
                let is_relevant = Self::vuln_matches_group(name, &group);
                if is_relevant {
                    matched.push(MatchedVuln {
                        vuln_name: name.clone(),
                        parameter: vuln.parameter.clone(),
                        severity: vuln.vulnerability.severity.clone(),
                        url: vuln.url.clone(),
                    });
                }
            }

            if matched.is_empty() {
                continue;
            }

            let max_severity = matched.iter()
                .map(|m| m.severity.clone())
                .max()
                .unwrap_or(Severity::Info);

            let risk_priority = Self::compute_risk(&max_severity, matched.len(), group.victims_published, group.brazil_flagged);

            // FIX v6.1: dedup dos nomes na exibição (a tabela e o rationale mostram tipos
            // únicos: evita "XSS, XSS" quando múltiplos achados compartilham o mesmo tipo)
            let unique_names: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                matched.iter().map(|m| m.vuln_name.clone()).filter(|n| seen.insert(n.clone())).collect()
            };
            let rationale = if unique_names.len() == 1 {
                format!("O alvo possui 1 vulnerabilidade ({}) no mesmo padrão explorado pelo {}.",
                    unique_names[0], group.name)
            } else {
                format!("O alvo possui {} vulnerabilidades no mesmo padrão explorado pelo {}: {}. \
                    Este grupo {} e deve ser considerado para priorização imediata de remediação.",
                    matched.len(),
                    group.name,
                    unique_names.join(", "),
                    if group.brazil_flagged { "já publicou organizações brasileiras em seu leak site" } else { "opera em alta velocidade com dupla extorsão" })
            };

            correlations.push(GroupCorrelation {
                group,
                matched_vulns: matched,
                max_severity,
                risk_priority,
                rationale,
            });
        }

        // Ordena por prioridade de risco (desc) e depois por número de vítimas publicadas (desc)
        correlations.sort_by(|a, b| {
            b.risk_priority.cmp(&a.risk_priority)
                .then(b.group.victims_published.cmp(&a.group.victims_published))
        });

        // Tenta carregar o catálogo CISA KEV (falha silenciosa — degrada para grupos apenas)
        let mut kevs_loaded = false;
        let mut kev_count = 0;
        let mut kev_catalog_version = "n/a".to_string();
        let mut kev_prioritized = Vec::new();

        if let Some(catalog) = super::cve_feed::KevCatalog::fetch(25).await {
            kevs_loaded = true;
            kev_count = catalog.total_entries;
            kev_catalog_version = catalog.catalog_version.clone();
            kev_prioritized = catalog.prioritize_web_infra(10)
                .into_iter()
                .cloned()
                .collect();
        }

        let top_recommendations = Self::recommendations(&correlations);

        Self {
            correlations,
            kevs_loaded,
            kev_count,
            kev_catalog_version,
            kev_prioritized,
            top_recommendations,
        }
    }

    /// Casamento flexível entre o nome da vulnerabilidade detectada e o perfil do grupo.
    fn vuln_matches_group(name: &str, group: &RansomwareGroup) -> bool {
        // Mapeia nomes usados pelo scanner → categorias que os grupos exploram
        let categories = vec![
            ("SQL Injection", vec!["SQL Injection"]),
            ("Command Injection", vec!["Command Injection", "Remote Code Execution"]),
            ("Local File Inclusion (LFI)", vec!["Local File Inclusion (LFI)", "File Upload Vulnerabilities", "Remote Code Execution"]),
            ("Cross-Site Scripting (XSS)", vec!["Remote Code Execution"]), // XSS raramente leva direto a ransomware, só em casos combinados
            ("Open Redirect", vec!["Authentication Bypass"]),
            ("Cross-Site Request Forgery (CSRF)", vec!["Authentication Bypass"]),
            ("XML External Entity (XXE)", vec!["Local File Inclusion (LFI)", "Remote Code Execution"]),
            ("LDAP Injection", vec!["SQL Injection", "Authentication Bypass"]),
            ("Host Header Injection", vec!["Authentication Bypass", "Remote Code Execution"]),
            ("Portas Abertas", vec!["Remote Access Exposure (RDP/VPN)"]),
        ];

        for (vuln_prefix, accepted) in &categories {
            if name.starts_with(vuln_prefix) && accepted.iter().any(|cat| group.exploited_vuln_types.contains(&cat.to_string())) {
                return true;
            }
        }
        false
    }

    /// Prioridade 0-100:
    ///   base de severidade (Crítica=40, Alta=30, Média=20, Baixa=10, Info=5)
    ///   + 15 por vulnerabilidade correlacionada (teto 30)
    ///   + 10 se grupo já publicou organizações brasileiras
    ///   + 5 por 20+ vítimas publicadas (teto 15)
    fn compute_risk(severity: &Severity, matched_count: usize, victims: u32, brazil_flagged: bool) -> u8 {
        let base = match severity {
            Severity::Critical => 40u8,
            Severity::High => 30,
            Severity::Medium => 20,
            Severity::Low => 10,
            Severity::Info => 5,
        };
        let exposure = ((matched_count as u8).min(2)) * 15;
        let brazil = if brazil_flagged { 10u8 } else { 0 };
        let scale = (victims / 20).min(3) as u8 * 5;
        (base + exposure + brazil + scale).min(100)
    }

    fn recommendations(correlations: &[GroupCorrelation]) -> Vec<String> {
        let mut recs = Vec::new();
        if correlations.is_empty() {
            recs.push("Nenhuma vulnerabilidade detectada casou com o perfil de exploração dos grupos monitorados. Manter varreduras periódicas.".to_string());
            return recs;
        }

        let any_critical = correlations.iter().any(|c| c.max_severity == Severity::Critical);
        if any_critical {
            recs.push("Prioridade 1: corrigir imediatamente as vulnerabilidades críticas correlacionadas — grupos como DireWolf e Devman exploram esse padrão para acesso inicial e exfiltração antes da criptografia.".to_string());
        }

        let any_brazil = correlations.iter().any(|c| c.group.brazil_flagged);
        if any_brazil {
            recs.push("Prioridade 2: grupos que já publicaram organizações brasileiras (DireWolf, Devman, Vect) estão ativos. Monitorar os leak sites (Proven Data) e preparar plano de resposta a incidente com foco em dupla extorsão.".to_string());
        }

        recs.push("Prioridade 3: verificar no feed CISA KEV se o software exposto possui CVEs com exploração ativa e aplicar patches prioritariamente.".to_string());
        recs.push("Prioridade 4: validar controles de exfiltração (DLP), segmentação de rede e backups imutáveis — a criptografia é secundária; o prejuízo real vem do vazamento de dados.".to_string());
        recs
    }
}
