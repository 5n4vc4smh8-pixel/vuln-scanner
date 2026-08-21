#![allow(dead_code)]
/// Consulta ao catálogo CISA KEV (Known Exploited Vulnerabilities).
///
/// Fonte oficial: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
/// JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
/// Contém CVEs com evidência de exploração ativa — os mais relevantes para priorizar remediação.
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisaKevEntry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub cwe: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevCatalog {
    pub catalog_version: String,
    pub date_retrieved: String,
    pub total_entries: usize,
    pub entries: Vec<CisaKevEntry>,
}

impl KevCatalog {
    /// Baixa o feed CISA KEV. Em caso de falha (rede, proxy, indisponibilidade),
    /// retorna None — o módulo continua funcionando com a base estática de grupos.
    pub async fn fetch(timeout_secs: u64) -> Option<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs.max(10)))
            .danger_accept_invalid_certs(false)
            .build()
            .ok()?;

        let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        // FIX v6: retry x3 com backoff (3s) — feeds de governo frequentemente falham de
        // forma intermitente (rate limit, TLS handshake, DNS); degrada para grupos apenas
        // só depois de esgotar as tentativas
        let mut json: Option<serde_json::Value> = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            if let Ok(resp) = client.get(url).send().await {
                if let Ok(j) = resp.json::<serde_json::Value>().await {
                    json = Some(j);
                    break;
                }
            }
        }
        let json = json?;

        let version = json.get("catalogVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("desconhecida")
            .to_string();

        let vulnerabilities = json.get("vulnerabilities")?.as_array()?;
        let now = chrono::Local::now().format("%Y-%m-%d").to_string();

        let mut entries = Vec::new();
        for item in vulnerabilities {
            if let (Some(id), Some(vendor), Some(product), Some(name), Some(added), Some(desc)) = (
                item.get("cveID").and_then(|v| v.as_str()),
                item.get("vendor").and_then(|v| v.as_str()),
                item.get("product").and_then(|v| v.as_str()),
                item.get("shortDescription").and_then(|v| v.as_str()),
                item.get("dateAdded").and_then(|v| v.as_str()),
                item.get("longDescription").and_then(|v| v.as_str()),
            ) {
                let cwe = item.get("cwe")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_else(|| "N/A".to_string());

                entries.push(CisaKevEntry {
                    cve_id: id.to_string(),
                    vendor: vendor.to_string(),
                    product: product.to_string(),
                    vulnerability_name: name.to_string(),
                    date_added: added.to_string(),
                    cwe,
                    description: desc.to_string(),
                });
            }
        }

        // FIX v6.1: o catálogo oficial sempre tem 1000+ CVEs. Se o parse do JSON
        // funcionou mas veio 0 entradas, o conteúdo provavelmente é página de bloqueio
        // (firewall/proxy corporativo) — degradar para consulta manual
        if entries.is_empty() {
            return None;
        }
        Some(KevCatalog {
            catalog_version: version,
            date_retrieved: now,
            total_entries: entries.len(),
            entries,
        })
    }

    /// Prioriza os CVEs mais recentes e relevantes para infraestrutura web
    /// (servidores, aplicações web, software empresarial). Limita a `limit` entradas.
    pub fn prioritize_web_infra(&self, limit: usize) -> Vec<&CisaKevEntry> {
        let mut scored: Vec<(i32, &CisaKevEntry)> = self.entries.iter().map(|e| {
            let score = Self::relevance_score(e);
            (score, e)
        }).collect();

        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored.iter().take(limit).map(|(_, e)| *e).collect()
    }

    /// Filtra CVEs que casam com os produtos mencionados no contexto do alvo.
    pub fn match_products(&self, products: &[String], limit: usize) -> Vec<&CisaKevEntry> {
        let mut matched: Vec<&CisaKevEntry> = self.entries.iter().filter(|e| {
            let hay = format!("{} {} {}", e.vendor, e.product, e.vulnerability_name).to_lowercase();
            products.iter().any(|p| hay.contains(&p.to_lowercase()))
        }).collect();
        matched.sort_by(|a, b| b.date_added.cmp(&a.date_added));
        matched.truncate(limit);
        matched
    }

    /// CVEs adicionados ao catálogo nos últimos `days` dias.
    pub fn recent(&self, days: usize) -> Vec<&CisaKevEntry> {
        let cutoff = chrono::Local::now()
            .checked_sub_signed(chrono::Duration::days(days as i64))
            .map(|d| d.format("%Y-%m-%d").to_string());
        match cutoff {
            Some(cutoff) => self.entries.iter()
                .filter(|e| e.date_added >= cutoff)
                .collect(),
            None => vec![],
        }
    }

    fn relevance_score(e: &CisaKevEntry) -> i32 {
        let mut score = 0i32;
        let hay = format!("{} {} {}", e.vendor, e.product, e.vulnerability_name).to_lowercase();
        // Softwares alvos típicos de ransomware emergente
        if hay.contains("wordpress") || hay.contains("apache") || hay.contains("nginx") ||
           hay.contains("iis") || hay.contains("php") || hay.contains("java") || hay.contains("tomcat") {
            score += 3;
        }
        if hay.contains("microsoft") || hay.contains("windows") || hay.contains("sharepoint") ||
           hay.contains("sql") || hay.contains("exchange") || hay.contains("fortinet") ||
           hay.contains("vpn") || hay.contains("rce") {
            score += 2;
        }
        if hay.contains("linux") || hay.contains("esxi") || hay.contains("vmware") {
            score += 2;
        }
        // CVEs recentes valem mais (grupos emergentes exploram o que acabou de sair)
        if let Some(Ok(y)) = e.date_added.split('-').next().map(|y| y.parse::<i32>()) {
            if y >= 2026 { score += 2; } else if y >= 2025 { score += 1; }
        }
        score
    }
}
