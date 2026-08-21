use super::{VulnerabilityEvidence, EvidenceType, EvidenceCollection, ScanMetadata};
use crate::scanner::DetectedVuln;
use chrono::Utc;
use log::info;

pub struct EvidenceCollector {
    evidences: Vec<VulnerabilityEvidence>,
}

impl EvidenceCollector {
    pub fn new() -> Self {
        Self {
            evidences: Vec::new(),
        }
    }

    pub fn collect_from_detected_vuln(
        &mut self,
        vuln: &DetectedVuln,
        http_method: &str,
        response_code: u16,
        response_body: &str,
        response_headers: Vec<(String, String)>,
    ) {
        let evidence_type = self.map_evidence_type(&vuln.vulnerability.id);
        
        let evidence = VulnerabilityEvidence::new(
            &vuln.vulnerability.id,
            &vuln.vulnerability.name,
            &format!("{:?}", vuln.vulnerability.severity),
            evidence_type,
        )
        .with_cwe(vuln.vulnerability.cwe.as_deref().unwrap_or(""))
        .with_confidence(self.calculate_confidence(vuln))
        .with_endpoint(&vuln.url)
        .with_parameter(vuln.parameter.as_deref().unwrap_or(""))
        .with_http_method(http_method)
        .with_payload(&vuln.evidence)
        .with_response_code(response_code)
        .with_response_body(response_body, 500)
        .with_response_headers(response_headers)
        .with_false_positive_risk(0)
        .with_remediation_complexity(&self.calculate_complexity(&vuln.vulnerability.name));

        let mut evidence = evidence;
        evidence.calculate_false_positive_risk();

        info!(
            "📊 Evidência coletada: {} (confiança: {}%, risco FP: {}%)",
            evidence.vulnerability_name,
            evidence.confidence * 10,
            evidence.false_positive_risk
        );

        self.evidences.push(evidence);
    }

    fn map_evidence_type(&self, vuln_id: &str) -> EvidenceType {
        match vuln_id {
            "SQLI-001" => EvidenceType::SqlInjection,
            "XSS-001" => EvidenceType::Xss,
            "LFI-001" => EvidenceType::Lfi,
            "CMD-001" => EvidenceType::CommandInjection,
            "CSRF-001" => EvidenceType::Csrf,
            "XXE-001" => EvidenceType::Xxe,
            "LDAP-001" => EvidenceType::LdapInjection,
            "HOST-001" => EvidenceType::HostHeaderInjection,
            "OPEN-001" => EvidenceType::OpenRedirect,
            "WAF-001" => EvidenceType::WafDetection,
            "PORT-001" => EvidenceType::PortScan,
            _ => EvidenceType::InformationDisclosure,
        }
    }

    fn calculate_confidence(&self, vuln: &DetectedVuln) -> u8 {
        let evidence = &vuln.evidence.to_lowercase();
        
        match vuln.vulnerability.id.as_str() {
            "SQLI-001" => {
                if evidence.contains("sql syntax") || evidence.contains("mysql") || evidence.contains("postgresql") {
                    9
                } else {
                    6
                }
            }
            "XSS-001" => {
                if evidence.contains("<script>") {
                    8
                } else {
                    5
                }
            }
            "LFI-001" => {
                if evidence.contains("root:x:") || evidence.contains("boot.ini") {
                    10
                } else {
                    7
                }
            }
            "CMD-001" => {
                if evidence.contains("uid=") || evidence.contains("system32") {
                    9
                } else {
                    6
                }
            }
            "XXE-001" => {
                if evidence.contains("root:x:") || evidence.contains("boot.ini") {
                    9
                } else {
                    7
                }
            }
            "LDAP-001" => {
                if evidence.contains("ldap") || evidence.contains("search") {
                    8
                } else {
                    6
                }
            }
            "HOST-001" => 7,
            "OPEN-001" => 8,
            "CSRF-001" => 6,
            "WAF-001" => 8,
            "PORT-001" => 10,
            _ => 5,
        }
    }

    fn calculate_complexity(&self, vuln_name: &str) -> String {
        match vuln_name {
            "SQL Injection" => "medium",
            "Cross-Site Scripting (XSS)" => "low",
            "Local File Inclusion (LFI)" => "medium",
            "Command Injection" => "high",
            "CSRF" => "low",
            "XXE" => "medium",
            "LDAP Injection" => "medium",
            "Host Header Injection" => "high",
            "Open Redirect" => "low",
            "WAF Detectado" => "informational",
            "Portas Abertas" => "low",
            _ => "medium",
        }.to_string()
    }

    pub fn get_evidence_collection(&self, target: &str) -> EvidenceCollection {
        let total = self.evidences.len() as u32;
        let total_confidence: u32 = self.evidences.iter().map(|e| e.confidence as u32).sum();
        let average_confidence = if total > 0 {
            total_confidence as f32 / total as f32
        } else {
            0.0
        };

        let high_confidence_count = self.evidences.iter().filter(|e| e.confidence >= 7).count() as u32;
        let medium_confidence_count = self.evidences.iter().filter(|e| e.confidence >= 4 && e.confidence < 7).count() as u32;
        let low_confidence_count = self.evidences.iter().filter(|e| e.confidence < 4).count() as u32;

        EvidenceCollection {
            vulnerabilities: self.evidences.clone(),
            scan_metadata: ScanMetadata {
                target: target.to_string(),
                scan_start: Utc::now(),
                scan_end: Utc::now(),
                total_requests: 0,
                total_vulnerabilities: total,
                average_confidence,
                high_confidence_count,
                medium_confidence_count,
                low_confidence_count,
            },
        }
    }

    pub fn get_high_confidence_evidences(&self) -> Vec<&VulnerabilityEvidence> {
        self.evidences.iter().filter(|e| e.confidence >= 7).collect()
    }

    pub fn get_medium_confidence_evidences(&self) -> Vec<&VulnerabilityEvidence> {
        self.evidences.iter().filter(|e| e.confidence >= 4 && e.confidence < 7).collect()
    }

    pub fn get_low_confidence_evidences(&self) -> Vec<&VulnerabilityEvidence> {
        self.evidences.iter().filter(|e| e.confidence < 4).collect()
    }

    pub fn get_false_positive_candidates(&self) -> Vec<&VulnerabilityEvidence> {
        self.evidences.iter().filter(|e| e.false_positive_risk >= 50).collect()
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}