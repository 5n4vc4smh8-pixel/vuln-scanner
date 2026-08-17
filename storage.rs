use super::{EvidenceCollection, VulnerabilityEvidence};
use std::fs;
use std::path::Path;
use chrono::Utc;
use log::info;

pub struct EvidenceStorage {
    base_path: String,
}

impl EvidenceStorage {
    pub fn new(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
        }
    }

    pub fn save_evidence_collection(&self, collection: &EvidenceCollection) -> Result<String, Box<dyn std::error::Error>> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("evidence_{}.json", timestamp);
        let full_path = format!("{}/{}", self.base_path, filename);

        if let Some(parent) = Path::new(&full_path).parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(collection)?;
        fs::write(&full_path, json)?;

        info!("💾 Evidências salvas em: {}", full_path);
        Ok(full_path)
    }

    pub fn load_evidence_collection(&self, filename: &str) -> Result<EvidenceCollection, Box<dyn std::error::Error>> {
        let full_path = format!("{}/{}", self.base_path, filename);
        let content = fs::read_to_string(full_path)?;
        let collection: EvidenceCollection = serde_json::from_str(&content)?;
        Ok(collection)
    }

    pub fn list_evidence_files(&self) -> Vec<String> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.starts_with("evidence_") && filename.ends_with(".json") {
                        files.push(filename.to_string());
                    }
                }
            }
        }
        files.sort();
        files.reverse();
        files
    }

    pub fn get_latest_evidence(&self) -> Option<EvidenceCollection> {
        let files = self.list_evidence_files();
        if let Some(latest) = files.first() {
            self.load_evidence_collection(latest).ok()
        } else {
            None
        }
    }

    pub fn export_vulnerability_details(&self, evidence: &VulnerabilityEvidence) -> String {
        let mut details = String::new();
        details.push_str(&format!("=== {} ===\n", evidence.vulnerability_name));
        details.push_str(&format!("ID: {}\n", evidence.vulnerability_id));
        details.push_str(&format!("Severidade: {}\n", evidence.severity));
        details.push_str(&format!("Confiança: {}%\n", evidence.confidence * 10));
        details.push_str(&format!("Risco de Falso Positivo: {}%\n", evidence.false_positive_risk));
        
        if let Some(cwe) = &evidence.cwe {
            details.push_str(&format!("CWE: {}\n", cwe));
        }
        
        details.push_str(&format!("CVSS: {:.1}\n", evidence.cvss_score));
        details.push_str(&format!("Endpoint: {}\n", evidence.endpoint));
        
        if let Some(param) = &evidence.parameter {
            details.push_str(&format!("Parâmetro: {}\n", param));
        }
        
        details.push_str(&format!("Método HTTP: {}\n", evidence.http_method));
        details.push_str(&format!("Payload: {}\n", evidence.payload_used));
        details.push_str(&format!("Código de Resposta: {}\n", evidence.response_code));
        details.push_str(&format!("Complexidade de Correção: {}\n", evidence.remediation_complexity));
        
        if !evidence.response_body_snippet.is_empty() {
            details.push_str("\n--- Trecho da Resposta ---\n");
            details.push_str(&evidence.response_body_snippet);
            details.push_str("\n");
        }

        details
    }
}