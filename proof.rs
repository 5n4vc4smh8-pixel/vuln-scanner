use super::VerificationReport;
use crate::evidence::VulnerabilityEvidence;
use chrono::Utc;
use std::fs;
use std::path::Path;

pub struct ProofGenerator;

impl ProofGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_proof_of_fix(
        &self,
        evidence: &VulnerabilityEvidence,
        fix_description: &str,
    ) -> ProofOfFix {
        ProofOfFix {
            vulnerability_id: evidence.vulnerability_id.clone(),
            vulnerability_name: evidence.vulnerability_name.clone(),
            endpoint: evidence.endpoint.clone(),
            parameter: evidence.parameter.clone(),
            original_payload: evidence.payload_used.clone(),
            fix_description: fix_description.to_string(),
            proof_timestamp: Utc::now(),
            verified_by: "VulnScanner Verification Engine".to_string(),
        }
    }

    pub fn save_proof_report(
        &self,
        report: &VerificationReport,
        output_path: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("proof_of_fix_{}.json", timestamp);
        let full_path = format!("{}/{}", output_path, filename);

        if let Some(parent) = Path::new(&full_path).parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(report)?;
        fs::write(&full_path, json)?;

        Ok(full_path)
    }
}

pub struct ProofOfFix {
    pub vulnerability_id: String,
    pub vulnerability_name: String,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub original_payload: String,
    pub fix_description: String,
    pub proof_timestamp: chrono::DateTime<Utc>,
    pub verified_by: String,
}

impl ProofOfFix {
    pub fn display(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("=== ✅ PROVA DE CORREÇÃO ===\n"));
        output.push_str(&format!("Vulnerabilidade: {}\n", self.vulnerability_name));
        output.push_str(&format!("ID: {}\n", self.vulnerability_id));
        output.push_str(&format!("Endpoint: {}\n", self.endpoint));
        
        if let Some(param) = &self.parameter {
            output.push_str(&format!("Parâmetro: {}\n", param));
        }
        
        output.push_str(&format!("Payload original: {}\n", self.original_payload));
        output.push_str(&format!("Correção: {}\n", self.fix_description));
        output.push_str(&format!("Data: {}\n", self.proof_timestamp.format("%Y-%m-%d %H:%M:%S")));
        output.push_str(&format!("Verificado por: {}\n", self.verified_by));
        output
    }
}

impl Default for ProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}