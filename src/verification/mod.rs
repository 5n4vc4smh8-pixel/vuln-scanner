pub mod test_runner;
pub mod rescan;
pub mod proof;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub vulnerability_id: String,
    pub vulnerability_name: String,
    pub verified: bool,
    pub proof_of_vulnerability: String,
    pub proof_of_fix: Option<String>,
    pub verification_timestamp: DateTime<Utc>,
    pub attempts: u32,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub target: String,
    pub scan_date: DateTime<Utc>,
    pub total_vulnerabilities: u32,
    pub verified_vulnerabilities: u32,
    pub fixed_vulnerabilities: u32,
    pub remaining_vulnerabilities: u32,
    pub results: Vec<VerificationResult>,
}

impl VerificationReport {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            scan_date: Utc::now(),
            total_vulnerabilities: 0,
            verified_vulnerabilities: 0,
            fixed_vulnerabilities: 0,
            remaining_vulnerabilities: 0,
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: VerificationResult) {
        if result.verified {
            self.verified_vulnerabilities += 1;
        }
        if result.proof_of_fix.is_some() {
            self.fixed_vulnerabilities += 1;
        }
        self.results.push(result);
    }

    pub fn display_summary(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("=== 📋 RELATÓRIO DE VERIFICAÇÃO ===\n"));
        output.push_str(&format!("Alvo: {}\n", self.target));
        output.push_str(&format!("Data: {}\n", self.scan_date.format("%Y-%m-%d %H:%M:%S")));
        output.push_str(&format!("Total de vulnerabilidades: {}\n", self.total_vulnerabilities));
        output.push_str(&format!("Verificadas: {}\n", self.verified_vulnerabilities));
        output.push_str(&format!("Corrigidas: {}\n", self.fixed_vulnerabilities));
        output.push_str(&format!("Restantes: {}\n", self.remaining_vulnerabilities));
        output
    }
}