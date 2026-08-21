use super::VerificationResult;
use crate::evidence::VulnerabilityEvidence;
use chrono::Utc;

pub struct TestRunner;

impl TestRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_vulnerability(&self, evidence: &VulnerabilityEvidence, attempt: u32) -> VerificationResult {
        // Simula a verificação da vulnerabilidade
        // Em um cenário real, isso re-executaria o teste
        let verified = evidence.confidence >= 5;
        
        VerificationResult {
            vulnerability_id: evidence.vulnerability_id.clone(),
            vulnerability_name: evidence.vulnerability_name.clone(),
            verified,
            proof_of_vulnerability: if verified {
                format!(
                    "Vulnerabilidade confirmada via {} no endpoint {} usando payload: {}",
                    evidence.http_method,
                    evidence.endpoint,
                    evidence.payload_used
                )
            } else {
                "Não foi possível confirmar a vulnerabilidade".to_string()
            },
            proof_of_fix: None,
            verification_timestamp: Utc::now(),
            attempts: attempt,
            confidence: evidence.confidence,
        }
    }

    pub fn verify_fix(&self, evidence: &VulnerabilityEvidence) -> Option<String> {
        // Simula a verificação de correção
        // Em um cenário real, isso re-executaria o teste após o fix
        if evidence.confidence < 3 {
            Some(format!(
                "Correção confirmada: {} não é mais vulnerável no endpoint {}",
                evidence.vulnerability_name,
                evidence.endpoint
            ))
        } else {
            None
        }
    }
}

impl Default for TestRunner {
    fn default() -> Self {
        Self::new()
    }
}