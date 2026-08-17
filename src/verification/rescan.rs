use crate::evidence::VulnerabilityEvidence;
use std::time::Duration;
use tokio::time::sleep;

pub struct Rescanner;

impl Rescanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn rescan_target(&self, _target: &str, _timeout_secs: u64) -> Vec<VulnerabilityEvidence> {
        // Aguarda um pouco antes de re-escanear
        sleep(Duration::from_secs(2)).await;
        
        // Em um cenário real, isso re-executaria o scan completo
        // Aqui retornamos vazio como placeholder
        Vec::new()
    }

    pub fn compare_results(
        &self,
        before: &[VulnerabilityEvidence],
        after: &[VulnerabilityEvidence],
    ) -> ComparisonResult {
        let before_count = before.len();
        let after_count = after.len();
        
        let fixed = before_count.saturating_sub(after_count);
        let new_vulnerabilities = after_count.saturating_sub(before_count);
        
        ComparisonResult {
            before_count,
            after_count,
            fixed_count: fixed,
            new_vulnerabilities,
            is_fully_fixed: after_count == 0 && before_count > 0,
        }
    }
}

pub struct ComparisonResult {
    pub before_count: usize,
    pub after_count: usize,
    pub fixed_count: usize,
    pub new_vulnerabilities: usize,
    pub is_fully_fixed: bool,
}

impl ComparisonResult {
    pub fn display(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("=== 🔄 COMPARAÇÃO ANTES/DEPOIS ===\n"));
        output.push_str(&format!("Antes: {} vulnerabilidades\n", self.before_count));
        output.push_str(&format!("Depois: {} vulnerabilidades\n", self.after_count));
        output.push_str(&format!("Corrigidas: {}\n", self.fixed_count));
        output.push_str(&format!("Novas: {}\n", self.new_vulnerabilities));
        
        if self.is_fully_fixed {
            output.push_str("✅ TODAS AS VULNERABILIDADES FORAM CORRIGIDAS!\n");
        }
        
        output
    }
}

impl Default for Rescanner {
    fn default() -> Self {
        Self::new()
    }
}