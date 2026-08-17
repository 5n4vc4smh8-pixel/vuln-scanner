pub mod explainer;
pub mod patch_gen;
pub mod code_fix;

use serde::{Deserialize, Serialize};
use crate::evidence::VulnerabilityEvidence;
use crate::risk::RiskAssessment;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub vulnerability_id: String,
    pub vulnerability_name: String,
    pub explanation: String,
    pub root_cause: String,
    pub code_before: String,
    pub code_after: String,
    pub patch_diff: String,
    pub language: String,
    pub framework: String,
    pub complexity: String,
    pub estimated_time: String,
    pub steps: Vec<RemediationStep>,
    pub verification_required: bool,
    pub automated_fix_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub step_number: u8,
    pub action: String,
    pub code_snippet: Option<String>,
    pub description: String,
}

impl RemediationPlan {
    pub fn new(evidence: &VulnerabilityEvidence, _risk: &RiskAssessment) -> Self {
        let explanation = explainer::explain_vulnerability(evidence);
        let root_cause = explainer::identify_root_cause(evidence);
        let (code_before, code_after) = patch_gen::generate_patch(evidence);
        let patch_diff = patch_gen::generate_diff(&code_before, &code_after);
        let language = patch_gen::detect_language(evidence);
        let framework = patch_gen::detect_framework(evidence);
        let complexity = evidence.remediation_complexity.clone();
        let estimated_time = patch_gen::estimate_time(&complexity);
        let steps = code_fix::generate_steps(evidence);
        let verification_required = true;
        let automated_fix_available = patch_gen::can_auto_fix(evidence);

        Self {
            vulnerability_id: evidence.vulnerability_id.clone(),
            vulnerability_name: evidence.vulnerability_name.clone(),
            explanation,
            root_cause,
            code_before,
            code_after,
            patch_diff,
            language,
            framework,
            complexity,
            estimated_time,
            steps,
            verification_required,
            automated_fix_available,
        }
    }

    pub fn display_plan(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("=== 🛠️ PLANO DE CORREÇÃO: {} ===\n\n", self.vulnerability_name));
        output.push_str(&format!("📝 Explicação: {}\n", self.explanation));
        output.push_str(&format!("🔍 Causa Raiz: {}\n", self.root_cause));
        output.push_str(&format!("💻 Linguagem: {}\n", self.language));
        output.push_str(&format!("🏗️ Framework: {}\n", self.framework));
        output.push_str(&format!("⏱️ Tempo estimado: {}\n", self.estimated_time));
        output.push_str(&format!("🤖 Correção automática: {}\n\n", 
            if self.automated_fix_available { "Sim" } else { "Não" }));

        output.push_str("=== 📄 CÓDIGO ANTES ===\n");
        output.push_str(&self.code_before);
        output.push_str("\n\n=== ✅ CÓDIGO DEPOIS ===\n");
        output.push_str(&self.code_after);
        output.push_str("\n\n=== 📊 DIFF ===\n");
        output.push_str(&self.patch_diff);
        output.push_str("\n\n=== 📋 PASSOS ===\n");

        for step in &self.steps {
            output.push_str(&format!("{}. {}\n", step.step_number, step.action));
            if let Some(snippet) = &step.code_snippet {
                output.push_str(&format!("   ```\n   {}\n   ```\n", snippet));
            }
        }

        output.push_str("\n=== ✅ VERIFICAÇÃO NECESSÁRIA ===\n");
        output.push_str("Após aplicar a correção, execute o scanner novamente para verificar.\n");

        output
    }
}