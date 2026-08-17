use crate::evidence::VulnerabilityEvidence;

pub struct FalsePositiveAnalyzer;

impl FalsePositiveAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, evidence: &VulnerabilityEvidence) -> FPAnalysis {
        let mut risk_score = evidence.false_positive_risk;
        let mut reasons = Vec::new();

        // Análise de confiança
        if evidence.confidence < 3 {
            risk_score += 20;
            reasons.push("Baixa confiança na detecção".to_string());
        }

        // Análise de resposta
        if evidence.response_body_snippet.is_empty() {
            risk_score += 15;
            reasons.push("Resposta do servidor vazia".to_string());
        }

        // Análise de payload
        if evidence.payload_used.contains("test") || evidence.payload_used.contains("teste") {
            risk_score += 10;
            reasons.push("Payload genérico de teste".to_string());
        }

        // Análise de contexto
        if evidence.parameter.is_none() && evidence.vulnerability_id != "WAF-001" {
            risk_score += 10;
            reasons.push("Sem parâmetro vulnerável identificado".to_string());
        }

        let is_likely_false_positive = risk_score >= 50;
        let is_definite_false_positive = risk_score >= 80;

        FPAnalysis {
            risk_score: risk_score.min(100),
            is_likely_false_positive,
            is_definite_false_positive,
            reasons,
            recommendation: if is_definite_false_positive {
                "Descartar esta vulnerabilidade - muito provavelmente é falso positivo".to_string()
            } else if is_likely_false_positive {
                "Verificar manualmente antes de agir - possível falso positivo".to_string()
            } else {
                "Evidência confiável - proceder com a correção".to_string()
            },
        }
    }
}

pub struct FPAnalysis {
    pub risk_score: u8,
    pub is_likely_false_positive: bool,
    pub is_definite_false_positive: bool,
    pub reasons: Vec<String>,
    pub recommendation: String,
}