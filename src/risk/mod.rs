pub mod scoring;
pub mod prioritization;
pub mod false_positive;

use serde::{Deserialize, Serialize};
use crate::evidence::VulnerabilityEvidence;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub vulnerability_id: String,
    pub cvss_score: f32,
    pub cvss_vector: String,
    pub risk_level: RiskLevel,
    pub priority: u8,
    pub impact_score: f32,
    pub exploitability_score: f32,
    pub business_impact: String,
    pub recommended_action: String,
    pub sla_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn from_cvss(cvss: f32) -> Self {
        match cvss {
            cvss if cvss >= 9.0 => RiskLevel::Critical,
            cvss if cvss >= 7.0 => RiskLevel::High,
            cvss if cvss >= 4.0 => RiskLevel::Medium,
            cvss if cvss >= 0.1 => RiskLevel::Low,
            _ => RiskLevel::Info,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            RiskLevel::Critical => "Critical".to_string(),
            RiskLevel::High => "High".to_string(),
            RiskLevel::Medium => "Medium".to_string(),
            RiskLevel::Low => "Low".to_string(),
            RiskLevel::Info => "Info".to_string(),
        }
    }
}

impl RiskAssessment {
    pub fn new(evidence: &VulnerabilityEvidence) -> Self {
        let cvss_score = scoring::calculate_cvss(evidence);
        let cvss_vector = scoring::generate_cvss_vector(evidence);
        let risk_level = RiskLevel::from_cvss(cvss_score);
        let priority = prioritization::calculate_priority(evidence, cvss_score);
        let impact_score = scoring::calculate_impact_score(evidence);
        let exploitability_score = scoring::calculate_exploitability_score(evidence);
        let business_impact = prioritization::assess_business_impact(evidence);
        let recommended_action = prioritization::recommend_action(evidence, &risk_level);
        let sla_hours = prioritization::calculate_sla(&risk_level);

        Self {
            vulnerability_id: evidence.vulnerability_id.clone(),
            cvss_score,
            cvss_vector,
            risk_level,
            priority,
            impact_score,
            exploitability_score,
            business_impact,
            recommended_action,
            sla_hours,
        }
    }

    pub fn is_critical(&self) -> bool {
        self.risk_level == RiskLevel::Critical
    }

    pub fn is_high_priority(&self) -> bool {
        self.priority >= 8
    }

    pub fn get_sla_description(&self) -> String {
        match self.sla_hours {
            0 => "Imediato (0 horas)".to_string(),
            24 => "Urgente (24 horas)".to_string(),
            72 => "Alta prioridade (72 horas)".to_string(),
            168 => "Média prioridade (1 semana)".to_string(),
            _ => format!("{} horas", self.sla_hours),
        }
    }
}