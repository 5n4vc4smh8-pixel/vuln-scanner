use crate::evidence::VulnerabilityEvidence;
use super::RiskLevel;

pub fn calculate_priority(evidence: &VulnerabilityEvidence, cvss_score: f32) -> u8 {
    let mut priority = 0.0;

    // CVSS Score (peso 40%)
    priority += cvss_score * 4.0;

    // Confiança (peso 30%)
    priority += evidence.confidence as f32 * 3.0;

    // Impacto no negócio (peso 30%)
    let business_impact = match evidence.vulnerability_id.as_str() {
        "SQLI-001" => 10.0,
        "CMD-001" => 10.0,
        "XXE-001" => 9.0,
        "LFI-001" => 8.0,
        "XSS-001" => 6.0,
        "LDAP-001" => 8.0,
        "HOST-001" => 7.0,
        "OPEN-001" => 4.0,
        "CSRF-001" => 5.0,
        "PORT-001" => 3.0,
        _ => 5.0,
    };
    priority += business_impact * 3.0;

    (priority / 10.0).min(10.0) as u8
}

pub fn assess_business_impact(evidence: &VulnerabilityEvidence) -> String {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => "Acesso não autorizado a dados sensíveis".to_string(),
        "CMD-001" => "Execução remota de código no servidor".to_string(),
        "XXE-001" => "Leitura de arquivos internos do servidor".to_string(),
        "LFI-001" => "Acesso a arquivos do sistema".to_string(),
        "XSS-001" => "Roubo de sessão e dados do usuário".to_string(),
        "LDAP-001" => "Bypass de autenticação".to_string(),
        "HOST-001" => "Envenenamento de cache e redirecionamento".to_string(),
        "OPEN-001" => "Phishing e redirecionamento malicioso".to_string(),
        "CSRF-001" => "Ações não autorizadas em nome do usuário".to_string(),
        "PORT-001" => "Exposição de serviços internos".to_string(),
        _ => "Impacto moderado na aplicação".to_string(),
    }
}

pub fn recommend_action(evidence: &VulnerabilityEvidence, risk_level: &RiskLevel) -> String {
    match risk_level {
        RiskLevel::Critical => format!("Ação imediata: Corrigir {} usando {}", 
            evidence.vulnerability_name, 
            get_remediation_suggestion(&evidence.vulnerability_id)),
        RiskLevel::High => format!("Alta prioridade: Implementar correção para {} em até 24 horas", 
            evidence.vulnerability_name),
        RiskLevel::Medium => format!("Média prioridade: Planejar correção para {} em até 1 semana", 
            evidence.vulnerability_name),
        RiskLevel::Low => format!("Baixa prioridade: Monitorar e corrigir {} quando possível", 
            evidence.vulnerability_name),
        RiskLevel::Info => "Informação: Nenhuma ação imediata necessária".to_string(),
    }
}

pub fn calculate_sla(risk_level: &RiskLevel) -> u32 {
    match risk_level {
        RiskLevel::Critical => 0,    // Imediato
        RiskLevel::High => 24,       // 24 horas
        RiskLevel::Medium => 72,     // 72 horas
        RiskLevel::Low => 168,       // 1 semana
        RiskLevel::Info => 720,      // 30 dias
    }
}

fn get_remediation_suggestion(vuln_id: &str) -> String {
    match vuln_id {
        "SQLI-001" => "prepared statements e input validation".to_string(),
        "CMD-001" => "APIs seguras e sanitização de input".to_string(),
        "XXE-001" => "desabilitar entities externas no parser XML".to_string(),
        "LFI-001" => "whitelist de arquivos permitidos".to_string(),
        "XSS-001" => "output encoding e Content Security Policy".to_string(),
        "LDAP-001" => "escape de caracteres especiais".to_string(),
        "HOST-001" => "validação do header Host contra whitelist".to_string(),
        "OPEN-001" => "validação de URLs de redirecionamento".to_string(),
        "CSRF-001" => "tokens CSRF em todos os formulários".to_string(),
        "PORT-001" => "firewall e fechamento de portas desnecessárias".to_string(),
        _ => "boas práticas de segurança".to_string(),
    }
}