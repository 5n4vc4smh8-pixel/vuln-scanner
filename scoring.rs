use crate::evidence::VulnerabilityEvidence;

pub fn calculate_cvss(evidence: &VulnerabilityEvidence) -> f32 {
    let base_score = match evidence.vulnerability_id.as_str() {
        "SQLI-001" => 9.8,
        "CMD-001" => 9.8,
        "XXE-001" => 9.1,
        "LFI-001" => 8.8,
        "XSS-001" => 7.5,
        "LDAP-001" => 7.5,
        "HOST-001" => 7.5,
        "OPEN-001" => 6.1,
        "CSRF-001" => 6.5,
        "WAF-001" => 0.0,
        "PORT-001" => 3.7,
        _ => 5.0,
    };

    // Ajusta baseado na confiança
    let confidence_factor = evidence.confidence as f32 / 10.0;
    let adjusted_score = base_score * (0.7 + (0.3 * confidence_factor));

    // Ajusta baseado no risco de falso positivo
    let fp_factor = 1.0 - (evidence.false_positive_risk as f32 / 200.0);
    
    (adjusted_score * fp_factor).min(10.0)
}

pub fn generate_cvss_vector(evidence: &VulnerabilityEvidence) -> String {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        "CMD-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        "XXE-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
        "LFI-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
        "XSS-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string(),
        "LDAP-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string(),
        "HOST-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N".to_string(),
        "OPEN-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string(),
        "CSRF-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N".to_string(),
        "PORT-001" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
        _ => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N".to_string(),
    }
}

pub fn calculate_impact_score(evidence: &VulnerabilityEvidence) -> f32 {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => 9.0,
        "CMD-001" => 9.0,
        "XXE-001" => 8.0,
        "LFI-001" => 7.0,
        "XSS-001" => 5.0,
        "LDAP-001" => 8.0,
        "HOST-001" => 6.0,
        "OPEN-001" => 4.0,
        "CSRF-001" => 5.0,
        "PORT-001" => 2.0,
        _ => 3.0,
    }
}

pub fn calculate_exploitability_score(evidence: &VulnerabilityEvidence) -> f32 {
    let base = match evidence.vulnerability_id.as_str() {
        "SQLI-001" => 9.0,
        "CMD-001" => 8.0,
        "XXE-001" => 7.0,
        "LFI-001" => 8.0,
        "XSS-001" => 8.0,
        "LDAP-001" => 6.0,
        "HOST-001" => 7.0,
        "OPEN-001" => 9.0,
        "CSRF-001" => 7.0,
        "PORT-001" => 9.0,
        _ => 5.0,
    };

    let confidence_factor = evidence.confidence as f32 / 10.0;
    base * confidence_factor
}