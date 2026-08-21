use std::collections::HashMap;

pub struct AiConfidence {
    weights: HashMap<String, f32>,
    threshold: f32,
}

impl AiConfidence {
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        
        weights.insert("sql".to_string(), 0.8);
        weights.insert("xss".to_string(), 0.9);
        weights.insert("lfi".to_string(), 0.7);
        weights.insert("nosql".to_string(), 0.75);
        weights.insert("ssti".to_string(), 0.7);
        weights.insert("ssrf".to_string(), 0.65);
        weights.insert("cmd".to_string(), 0.8);
        weights.insert("xxe".to_string(), 0.7);
        weights.insert("csrf".to_string(), 0.6);
        weights.insert("idor".to_string(), 0.55);
        weights.insert("ldap".to_string(), 0.7);
        weights.insert("open".to_string(), 0.6);
        weights.insert("host".to_string(), 0.6);
        
        Self {
            weights,
            threshold: 0.6,
        }
    }
    
    pub fn calculate_confidence(&self, vuln_type: &str, indicators: &[String], body: &str) -> f32 {
        let base_weight = *self.weights.get(vuln_type).unwrap_or(&0.5);
        let body_lower = body.to_lowercase();
        
        let mut found = 0;
        for indicator in indicators {
            if body_lower.contains(indicator) {
                found += 1;
            }
        }
        
        let total = indicators.len();
        let hit_ratio = if total > 0 { found as f32 / total as f32 } else { 0.0 };
        
        let confidence = base_weight * (0.5 + 0.5 * hit_ratio);
        confidence.min(1.0)
    }
    
    pub fn should_report(&self, confidence: f32) -> bool {
        confidence >= self.threshold
    }
    
    pub fn confidence_level(confidence: f32) -> String {
        if confidence >= 0.85 {
            "Alta".to_string()
        } else if confidence >= 0.7 {
            "Média".to_string()
        } else if confidence >= 0.5 {
            "Baixa".to_string()
        } else {
            "Muito Baixa".to_string()
        }
    }
}