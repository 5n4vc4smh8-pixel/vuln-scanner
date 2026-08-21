pub mod collector;
pub mod context;
pub mod storage;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityEvidence {
    pub vulnerability_id: String,
    pub vulnerability_name: String,
    pub severity: String,
    pub cwe: Option<String>,
    pub cvss_score: f32,
    pub confidence: u8,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub http_method: String,
    pub payload_used: String,
    pub response_code: u16,
    pub response_body_snippet: String,
    pub response_headers: Vec<(String, String)>,
    pub stack_technology: Option<String>,
    pub framework: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub false_positive_risk: u8,
    pub remediation_complexity: String,
    pub evidence_type: EvidenceType,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceType {
    SqlInjection,
    Xss,
    Lfi,
    CommandInjection,
    Csrf,
    Xxe,
    LdapInjection,
    HostHeaderInjection,
    OpenRedirect,
    WafDetection,
    PortScan,
    InformationDisclosure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCollection {
    pub vulnerabilities: Vec<VulnerabilityEvidence>,
    pub scan_metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub target: String,
    pub scan_start: DateTime<Utc>,
    pub scan_end: DateTime<Utc>,
    pub total_requests: u32,
    pub total_vulnerabilities: u32,
    pub average_confidence: f32,
    pub high_confidence_count: u32,
    pub medium_confidence_count: u32,
    pub low_confidence_count: u32,
}

impl Default for VulnerabilityEvidence {
    fn default() -> Self {
        Self {
            vulnerability_id: String::new(),
            vulnerability_name: String::new(),
            severity: String::new(),
            cwe: None,
            cvss_score: 0.0,
            confidence: 0,
            endpoint: String::new(),
            parameter: None,
            http_method: "GET".to_string(),
            payload_used: String::new(),
            response_code: 0,
            response_body_snippet: String::new(),
            response_headers: Vec::new(),
            stack_technology: None,
            framework: None,
            timestamp: Utc::now(),
            false_positive_risk: 0,
            remediation_complexity: "low".to_string(),
            evidence_type: EvidenceType::InformationDisclosure,
            correlation_id: None,
        }
    }
}

impl VulnerabilityEvidence {
    pub fn new(
        vulnerability_id: &str,
        vulnerability_name: &str,
        severity: &str,
        evidence_type: EvidenceType,
    ) -> Self {
        Self {
            vulnerability_id: vulnerability_id.to_string(),
            vulnerability_name: vulnerability_name.to_string(),
            severity: severity.to_string(),
            evidence_type,
            ..Default::default()
        }
    }

    pub fn with_cwe(mut self, cwe: &str) -> Self {
        if !cwe.is_empty() {
            self.cwe = Some(cwe.to_string());
        }
        self
    }

    pub fn with_cvss(mut self, cvss: f32) -> Self {
        self.cvss_score = cvss;
        self
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = endpoint.to_string();
        self
    }

    pub fn with_parameter(mut self, parameter: &str) -> Self {
        if !parameter.is_empty() {
            self.parameter = Some(parameter.to_string());
        }
        self
    }

    pub fn with_http_method(mut self, method: &str) -> Self {
        self.http_method = method.to_string();
        self
    }

    pub fn with_payload(mut self, payload: &str) -> Self {
        self.payload_used = payload.to_string();
        self
    }

    pub fn with_response_code(mut self, code: u16) -> Self {
        self.response_code = code;
        self
    }

    pub fn with_response_body(mut self, body: &str, snippet_size: usize) -> Self {
        self.response_body_snippet = if body.len() > snippet_size {
            body[..snippet_size].to_string()
        } else {
            body.to_string()
        };
        self
    }

    pub fn with_response_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.response_headers = headers;
        self
    }

    pub fn with_stack_technology(mut self, stack: &str) -> Self {
        self.stack_technology = Some(stack.to_string());
        self
    }

    pub fn with_framework(mut self, framework: &str) -> Self {
        self.framework = Some(framework.to_string());
        self
    }

    pub fn with_false_positive_risk(mut self, risk: u8) -> Self {
        self.false_positive_risk = risk;
        self
    }

    pub fn with_remediation_complexity(mut self, complexity: &str) -> Self {
        self.remediation_complexity = complexity.to_string();
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: &str) -> Self {
        self.correlation_id = Some(correlation_id.to_string());
        self
    }

    pub fn calculate_false_positive_risk(&mut self) {
        let mut risk = 0;

        if self.confidence < 3 {
            risk += 30;
        } else if self.confidence < 5 {
            risk += 15;
        }

        if self.payload_used.contains("test") || self.payload_used.contains("teste") {
            risk += 10;
        }

        if self.cwe.is_none() {
            risk += 10;
        }

        if self.response_body_snippet.is_empty() {
            risk += 20;
        }

        if self.parameter.is_none() && self.evidence_type != EvidenceType::WafDetection {
            risk += 10;
        }

        self.false_positive_risk = risk.min(100);
    }
}