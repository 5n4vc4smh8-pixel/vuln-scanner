use super::VulnerabilityEvidence;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct VulnerabilityContext {
    pub technology_stack: HashMap<String, String>,
    pub affected_components: Vec<String>,
    pub data_flow: Option<DataFlow>,
    pub security_controls: Vec<String>,
    pub related_vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DataFlow {
    pub source: String,
    pub sink: String,
    pub sanitization: Option<String>,
    pub validation: Option<String>,
}

pub struct ContextAnalyzer {
    contexts: HashMap<String, VulnerabilityContext>,
}

impl ContextAnalyzer {
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
        }
    }

    pub fn analyze_evidence(&mut self, evidence: &VulnerabilityEvidence) -> VulnerabilityContext {
        let mut context = VulnerabilityContext {
            technology_stack: self.detect_technology_stack(evidence),
            affected_components: self.identify_affected_components(evidence),
            data_flow: self.trace_data_flow(evidence),
            security_controls: self.identify_security_controls(evidence),
            related_vulnerabilities: Vec::new(),
        };

        if let Some(existing) = self.contexts.get(&evidence.endpoint) {
            context.related_vulnerabilities = existing.related_vulnerabilities.clone();
        }

        self.contexts.insert(evidence.endpoint.clone(), context.clone());
        context
    }

    fn detect_technology_stack(&self, evidence: &VulnerabilityEvidence) -> HashMap<String, String> {
        let mut stack = HashMap::new();
        
        for (header, value) in &evidence.response_headers {
            let header_lower = header.to_lowercase();
            let value_lower = value.to_lowercase();

            if header_lower.contains("x-powered-by") {
                if value_lower.contains("php") {
                    stack.insert("language".to_string(), "PHP".to_string());
                    stack.insert("framework".to_string(), "PHP".to_string());
                } else if value_lower.contains("asp.net") {
                    stack.insert("language".to_string(), "C#".to_string());
                    stack.insert("framework".to_string(), "ASP.NET".to_string());
                } else if value_lower.contains("express") {
                    stack.insert("language".to_string(), "JavaScript".to_string());
                    stack.insert("framework".to_string(), "Node.js/Express".to_string());
                } else {
                    stack.insert("language".to_string(), value_lower.clone());
                }
            }

            if header_lower.contains("server") {
                if value_lower.contains("nginx") {
                    stack.insert("web_server".to_string(), "Nginx".to_string());
                } else if value_lower.contains("apache") {
                    stack.insert("web_server".to_string(), "Apache".to_string());
                } else if value_lower.contains("iis") {
                    stack.insert("web_server".to_string(), "IIS".to_string());
                }
            }
        }

        let evidence_lower = evidence.payload_used.to_lowercase();
        if evidence_lower.contains("mysql") || evidence_lower.contains("mysql_fetch") {
            stack.insert("database".to_string(), "MySQL".to_string());
        } else if evidence_lower.contains("postgresql") || evidence_lower.contains("psql") {
            stack.insert("database".to_string(), "PostgreSQL".to_string());
        } else if evidence_lower.contains("sqlserver") || evidence_lower.contains("mssql") {
            stack.insert("database".to_string(), "SQL Server".to_string());
        }

        stack
    }

    fn identify_affected_components(&self, evidence: &VulnerabilityEvidence) -> Vec<String> {
        let mut components = Vec::new();
        
        if let Some(param) = &evidence.parameter {
            components.push(format!("Input parameter: {}", param));
        }
        
        components.push(format!("Endpoint: {}", evidence.endpoint));
        
        match evidence.vulnerability_id.as_str() {
            "SQLI-001" => {
                components.push("Database query".to_string());
                components.push("Data access layer".to_string());
            }
            "XSS-001" => {
                components.push("Output rendering".to_string());
                components.push("Template engine".to_string());
            }
            "LFI-001" => {
                components.push("File system".to_string());
                components.push("Input validation".to_string());
            }
            "CMD-001" => {
                components.push("System shell".to_string());
                components.push("Command executor".to_string());
            }
            _ => {
                components.push("Web application".to_string());
            }
        }

        components
    }

    fn trace_data_flow(&self, evidence: &VulnerabilityEvidence) -> Option<DataFlow> {
        if evidence.parameter.is_none() {
            return None;
        }

        let source = format!("User input (parameter: {})", evidence.parameter.as_ref().unwrap());
        
        let sink = match evidence.vulnerability_id.as_str() {
            "SQLI-001" => "SQL query execution".to_string(),
            "XSS-001" => "HTML output rendering".to_string(),
            "LFI-001" => "File system access".to_string(),
            "CMD-001" => "System command execution".to_string(),
            "LDAP-001" => "LDAP query execution".to_string(),
            "XXE-001" => "XML parser".to_string(),
            _ => "Application logic".to_string(),
        };

        Some(DataFlow {
            source,
            sink,
            sanitization: None,
            validation: None,
        })
    }

    fn identify_security_controls(&self, evidence: &VulnerabilityEvidence) -> Vec<String> {
        let mut controls = Vec::new();

        for (header, value) in &evidence.response_headers {
            let header_lower = header.to_lowercase();
            
            if header_lower.contains("content-security-policy") {
                controls.push("CSP enabled".to_string());
            }
            if header_lower.contains("x-frame-options") {
                controls.push("Clickjacking protection".to_string());
            }
            if header_lower.contains("x-content-type-options") {
                controls.push("MIME sniffing protection".to_string());
            }
            if header_lower.contains("strict-transport-security") {
                controls.push("HSTS enabled".to_string());
            }
            if header_lower.contains("x-xss-protection") {
                controls.push("XSS filter".to_string());
            }
            if header_lower.contains("set-cookie") && value.contains("httponly") {
                controls.push("HttpOnly cookies".to_string());
            }
            if header_lower.contains("set-cookie") && value.contains("secure") {
                controls.push("Secure cookies".to_string());
            }
        }

        controls
    }

    pub fn get_context_for_endpoint(&self, endpoint: &str) -> Option<&VulnerabilityContext> {
        self.contexts.get(endpoint)
    }

    pub fn get_all_contexts(&self) -> &HashMap<String, VulnerabilityContext> {
        &self.contexts
    }
}

impl Default for ContextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}