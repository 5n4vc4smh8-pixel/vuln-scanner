#![allow(dead_code)]
pub mod discovery;
pub mod engine;
pub mod payloads;
pub mod ports;
pub mod reporter;
pub mod report_path;
pub mod threat_intel;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub timestamp: String,
    pub vulnerabilities: Vec<DetectedVuln>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedVuln {
    pub vulnerability: Vulnerability,
    pub url: String,
    pub parameter: Option<String>,
    pub evidence: String,
    pub sanitized_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_requests: usize,
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}