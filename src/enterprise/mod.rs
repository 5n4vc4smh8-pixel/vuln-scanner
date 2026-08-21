pub mod batch_scanner;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    pub multiple_targets: bool,
    pub scheduling: bool,
    pub pdf_reports: bool,
    pub real_time_alerts: bool,
    pub priority_support: bool,
    pub sla_guarantee: bool,
    pub max_concurrent_scans: usize,
    pub scan_interval_seconds: u64,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            multiple_targets: true,
            scheduling: true,
            pdf_reports: true,
            real_time_alerts: true,
            priority_support: true,
            sla_guarantee: true,
            max_concurrent_scans: 10,
            scan_interval_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanResult {
    pub target: String,
    pub vulnerabilities_found: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub scan_duration_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
}