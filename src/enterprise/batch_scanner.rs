use super::BatchScanResult;
use crate::scanner::engine::ScanEngine;
use crate::scanner::DetectedVuln;
use crate::cli::Cli;
use std::time::Instant;
use tokio::sync::Semaphore;
use std::sync::Arc;
use log::{info, error};

pub struct BatchScanner {
    max_concurrent: usize,
}

impl BatchScanner {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.min(50),
        }
    }

    pub async fn scan_multiple_targets(
        &self,
        targets: Vec<String>,
        base_cli: &Cli,
    ) -> Vec<BatchScanResult> {
        info!("🚀 Iniciando scan em lote de {} alvos", targets.len());
        
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut tasks = Vec::new();

        for target in targets {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let target = target.clone();
            let base = base_cli.clone();

            tasks.push(tokio::spawn(async move {
                let mut cli = base;
                cli.target = Some(target.clone());
                let start = Instant::now();
                let result = Self::scan_single_target(cli).await;
                let duration_ms = start.elapsed().as_millis() as u64;
                drop(permit);
                (target, result, duration_ms)
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok((target, result, duration_ms)) => {
                    match result {
                        Ok(vulns) => {
                            let mut scan_result = BatchScanResult {
                                target: target.clone(),
                                vulnerabilities_found: vulns.len() as u32,
                                critical: 0,
                                high: 0,
                                medium: 0,
                                low: 0,
                                scan_duration_ms: duration_ms,
                                success: true,
                                error_message: None,
                            };

                            for vuln in &vulns {
                                match vuln.vulnerability.severity {
                                    crate::scanner::Severity::Critical => scan_result.critical += 1,
                                    crate::scanner::Severity::High => scan_result.high += 1,
                                    crate::scanner::Severity::Medium => scan_result.medium += 1,
                                    crate::scanner::Severity::Low => scan_result.low += 1,
                                    crate::scanner::Severity::Info => {}
                                }
                            }

                            info!("✅ {} - {} vulnerabilidades ({}ms)", 
                                  target, scan_result.vulnerabilities_found, duration_ms);
                            results.push(scan_result);
                        }
                        Err(e) => {
                            error!("❌ {} - Erro: {}", target, e);
                            results.push(BatchScanResult {
                                target: target.clone(),
                                vulnerabilities_found: 0,
                                critical: 0,
                                high: 0,
                                medium: 0,
                                low: 0,
                                scan_duration_ms: duration_ms,
                                success: false,
                                error_message: Some(e.to_string()),
                            });
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Task falhou: {}", e);
                }
            }
        }

        info!("📊 Scan em lote concluído: {} alvos processados", results.len());
        results
    }

    async fn scan_single_target(
        cli: Cli,
    ) -> Result<Vec<DetectedVuln>, String> {
        let mut engine = ScanEngine::new(cli).await.map_err(|e| e.to_string())?;
        let results = engine.scan().await.map_err(|e| e.to_string())?;
        Ok(results)
    }

    pub fn display_batch_summary(results: &[BatchScanResult]) -> String {
        let mut output = String::new();
        output.push_str("\n=== 📊 RELATÓRIO DE SCAN EM LOTE ===\n");
        output.push_str(&format!("Total de alvos: {}\n", results.len()));
        
        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.iter().filter(|r| !r.success).count();
        let total_vulns: u32 = results.iter().map(|r| r.vulnerabilities_found).sum();
        let total_critical: u32 = results.iter().map(|r| r.critical).sum();
        let total_high: u32 = results.iter().map(|r| r.high).sum();
        
        output.push_str(&format!("✅ Sucesso: {}\n", successful));
        output.push_str(&format!("❌ Falhas: {}\n", failed));
        output.push_str(&format!("🔍 Total de vulnerabilidades: {}\n", total_vulns));
        output.push_str(&format!("🔴 Críticas: {}\n", total_critical));
        output.push_str(&format!("🟠 Altas: {}\n", total_high));
        output.push_str("\n--- Detalhes ---\n");
        
        for result in results {
            if result.success {
                output.push_str(&format!(
                    "✅ {} - {} vulns ({} críticas, {} altas) - {}ms\n",
                    result.target,
                    result.vulnerabilities_found,
                    result.critical,
                    result.high,
                    result.scan_duration_ms
                ));
            } else {
                output.push_str(&format!(
                    "❌ {} - Falhou: {}\n",
                    result.target,
                    result.error_message.as_deref().unwrap_or("Erro desconhecido")
                ));
            }
        }
        
        output
    }
}

impl Default for BatchScanner {
    fn default() -> Self {
        Self::new(10)
    }
}