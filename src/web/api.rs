use std::sync::Arc;
use tokio::sync::Mutex;

use chrono::Local;
use serde::Serialize;

use crate::cli::Cli;
use crate::scanner::engine::ScanEngine;

// ===== Tipos de dados do dashboard =====

#[derive(Debug, Clone, Serialize)]
pub enum ScanStatus {
    Running,
    Done,
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSession {
    pub id: u64,
    pub target: String,
    pub aggressive: bool,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: ScanStatus,
    pub total_vulns: Option<usize>,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub report_path: Option<String>,
    pub error: Option<String>,
}

// ===== Store compartilhado de sessões =====

#[derive(Clone)]
pub struct ScanStore {
    pub sessions: Arc<Mutex<Vec<ScanSession>>>,
    next_id: Arc<Mutex<u64>>,
}

impl ScanStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    pub async fn add_session(&self, target: String, aggressive: bool) -> u64 {
        let mut id = self.next_id.lock().await;
        let sid = *id;
        *id += 1;
        drop(id);

        let session = ScanSession {
            id: sid,
            target: target.clone(),
            aggressive,
            started_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            finished_at: None,
            status: ScanStatus::Running,
            total_vulns: None,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            report_path: None,
            error: None,
        };
        self.sessions.lock().await.push(session);
        sid
    }

    pub async fn update_session<F>(&self, sid: u64, f: F)
    where
        F: FnOnce(&mut ScanSession),
    {
        if let Some(s) = self.sessions.lock().await.iter_mut().find(|s| s.id == sid) {
            f(s);
        }
    }
}

// ===== Executa o scan em background (integração direta com o motor) =====

pub async fn run_scan_background(store: ScanStore, sid: u64, target: String, aggressive: bool) {
    // Monta o CLI equivalente ao comando --target X --aggressive
    let mut args = vec!["vuln-scanner".to_string(), "--target".to_string(), target.clone()];
    if aggressive {
        args.push("--aggressive".to_string());
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            store.update_session(sid, |s| {
                s.status = ScanStatus::Error(msg.clone());
                s.finished_at = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                s.error = Some(msg);
            }).await;
            return;
        }
    };

    let target_for_filename = cli.target.clone().unwrap_or(target);
    let engine_result: Result<ScanEngine, String> = ScanEngine::new(cli)
        .await
        .map_err(|e| e.to_string());
    match engine_result {
        Ok(mut engine) => {
            let scan_result = engine.scan().await.map_err(|e| e.to_string());
            match scan_result {
            Ok(results) => {
                let mut critical = 0;
                let mut high = 0;
                let mut medium = 0;
                let mut low = 0;
                let mut info = 0;
                for v in &results {
                    use crate::scanner::Severity::*;
                    match v.vulnerability.severity {
                        Critical => critical += 1,
                        High => high += 1,
                        Medium => medium += 1,
                        Low => low += 1,
                        Info => info += 1,
                    }
                }
                // Gera o relatório na pasta compartilhada `reports/` com nome
                // determinista, usando o MESMO helper que o painel usa para
                // localizar o arquivo (elimina divergência de timestamp/diretório).
                let suffix = format!("web_{}", sid);
                let rpt = crate::scanner::report_path::report_path(&target_for_filename, &suffix);
                if let Err(e) = engine.generate_report_for(results.clone(), &suffix).await {
                    log::warn!("Falha ao gravar relatório: {}", e);
                }
                let report_path: Option<String> = Some(rpt);
                store.update_session(sid, |s| {
                    s.status = ScanStatus::Done;
                    s.finished_at = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                    s.total_vulns = Some(results.len());
                    s.critical = critical;
                    s.high = high;
                    s.medium = medium;
                    s.low = low;
                    s.info = info;
                    s.report_path = report_path;
                }).await;
            }
            Err(msg) => {
                store.update_session(sid, |s| {
                    s.status = ScanStatus::Error(msg.clone());
                    s.finished_at = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                    s.error = Some(msg);
                }).await;
            }
            }
        },
        Err(msg) => {
            store.update_session(sid, |s| {
                s.status = ScanStatus::Error(msg.clone());
                s.finished_at = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                s.error = Some(msg);
            }).await;
        }
    }
}

/// Relatórios do painel web ficam na pasta compartilhada `reports/` (ver
/// scanner/report_path.rs). O painel lê o caminho salvo na sessão, então não
/// há mais derivação de nome aqui.

use clap::Parser as _;
