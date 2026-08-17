#![allow(dead_code)]

mod ai;
mod evidence;
mod remediation;
mod risk;
mod verification;
mod enterprise;

mod cli;
mod scanner;
mod security;
mod utils;
mod web;

use clap::Parser;
use cli::Cli;
use scanner::engine::ScanEngine;
use log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializa logger
    env_logger::init();

    // Parseia argumentos da CLI
    let cli = Cli::parse();

    // ===== V7: MODO SERVIDOR WEB ENTERPRISE =====
    // vuln-scanner --web-server        → painel web na porta 3000
    // vuln-scanner --web-server 3001   → painel web na porta 3001
    if cli.web_server.is_some() {
        let port = cli.web_server.flatten().unwrap_or(3000);
        let store = web::api::ScanStore::new();
        web::server::serve(store, port).await?;
        return Ok(());
    }

    // ===== MODO CLI CLÁSSICO (v1–v6) =====
    if cli.target.is_none() {
        eprintln!("Erro: é necessário informar --target <url> no modo CLI. Para usar o painel web, execute: vuln-scanner --web-server");
        std::process::exit(1);
    }
    let target = cli.target.clone().unwrap_or_default();
    info!("Iniciando scanner para alvo: {}", target);

    // Cria engine de scan
    let mut engine = ScanEngine::new(cli).await?;
    
    // Executa o scan
    let results = engine.scan().await?;
    
    // Gera relatório
    engine.generate_report(results).await?;

    Ok(())
}