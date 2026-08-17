
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use super::api::{run_scan_background, ScanSession, ScanStore};
use super::auth;

#[derive(Clone)]
pub struct AppState {
    pub store: ScanStore,
}

/// Página única do painel Enterprise (HTML + CSS + JS embutidos)
fn dashboard_html() -> &'static str {
    include_str!("dashboard.html")
}

pub fn build_app(store: ScanStore) -> Router {
    let state = AppState { store };

    Router::new()
        .route("/", get(index_handler))
        .route("/api/login", post(login_handler))
        .route("/api/scans", get(list_scans_handler).post(start_scan_handler))
        .route("/api/scans/:id", get(scan_detail_handler))
        .route("/api/scans/:id/report", get(report_handler))
        .route("/api/stats", get(stats_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn index_handler() -> Html<&'static str> {
    Html(dashboard_html())
}

// ===== Autenticação =====

#[derive(Deserialize)]
struct LoginRequest {
    user: String,
    pass: String,
}

#[derive(Serialize)]
struct LoginResponse {
    ok: bool,
    token: Option<String>,
    error: Option<String>,
}

async fn login_handler(Json(req): Json<LoginRequest>) -> Json<LoginResponse> {
    if auth::verify_credentials(&req.user, &req.pass) {
        match auth::create_token(&req.user) {
            Ok(token) => Json(LoginResponse { ok: true, token: Some(token), error: None }),
            Err(e) => Json(LoginResponse { ok: false, token: None, error: Some(e.to_string()) }),
        }
    } else {
        Json(LoginResponse { ok: false, token: None, error: Some("Credenciais inválidas".into()) })
    }
}

/// Middleware manual simples: valida o Bearer token nas rotas protegidas
fn check_token(header: Option<String>) -> Result<String, StatusCode> {
    let header = header.ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth::bearer_token(&header).ok_or(StatusCode::UNAUTHORIZED)?;
    auth::verify_token(token)
        .map(|c| c.sub)
        .ok_or(StatusCode::UNAUTHORIZED)
}

// ===== Scans =====

#[derive(Serialize)]
struct ScansResponse {
    ok: bool,
    scans: Vec<ScanSession>,
}

async fn list_scans_handler(
    State(state): State<AppState>,
    auth_header: Option<axum::http::HeaderMap>,
) -> Result<Json<ScansResponse>, StatusCode> {
    check_token(auth_header.and_then(|h| h.get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string())))?;
    let scans = state.store.sessions.lock().await.clone();
    Ok(Json(ScansResponse { ok: true, scans }))
}

#[derive(Deserialize)]
struct StartScanRequest {
    target: String,
    #[serde(default)]
    aggressive: bool,
}

#[derive(Serialize)]
struct StartScanResponse {
    ok: bool,
    scan_id: Option<u64>,
    error: Option<String>,
}

async fn start_scan_handler(
    State(state): State<AppState>,
    auth_header: Option<axum::http::HeaderMap>,
    Json(req): Json<StartScanRequest>,
) -> Result<Json<StartScanResponse>, StatusCode> {
    check_token(auth_header.and_then(|h| h.get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string())))?;

    // Validação mínima de URL (exige http:// ou https://)
    let target = req.target.trim().to_string();
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return Ok(Json(StartScanResponse {
            ok: false,
            scan_id: None,
            error: Some("O alvo deve começar com http:// ou https://".into()),
        }));
    }

    let store = state.store.clone();
    let sid = store.add_session(target.clone(), req.aggressive).await;

    // Executa em background sem bloquear a resposta
    tokio::spawn(async move { run_scan_background(store, sid, target, req.aggressive).await });

    Ok(Json(StartScanResponse { ok: true, scan_id: Some(sid), error: None }))
}

#[derive(Serialize)]
struct ScanDetailResponse {
    ok: bool,
    scan: Option<ScanSession>,
    error: Option<String>,
}

async fn scan_detail_handler(
    State(state): State<AppState>,
    auth_header: Option<axum::http::HeaderMap>,
    Path(id): Path<u64>,
) -> Result<Json<ScanDetailResponse>, StatusCode> {
    check_token(auth_header.and_then(|h| h.get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string())))?;
    let scan = state.store.sessions.lock().await.iter().find(|s| s.id == id).cloned();
    if let Some(s) = scan {
        Ok(Json(ScanDetailResponse { ok: true, scan: Some(s), error: None }))
    } else {
        Ok(Json(ScanDetailResponse { ok: false, scan: None, error: Some("Scan não encontrado".into()) }))
    }
}

#[derive(Serialize)]
struct ReportResponse {
    ok: bool,
    report: Option<String>,
    error: Option<String>,
}

async fn report_handler(
    State(state): State<AppState>,
    auth_header: Option<axum::http::HeaderMap>,
    Path(id): Path<u64>,
) -> Result<Json<ReportResponse>, StatusCode> {
    check_token(auth_header.and_then(|h| h.get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string())))?;
    let sessions = state.store.sessions.lock().await;
    let scan = sessions.iter().find(|s| s.id == id);
    let report_path = scan.and_then(|s| s.report_path.clone());
    drop(sessions);

    if let Some(path) = report_path {
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => Ok(Json(ReportResponse { ok: true, report: Some(content), error: None })),
            Err(e) => Ok(Json(ReportResponse { ok: false, report: None, error: Some(format!("Erro ao ler relatório: {}", e)) })),
        }
    } else {
        Ok(Json(ReportResponse { ok: false, report: None, error: Some("Relatório ainda não disponível (scan em andamento ou falhou)".into()) }))
    }
}

// ===== Estatísticas Enterprise =====

#[derive(Serialize)]
struct StatsResponse {
    ok: bool,
    total_scans: usize,
    running: usize,
    done: usize,
    errors: usize,
    total_vulns: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    user: String,
    version: String,
}

async fn stats_handler(
    State(state): State<AppState>,
    auth_header: Option<axum::http::HeaderMap>,
) -> Result<Json<StatsResponse>, StatusCode> {
    let user = check_token(auth_header.and_then(|h| h.get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string())))?;
    let sessions = state.store.sessions.lock().await;
    let mut running = 0;
    let mut done = 0;
    let mut errors = 0;
    let mut total_vulns = 0;
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    for s in sessions.iter() {
        match s.status {
            super::api::ScanStatus::Running => running += 1,
            super::api::ScanStatus::Done => {
                done += 1;
                total_vulns += s.total_vulns.unwrap_or(0);
                critical += s.critical;
                high += s.high;
                medium += s.medium;
                low += s.low;
                info += s.info;
            }
            super::api::ScanStatus::Error(_) => errors += 1,
        }
    }
    Ok(Json(StatsResponse {
        ok: true,
        total_scans: sessions.len(),
        running,
        done,
        errors,
        total_vulns,
        critical,
        high,
        medium,
        low,
        info,
        user,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

/// Inicia o servidor web na porta configurável (default 3000)
pub async fn serve(store: ScanStore, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_app(store);
    let addr = format!("0.0.0.0:{}", port);
    println!("🌐 Painel Enterprise rodando em http://localhost:{}", port);
    println!("🔑 Credenciais padrão: admin / enterprise2026 (altere via ADMIN_USER / ADMIN_PASS)");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
