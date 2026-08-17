// ===== VULN-SCANNER ENTERPRISE — SERVIDOR WEB (v7) =====
// Painel web com autenticação, dashboard de scans e histórico de relatórios.
// Integra-se diretamente ao motor de scan (scanner::engine::ScanEngine).
//
// Endpoints:
//   GET  /                    → painel (login ou dashboard)
//   POST /api/login           → autentica e retorna JWT
//   GET  /api/scans           → lista os scans (resumo + status)
//   POST /api/scans           → inicia um novo scan (target, aggressive)
//   GET  /api/scans/:id       → status detalhado do scan
//   GET  /api/scans/:id/report→ relatório markdown do scan concluído
//   GET  /api/stats           → estatísticas agregadas (Enterprise)
pub mod api;
pub mod auth;
pub mod server;
