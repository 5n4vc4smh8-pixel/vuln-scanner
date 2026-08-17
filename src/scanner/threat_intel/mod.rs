/// Módulo de Threat Intelligence (CTI).
///
/// Monitora grupos emergentes de ransomware (DireWolf, Devman, Vect, Tengu,
/// MintEye, NightSpire, Kazu, Warlock), correlaciona as vulnerabilidades
/// detectadas pelo scanner com o comportamento conhecido desses grupos e
/// enriquece o relatório com:
///   - Correlação alvo × grupos (prioridade de risco 0-100)
///   - Destaques do catálogo CISA KEV (CVEs com exploração ativa)
///   - Recomendações de remediação priorizadas
pub mod correlation;
pub mod cve_feed;
pub mod groups;
pub mod report_section;

pub use correlation::CorrelationResult;
