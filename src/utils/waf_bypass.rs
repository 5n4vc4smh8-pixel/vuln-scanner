//! Módulo de WAF Bypass v2
//!
//! Técnicas implementadas (P0 do roadmap):
//! 1. **Rotação de User-Agent** — pool de User-Agents reais de browsers;
//!    rotaciona a cada requisição e nunca usa identidade de scanner.
//! 2. **Throttling adaptativo** — ao detectar 403/429, reduz
//!    automaticamente a taxa de requisições (backoff exponencial)
//!    e retenta. Ao voltar a ver 200, recupera gradualmente.
//! 3. **Detecção de WAF** — headers padrão (X-WAF, Server, X-Cache) e
//!    padrões de body de páginas de bloqueio (Cloudflare, ModSecurity, etc.)
//! 4. **Header spoofing** — adiciona headers de browser legítimo
//!    (Accept, Accept-Language, Referer, Sec-Fetch) para parecer tráfego normal.
//! 5. **Fallback de payload** — quando um payload é bloqueado, tenta
//!    automaticamente a variante ofuscada correspondente.

use once_cell::sync::Lazy;
use rand::Rng;
use reqwest::{Client, Response};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

/// Milissegundos desde epoch (monotônico relativo ao boot é ok aqui, pois
/// só comparamos deltas).
fn millis_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Estado global do bypass (thread-safe).
#[derive(Clone)]
pub struct WafBypassState {
    /// Base atual de delay em ms (começa em 0).
    base_delay_ms: Arc<AtomicU64>,
    /// Indica que o bypass está em modo "agressivo reduzido".
    pub throttled: Arc<AtomicBool>,
    /// Contador de 403/429 recebidos.
    pub blocked_count: Arc<AtomicU64>,
    /// Contador de requisições totais (para rotação de UA).
    req_count: Arc<AtomicU64>,
    /// Delay mínimo garantido quando throttled.
    min_delay_ms: u64,
    /// Marca de tempo (ms, epoch) do último envio, para o slot lock.
    /// 0 = nunca enviou. Atualizado dentro de lock curto; o sleep acontece
    /// FORA do lock, então não há deadlock nem livelock.
    last_send_ms: Arc<Mutex<u64>>,
}

impl Default for WafBypassState {
    fn default() -> Self {
        Self {
            base_delay_ms: Arc::new(AtomicU64::new(0)),
            throttled: Arc::new(AtomicBool::new(false)),
            blocked_count: Arc::new(AtomicU64::new(0)),
            req_count: Arc::new(AtomicU64::new(0)),
            min_delay_ms: 150,
            last_send_ms: Arc::new(Mutex::new(0)),
        }
    }
}

impl WafBypassState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Delay atual com jitter aleatório (±30%).
    /// Sem bloqueios recentes o delay é ~0 — o espaçamento mínimo entre
    /// requisições fica por conta do slot-lock (wait()), que já garante que
    /// nenhuma thread dispare antes do gap mínimo global. Aplicar um piso de
    /// 250ms em TODA requisição tornava scans limpos ~20x mais lentos sem
    /// benefício real de stealth (um scanner a 2-5 req/s já é stealthy).
    pub fn current_delay(&self) -> Duration {
        let base = self.base_delay_ms.load(Ordering::Relaxed);
        if base == 0 {
            return Duration::ZERO;
        }
        let mut rng = rand::thread_rng();
        let jitter = (base as f64 * 0.3 * (rng.gen::<f64>() * 2.0 - 1.0)) as u64;
        Duration::from_millis(base.saturating_add(jitter))
    }

    /// Notifica um bloqueio (403/429): aumenta o backoff exponencial (máx 10s).
    pub fn on_blocked(&self) {
        self.blocked_count.fetch_add(1, Ordering::Relaxed);
        self.throttled.store(true, Ordering::Relaxed);
        let cur = self.base_delay_ms.load(Ordering::Relaxed);
        // backoff exponencial: 250 -> 500 -> 1000 -> 1500 (teto).
        // FIX v9.2.1: teto de 3s era exagero — com dezenas de bloqueios o scan
        // ficava a 3s/requisição ("travado" de fato, embora vivo). 1.5s já
        // respeita o bucket de rate-limit do alvo (10 req/s, normaliza em 2s).
        let next = (cur * 2).clamp(250, 1_500);
        self.base_delay_ms.store(next, Ordering::Relaxed);
        log::info!(
            "🛡️ WAF bypass: bloqueio detectado (403/429 #{}), delay ajustado para {}ms",
            self.blocked_count.load(Ordering::Relaxed),
            next
        );
    }

    /// Notifica uma resposta OK: recupera gradualmente o delay (divide por 2).
    pub fn on_success(&self) {
        let cur = self.base_delay_ms.load(Ordering::Relaxed);
        if cur > 0 {
            // FIX v9.2.1: recuperação 3x mais rápida — dividir por 3 e zerar
            // abaixo de 200ms. Com teto 3s o scan levava ~10 successes para
            // sair do throttle; agora normaliza em ~4 successes (6→3→1→0).
            let next = cur / 3;
            self.base_delay_ms.store(if next < 200 { 0 } else { next }, Ordering::Relaxed);
        }
        // Throttle só encerra quando o backoff chegar a zero (nenhum bloqueio recente)
        if self.base_delay_ms.load(Ordering::Relaxed) == 0 {
            self.throttled.store(false, Ordering::Relaxed);
        }
    }

    /// Next User-Agent do pool (rotação determinística por contagem).
    pub fn next_user_agent(&self) -> &'static str {
        let idx = self.req_count.fetch_add(1, Ordering::Relaxed) as usize % USER_AGENTS.len();
        USER_AGENTS[idx]
    }

    /// Delay obrigatório antes da próxima requisição.
    /// Garante espaçamento GLOBAL entre threads via "slot lock" lock-free:
    /// cada thread espera o tempo restante desde o último envio e disputa o
    /// próximo slot com compare_exchange. Sem Mutex (sem deadlock) e sem
    /// rajadas (todas as threads respeitam o gap global). Sem isso, N threads
    /// acordam juntas após o mesmo sleep e geram >10 req/s, que é exatamente
    /// o que dispara rate-limit no alvo.
    pub async fn wait(&self) {
        let d = self.current_delay();
        // Gap global mínimo entre requisições: 150ms (~7 req/s no teto) quando
        // não há bloqueios recentes; sob throttle sobe para o backoff atual.
        // Sem este piso, threads acordadas juntas disparariam >10 req/s e
        // ativariam o rate-limit do alvo.
        let min_gap = if d.is_zero() {
            self.min_delay_ms.min(150)
        } else {
            d.as_millis() as u64
        };
        // Loop de disputa de slot com lock CURTO (apenas leitura/escrita do
        // timestamp — nunca dormimos dentro do lock):
        // 1. Lemos o último envio e calculamos o tempo restante.
        // 2. Dormimos FORA do lock.
        // 3. Após acordar, registramos nosso novo deadline (a espera já
        //    garantiu o gap, então qualquer registro aqui é válido).
        loop {
            let (remaining, slot_taken) = {
                let mut last = self.last_send_ms.lock().await;
                let now_ms = millis_since_epoch();
                if *last == 0 {
                    *last = now_ms.saturating_add(min_gap);
                    (0, true)
                } else {
                    let remaining = last.saturating_add(min_gap).saturating_sub(now_ms);
                    if remaining == 0 {
                        *last = now_ms.saturating_add(min_gap);
                        (0, true)
                    } else {
                        (remaining, false)
                    }
                }
            };
            if slot_taken {
                return;
            }
            // Dorme o tempo restante (fora do lock, sem risco de deadlock).
            // Adicionamos 1ms de tolerância para acordar um instante após o
            // slot estar livre.
            tokio::time::sleep(Duration::from_millis(remaining + 1)).await;
            // Ao acordar, tenta registrar; se outra thread registrou antes,
            // o loop recalcula.
            let mut last = self.last_send_ms.lock().await;
            if millis_since_epoch().saturating_add(1) >= last.saturating_sub(min_gap) {
                // slot livre (ou ninguém registrou ainda) — registrar
                *last = millis_since_epoch().saturating_add(min_gap);
                return;
            }
            // altrimenti continua o loop e recalcula
        }
    }
}

/// Pool de User-Agents reais de browsers (Windows/macOS/Linux, Chrome/Firefox/Safari/Edge).
/// Atualizado com assinaturas de 2025-2026.
pub static USER_AGENTS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/7.0.3495.16",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    ]
});

/// Headers que um browser legítimo sempre envia (browser fingerprint spoofing).
pub fn browser_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Cache-Control", "max-age=0"),
    ]
}

/// Detecta se a resposta veio de um WAF (Cloudflare, ModSecurity, etc.)
/// ou se é um bloqueio de rate-limit.
pub fn classify_block(resp: &Response) -> BlockReason {
    let status = resp.status().as_u16();
    let headers = resp.headers();

    // 429 = rate-limit explícito
    if status == 429 {
        return BlockReason::RateLimit;
    }
    // 403/406 + headers conhecidos de WAF
    if matches!(status, 403 | 406 | 503) {
        let has_waf_header = headers.contains_key("x-waf")
            || headers.contains_key("x-cdn")
            || headers.contains_key("cf-cache-status")
            || (headers.contains_key("server")
                && headers
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| {
                        s.contains("cloudflare") || s.contains("nginx") || s.contains("ModSecurity")
                    })
                    .unwrap_or(false));
        if has_waf_header {
            return BlockReason::Waf;
        }
        // fallback: página de bloqueio curta (páginas 403 de WAF tendem a ser
        // pequenas; páginas normais de erro da aplicação são maiores)
        let content_len = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if content_len > 0 && content_len < 3000 {
            return BlockReason::Waf;
        }
    }
    BlockReason::None
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlockReason {
    None,
    Waf,
    RateLimit,
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::None => write!(f, "nenhum"),
            BlockReason::Waf => write!(f, "WAF"),
            BlockReason::RateLimit => write!(f, "rate-limit (429)"),
        }
    }
}

/// Variações de ofuscação para payloads bloqueados (P1 do roadmap).
/// Recebe um payload genérico e retorna variantes para retentar.
pub fn obfuscate_variants(payload: &str) -> Vec<String> {
    use std::collections::VecDeque;

    let mut variants = Vec::new();

    // 1. Double URL-encoding (..%2F -> ..%252F)
    variants.push(percent_encoding::utf8_percent_encode(
        payload,
        percent_encoding::NON_ALPHANUMERIC,
    ).to_string());

    // 2. Case mixing (uNiOn -> mistura de maiúsculas/minúsculas)
    let mixed: String = payload
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 { c.to_uppercase().next().unwrap_or(c) }
            else { c.to_lowercase().next().unwrap_or(c) }
        })
        .collect();
    if mixed != payload {
        variants.push(mixed);
    }

    // 3. SQL comment injection (or -> o/**/r)
    let commented = payload
        .replace("or", "o/**/r")
        .replace("OR", "O/**/R")
        .replace("and", "a/**/nd")
        .replace("AND", "A/**/ND")
        .replace("union", "un/**/ion")
        .replace("UNION", "UN/**/ION");
    if commented != payload {
        variants.push(commented);
    }

    // 4. HTML entity encoding (< -> &lt;)
    if payload.contains('<') || payload.contains('>') {
        variants.push(
            payload
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#39;"),
        );
    }

    // 5. Tab/newline insertion (bloqueios regex simples não casam)
    variants.push(
        payload
            .replace(' ', "\t")
            .replace("union\tselect", "union\tselect")
            .replace("or\t", "or\t")
            .replace("select", "sel\nect"),
    );

    // Duplicados
    let mut seen = std::collections::HashSet::new();
    variants.retain(|v| seen.insert(v.clone()));
    variants
}
