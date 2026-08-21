#![allow(dead_code)]
use reqwest::{Client, Proxy, Response, Error, header};
use std::time::Duration;
use log::{debug, info, warn};
use serde_json::Value;
use std::sync::Arc;

use super::waf_bypass::{classify_block, browser_headers, obfuscate_variants, BlockReason, WafBypassState};
use url::Url;

/// Máximo de retentativas após bloqueio (403/429) antes de desistir.
const MAX_RETRY: u8 = 2;

#[derive(Clone)]
pub struct SecureHttpClient {
    pub client: Arc<Client>,
    pub cookies: Option<String>,
    pub bypass: WafBypassState,
    pub enable_bypass: bool,
}

impl SecureHttpClient {
    pub async fn new(
        timeout_secs: u64,
        proxy: Option<String>,
        cookie: Option<String>,
        custom_header: Option<String>,
    ) -> Result<Self, Error> {
        let mut headers = header::HeaderMap::new();

        // UA inicial — identidade de browser real (antes: "VulnScanner/0.1.0", que denunciava o scanner)
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        );

        if let Some(cookie_str) = &cookie {
            if let Ok(cookie_value) = header::HeaderValue::from_str(cookie_str) {
                headers.insert(header::COOKIE, cookie_value);
                debug!("Cookie adicionado: {}", cookie_str);
            }
        }

        if let Some(header_str) = &custom_header {
            if let Some((key, value)) = header_str.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if let Ok(header_value) = header::HeaderValue::from_str(value) {
                    if let Ok(header_name) = header::HeaderName::from_bytes(key.as_bytes()) {
                        headers.insert(header_name, header_value);
                        debug!("Header adicionado: {}: {}", key, value);
                    }
                }
            }
        }

        let mut builder = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .default_headers(headers)
            .cookie_store(true)
            .danger_accept_invalid_certs(false);

        if let Some(proxy_url) = proxy {
            if let Ok(proxy) = Proxy::all(&proxy_url) {
                builder = builder.proxy(proxy);
                debug!("Usando proxy: {}", proxy_url);
            }
        }

        let client = builder.build()?;
        Ok(Self {
            client: Arc::new(client),
            cookies: cookie,
            bypass: WafBypassState::new(),
            enable_bypass: false,
        })
    }

    /// Ativa o módulo de WAF bypass (rotação de UA + throttling adaptativo + retry).
    pub fn bypass_enabled(&self) -> bool {
        self.enable_bypass
    }

    pub fn enable_waf_bypass(&mut self) {
        self.enable_bypass = true;
        info!("🛡️ WAF bypass ativado: rotação de User-Agent + throttling adaptativo + retentativa em 403/429");
    }

    /// Monta os headers de uma requisição, aplicando rotação de UA e fingerprint
    /// de browser quando o bypass está ativo.
    fn build_headers(&self) -> Option<header::HeaderMap> {
        if !self.enable_bypass {
            return None;
        }
        let mut hm = header::HeaderMap::new();
        if let Ok(ua) = header::HeaderValue::from_str(self.bypass.next_user_agent()) {
            hm.insert(header::USER_AGENT, ua);
        }
        for (name, value) in browser_headers() {
            if let (Ok(hname), Ok(hval)) = (
                header::HeaderName::from_bytes(name.as_bytes()),
                header::HeaderValue::from_str(value),
            ) {
                hm.insert(hname, hval);
            }
        }
        Some(hm)
    }

    /// Executa um GET com bypass aplicado: delay adaptativo + retry em 403/429.
    pub async fn get(&self, url: &str) -> Result<Response, Error> {
        debug!("GET {}", url);
        let mut last_err: Option<Error> = None;
        let mut blocked_kind = BlockReason::None;
        let mut blocked_resp: Option<Response> = None;

        // URLs ofuscadas (variantes do bypass) a testar quando o WAF bloquear:
        // o retry simples reenvia a mesma URL, o que nunca vence um WAF de assinatura.
        // As variantes aplicam double-encoding, case mixing, comentários SQL (/**/),
        // tab/newline insertion etc. — técnicas que quebram regex de borda e chegam
        // intactas ao app vulnerável quando este faz unquote duplo.
        let mut obfuscated_queue: Vec<String> = Vec::new();
        let mut obfuscated_index: usize = 0;

        // FIX v9.2.1: tentar TODAS as variantes ofuscadas antes de desistir.
        // Antes: max_attempts=1 fazia o loop morrer após 1 variante, mesmo
        // com 4 outras na fila — o bypass "funcionava" só quando a 1ª
        // variante passava. Agora: o loop continua enquanto houver
        // variantes, limitado a MAX_RETRY + variantes (teto de 6).
        for attempt in 0..=(MAX_RETRY as usize + 6) {
            // Rate-limit (429) merece no máximo UMA retentativa: repetir em
            // rajada só piora o bloqueio do alvo e trava o scan em delay crescente.
            // FIX v9.2: em modo bypass, mesmo bloqueio WAF (403) recebe só 1
            // retentativa — insistir 3x no mesmo payload só gera tráfego em vão
            // e derruba a taxa sustentável do scan inteiro.
            let max_attempts = if matches!(blocked_kind, BlockReason::RateLimit) || self.enable_bypass {
                1
            } else {
                MAX_RETRY
            };

            // Escolhe a URL desta tentativa: a original na 1ª, depois variantes
            // ofuscadas (uma por tentativa, na ordem gerada).
            let current_url = if obfuscated_index == 0 {
                url.to_string()
            } else {
                obfuscated_queue[obfuscated_index - 1].clone()
            };

            if attempt == 0 {
                self.bypass.wait().await;
            } else if attempt <= max_attempts as usize + obfuscated_queue.len().min(5) {
                info!("🛡️ Retentativa {}/{} após bloqueio {} — {}", attempt, MAX_RETRY as usize + 6, blocked_kind, current_url);
                // FIX v9.2: current_delay() pode ser 0 quando o backoff ainda
                // não subiu (ex.: 429 recente). Repetir em 0ms só gera a próxima
                // rajada e mantém o alvo em 429. Piso de 500ms garante que o
                // bucket de rate-limit do alvo esvazie entre tentativas.
                let backoff = self.bypass.current_delay().max(Duration::from_millis(500));
                self.bypass.wait().await;
                tokio::time::sleep(backoff).await;
            } else {
                return Ok(blocked_resp.unwrap());
            }

            let mut req = self.client.get(&current_url);
            if let Some(hm) = self.build_headers() {
                req = req.headers(hm);
            }
            match req.send().await {
                Ok(resp) => {
                    let reason = classify_block(&resp);
                    match reason {
                        BlockReason::None => {
                            self.bypass.on_success();
                            return Ok(resp);
                        }
                        _ => {
                            blocked_kind = reason;
                            blocked_resp = Some(resp);
                            // Na 1ª tentativa bloqueada: gerar TODAS as variantes
                            // ofuscadas da URL original e enfileirá-las (1 por retry).
                            // Sem isso, o retry reenvia a mesma URL bloqueada e
                            // desiste — o scanner nunca vence um WAF de assinatura.
                            if obfuscated_queue.is_empty()
                                && self.enable_bypass
                                && matches!(reason, BlockReason::Waf)
                            {
                                obfuscated_queue = Self::obfuscate_url(&current_url);
                                info!("🛡️ WAF bloqueou — {} variantes ofuscadas geradas para retry", obfuscated_queue.len());
                            }
                            if self.enable_bypass && !obfuscated_queue.is_empty() && obfuscated_index < obfuscated_queue.len() {
                                obfuscated_index += 1;
                                self.bypass.on_blocked();
                                continue;
                            } else if self.enable_bypass && attempt < max_attempts as usize + obfuscated_queue.len().min(5) {
                                self.bypass.on_blocked();
                                continue;
                            } else if !self.enable_bypass && matches!(reason, BlockReason::Waf | BlockReason::RateLimit) {
                                warn!("⚠️ Alvo bloqueou a requisição ({}). Use --waf-bypass para rotação de UA e throttling adaptativo.", reason);
                                return Ok(blocked_resp.unwrap());
                            } else {
                                return Ok(blocked_resp.unwrap());
                            }
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            // reqwest::Error não é construtível diretamente; recriamos via
            // bloqueio em URL propositalmente inválida (nunca enviada na rede).
            reqwest::blocking::get("http://\u{0}.bypass.retries.exhausted.invalid")
                .unwrap_err()
        }))
    }

    // ===== Bypass por ofuscação de payload na URL =====
    // Recebe uma URL como `http://host/rota?param=payload` e gera variantes onde o
    // VALOR do payload é ofuscado (double-encode, case mix, /**/ , tabs) — a rota e o
    // nome do parâmetro ficam intactos. Retorna no máximo MAX_OBFUSCATED_VARIANTS.
    fn obfuscate_url(url: &str) -> Vec<String> {
        const MAX_OBFUSCATED_VARIANTS: usize = 5;
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Vec::new(),
        };
        let query_pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // FIX v9.2.1: variante que double-encoda APENAS os '%' do valor
        // original (ex.: ..%2F..%2F → ..%252F..%252F). query_pairs() decodifica
        // o valor, então o double-encode comum de obfuscate_variants recria a
        // URL idêntica à original (rejeitada por `variant != url`). O WAF de
        // assinatura opera sobre a URL bruta — '%252F' não casa com '\.\./'
        // e o app vulnerável faz unquote ao processar (double-unquote ou
        // unquote + interpretação do path). Sem esta variante, LFI/CMD com
        if query_pairs.is_empty() {
            return Vec::new();
        }

        let mut variants = Vec::new();
        let mut seen = std::collections::HashSet::new();
        // payloads já encodados nunca vencem o WAF.
        // Usa a query BRUTA (raw) da URL: query_pairs() decodifica '%2F'→'/',
        // então o replace('%','%25') sobre o decodificado não altera nada.
        // A raw mantém os '%' originais — double-encodá-los gera %252F que
        // o WAF não reconhece, e o app vulnerável decodifica ao processar.
        if let Some(raw_query) = parsed.query() {
            let doubled = raw_query.replace('%', "%25");
            let base = format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""),
                parsed.port().map_or(String::new(), |p| format!(":{}", p)));
            let variant = format!("{}{}?{}", base, parsed.path(), doubled);
            if variant != url {
                seen.insert(variant.clone());
                variants.push(variant);
            }
        }
        // Gera variantes de cada par de query (o que o WAF bloqueia é o valor).
        for (name, value) in &query_pairs {
            for v in obfuscate_variants(value) {
                if seen.contains(&v) {
                    continue;
                }
                seen.insert(v.clone());
                // Reconstrói a URL mantendo os demais parâmetros intactos.
                let mut pairs: Vec<(String, String)> = query_pairs.clone();
                for pair in &mut pairs {
                    if pair.0 == *name {
                        pair.1 = v.clone();
                    }
                }
                let query: String = pairs
                    .iter()
                    .map(|(k, val)| format!("{}={}", k, val))
                    .collect::<Vec<_>>()
                    .join("&");
                let base = format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""),
                    parsed.port().map_or(String::new(), |p| format!(":{}", p)));
                let variant = format!("{}{}?{}", base, parsed.path(), query);
                if variant != url && variants.len() < MAX_OBFUSCATED_VARIANTS {
                    variants.push(variant);
                }
            }
        }
        variants
    }

    // GET SEM seguir redirects - necessário para detectar Open Redirect (302)
    pub async fn get_no_redirect(&self, url: &str) -> Result<Response, Error> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());

        if self.enable_bypass {
            if let Some(hm) = self.build_headers() {
                builder = builder.default_headers(hm);
            }
        }

        self.bypass.wait().await;
        let client = builder.build()?;
        let resp = client.get(url).send().await?;
        self.bypass.on_success();
        Ok(resp)
    }

    pub async fn head(&self, url: &str) -> Result<Response, Error> {
        debug!("HEAD {}", url);
        self.bypass.wait().await;
        let mut req = self.client.head(url);
        if let Some(hm) = self.build_headers() {
            req = req.headers(hm);
        }
        let resp = req.send().await?;
        self.bypass.on_success();
        Ok(resp)
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<Response, Error> {
        debug!("POST {} - Body: {}", url, body);
        self.bypass.wait().await;
        let mut req = self.client.post(url).body(body.to_string());
        if let Some(hm) = self.build_headers() {
            req = req.headers(hm);
        }
        let resp = req.send().await?;
        self.bypass.on_success();
        Ok(resp)
    }

    pub async fn post_json(&self, url: &str, body: &str) -> Result<Response, Error> {
        debug!("POST JSON {} - Body: {}", url, body);
        self.bypass.wait().await;
        let mut req = self.client.post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string());
        if let Some(hm) = self.build_headers() {
            req = req.headers(hm);
        }
        let resp = req.send().await?;
        self.bypass.on_success();
        Ok(resp)
    }

    pub async fn post_form(&self, url: &str, body: &str) -> Result<Response, Error> {
        debug!("POST FORM {} - Body: {}", url, body);
        self.bypass.wait().await;
        let mut req = self.client.post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string());
        if let Some(hm) = self.build_headers() {
            req = req.headers(hm);
        }
        let resp = req.send().await?;
        self.bypass.on_success();
        Ok(resp)
    }

    // ===== Autenticação =====
    pub async fn login(
        &mut self,
        login_url: &str,
        username: &str,
        password: &str,
        login_data: Option<&str>,
    ) -> Result<bool, Error> {
        debug!("Tentando login em: {}", login_url);

        let body = if let Some(data) = login_data {
            data.to_string()
        } else {
            format!("username={}&password={}", username, password)
        };

        let response = self.post_form(login_url, &body).await?;

        // PEGA OS HEADERS ANTES DE CONSUMIR O BODY
        let status = response.status();
        let headers = response.headers().clone();
        let body_text = response.text().await.unwrap_or_default();

        debug!("Login - Status: {}", status);

        if status.is_success() {
            if let Some(cookie_header) = headers.get(header::SET_COOKIE) {
                if let Ok(cookie_str) = cookie_header.to_str() {
                    debug!("Cookie recebido: {}", cookie_str);
                    self.cookies = Some(cookie_str.to_string());
                }
            }
            return Ok(true);
        }

        if status.is_redirection() {
            debug!("Redirecionamento detectado - login provavelmente bem-sucedido");
            return Ok(true);
        }

        if body_text.contains("Welcome") ||
           body_text.contains("Dashboard") ||
           body_text.contains("Logout") ||
           body_text.contains("redirect") ||
           body_text.contains("success") {
            debug!("Login bem-sucedido detectado na resposta");
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn login_bearer(&mut self, login_url: &str, username: &str, password: &str) -> Result<bool, Error> {
        debug!("Tentando login Bearer Token em: {}", login_url);

        let login_body = serde_json::json!({
            "username": username,
            "password": password
        });

        let response = self.post_json(login_url, &login_body.to_string()).await?;

        // PEGA O STATUS E BODY ANTES DE MOVER
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();

        debug!("Login Bearer - Status: {}", status);

        if status.is_success() {
            if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                if json.get("token").and_then(|t| t.as_str()).is_some() {
                    debug!("Token Bearer obtido");
                    return Ok(true);
                }
                if json.get("access_token").and_then(|t| t.as_str()).is_some() {
                    debug!("Access Token obtido");
                    return Ok(true);
                }
            }

            if !body_text.contains("error") && !body_text.contains("invalid") {
                debug!("Login bem-sucedido (sem token detectado)");
                return Ok(true);
            }
        }

        Ok(false)
    }
}
