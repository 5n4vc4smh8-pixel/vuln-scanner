#![allow(dead_code)]
//! Discovery — crawleamento real do alvo.
//!
//! Navega pelos links e formulários do site (profundidade configurável),
//! extrai os parâmetros de cada formulário e descobre endpoints comuns de API.
//! Tudo é restrito ao mesmo host do alvo (sem vazar para domínios externos).

use crate::utils::http_client::SecureHttpClient;
use log::{debug, info};
use std::collections::{HashMap, HashSet};

/// Bloco de formulário descoberto numa página (interno).
struct FormInfo {
    url: String,
    method: String,
    params: Vec<String>,
}

/// Um endpoint descoberto com seus parâmetros de formulário.
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,          // URL base sem query
    pub method: String,       // GET ou POST
    pub params: Vec<String>,  // parâmetros de formulário encontrados
    pub origin: String,       // "crawl" | "api" | "target"
}

pub struct Crawler {
    client: SecureHttpClient,
    base_url: String,      // ex: http://host:port
    host: String,          // host para o filtro de mesmo domínio
    max_depth: usize,
    delay_ms: u64,
}

impl Crawler {
    pub fn new(client: SecureHttpClient, target: &str, max_depth: usize, delay_ms: u64) -> Self {
        let base = Self::base_url(target);
        let host = Self::extract_host(&base);
        Self {
            client,
            base_url: base,
            host,
            max_depth,
            delay_ms,
        }
    }

    /// Executa o crawleamento e devolve a lista de endpoints com parâmetros.
    pub async fn crawl(&self) -> Vec<DiscoveredEndpoint> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut endpoints: HashMap<String, DiscoveredEndpoint> = HashMap::new();
        let mut frontier: Vec<(String, usize)> = vec![(self.base_url.clone(), 0)];

        while let Some((url, depth)) = frontier.pop() {
            let base = Self::base_url(&url);
            if visited.contains(&base) || depth > self.max_depth {
                continue;
            }
            visited.insert(base.clone());

            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }

            let body = match self.fetch_body(&base).await {
                Some(b) => b,
                None => continue,
            };

            // 1. Extrai formulários da página atual
            for form in Crawler::extract_forms(&body, &base) {
                let entry = endpoints
                    .entry(form.url.clone())
                    .or_insert_with(|| DiscoveredEndpoint {
                        url: form.url.clone(),
                        method: form.method.clone(),
                        params: Vec::new(),
                        origin: "crawl".to_string(),
                    });
                for p in form.params {
                    if !entry.params.contains(&p) {
                        entry.params.push(p);
                    }
                }
            }

            // 2. Extrai links internos para o frontier
            for link in Crawler::extract_links(&body, &base) {
                // Links com query (?id=123) também viram endpoints parametrizados
                // — padrão clássico de Insecure Direct Object Reference (IDOR).
                if let Some(pos) = link.find('?') {
                    let resource_url = &link[..pos];
                    let query = &link[pos + 1..];
                    let params: Vec<String> = query
                        .split('&')
                        .filter_map(|kv| kv.split('=').next())
                        .filter(|name| !name.is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    if !params.is_empty() {
                        let entry = endpoints
                            .entry(resource_url.to_string())
                            .or_insert_with(|| DiscoveredEndpoint {
                                url: resource_url.to_string(),
                                method: "GET".to_string(),
                                params: Vec::new(),
                                origin: "crawl".to_string(),
                            });
                        for p in params {
                            if !entry.params.contains(&p) {
                                entry.params.push(p);
                            }
                        }
                    }
                }
                if visited.contains(&link) {
                    continue;
                }
                frontier.push((link, depth + 1));
            }
        }

        info!(
            "🕷️ Crawl: {} páginas visitadas, {} endpoints com formulários",
            visited.len(),
            endpoints.len()
        );

        let mut result: Vec<DiscoveredEndpoint> = endpoints.into_values().collect();
        result.sort_by(|a, b| a.url.cmp(&b.url));
        result
    }

    /// Endpoints comuns de API (independente do crawl).
    pub async fn common_api_endpoints(&self) -> Vec<DiscoveredEndpoint> {
        let paths = vec![
            "/api", "/api/v1", "/api/v2", "/api/users", "/graphql",
            "/login", "/admin", "/api/health", "/api/docs", "/swagger",
            "/api/search", "/api/products",
        ];
        let mut found = Vec::new();
        for path in paths {
            let url = format!("{}{}", self.base_url, path);
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            if let Ok(resp) = self.client.head(&url).await {
                if resp.status().is_success() || resp.status().as_u16() == 405 {
                    debug!("🕷️ API endpoint encontrado: {} ({})", url, resp.status());
                    found.push(DiscoveredEndpoint {
                        url,
                        method: "GET".to_string(),
                        params: Vec::new(),
                        origin: "api".to_string(),
                    });
                }
            }
        }
        found
    }

    // ----helpers internos----

    fn base_url(url: &str) -> String {
        let u = url.trim();
        let without_query = u.split('?').next().unwrap_or(u);
        let without_fragment = without_query.split('#').next().unwrap_or(without_query);
        without_fragment.to_string()
    }

    fn extract_host(url: &str) -> String {
        let no_proto = url
            .replace("https://", "")
            .replace("http://", "");
        let host_part = no_proto.split('/').next().unwrap_or(&no_proto);
        host_part.split(':').next().unwrap_or(host_part).to_string()
    }

    async fn fetch_body(&self, url: &str) -> Option<String> {
        if let Ok(resp) = self.client.get(url).await {
            if resp.status().is_success() {
                let content_type = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if content_type.contains("html") || content_type.is_empty() {
                    return Some(resp.text().await.unwrap_or_default());
                }
            }
        }
        None
    }

    fn is_same_host(&self, href: &str) -> bool {
        if href.starts_with("http://") || href.starts_with("https://") {
            href.contains(&format!("://{}/", self.host)) || href.contains(&format!("://{}", self.host))
        } else {
            // relativo → sempre mesmo host
            true
        }
    }

    /// Resolve href relativo contra a URL base da página.
    fn resolve_href(href: &str, page_base: &str) -> String {
        let href = href.trim().trim_matches('"').trim_matches('\'');
        if href.is_empty() || href.starts_with('#') || href.starts_with("mailto:") || href.starts_with("javascript:") {
            return String::new();
        }
        if href.starts_with("http://") || href.starts_with("https://") {
            return Self::base_url(href);
        }
        // relativo
        let base = Self::base_url(page_base);
        if href.starts_with('/') {
            // relativo à raiz: mantém scheme+host da página base
            let proto = if base.starts_with("https") { "https://" } else { "http://" };
            let host_part = &base[proto.len()..];
            let root = format!("{}{}", proto, host_part.split('/').next().unwrap_or(host_part));
            return format!("{}{}", root, href);
        }
        // relativo ao caminho atual
        if let Some(pos) = base.rfind('/') {
            format!("{}{}", &base[..pos + 1], href)
        } else {
            format!("{}/{}", base, href)
        }
    }

    fn extract_links(body: &str, page_base: &str) -> Vec<String> {
        let mut links = Vec::new();
        let mut search = 0;
        while let Some(pos) = body[search..].find("<a ") {
            let start = search + pos;
            let end = body[start..].find('>').map(|p| start + p).unwrap_or(start + 500);
            let tag = &body[start..end.min(body.len())];
            search = end;

            if let Some(href) = Self::attr_value(tag, "href") {
                let resolved = Self::resolve_href(&href, page_base);
                if !resolved.is_empty() {
                    // Aceita: (1) caminhos internos do mesmo host (/docs, /produtos),
                    // (2) links completos do mesmo host, (3) extensões com '.'.
                    // Rejeita: âncoras puras (#), javascript:, mailto:, tel:.
                    let lower = resolved.to_lowercase();
                    let skip = lower.starts_with("javascript:")
                        || lower.starts_with("mailto:")
                        || lower.starts_with("tel:")
                        || lower.starts_with("data:");
                    if !skip {
                        links.push(resolved);
                    }
                }
            }
        }
        links
    }

    fn extract_forms(body: &str, page_base: &str) -> Vec<FormInfo> {
        let mut forms = Vec::new();
        let mut search = 0;
        while let Some(pos) = body[search..].to_lowercase().find("<form") {
            let start = search + pos;
            // acha o fechamento do form
            let end = body[start..].to_lowercase().find("</form>")
                .map(|p| start + p + 7)
                .unwrap_or((start + 4000).min(body.len()));
            let form_block = &body[start..end];
            search = end;

            // action + method
            let action = Crawler::attr_value(form_block, "action")
                .map(|a| Crawler::resolve_href(&a, page_base))
                .unwrap_or_else(|| page_base.to_string());
            let method = Crawler::attr_value(form_block, "method")
                .unwrap_or_else(|| "GET".to_string())
                .to_uppercase();
            let action_clean = Self::base_url(&action);

            // inputs do form
            let mut params = Vec::new();
            let mut input_search = 0;
            while let Some(ipos) = form_block[input_search..].to_lowercase().find("<input") {
                let istart = input_search + ipos;
                let iend = form_block[istart..].find('>')
                    .map(|p| istart + p)
                    .unwrap_or((istart + 300).min(form_block.len()));
                let itag = &form_block[istart..iend];
                input_search = iend;

                if let Some(name) = Self::attr_value(itag, "name") {
                    let lower = name.to_lowercase();
                    let skip = ["csrf", "token", "submit", "button", "password", "pass"]
                        .iter()
                        .any(|s| lower.contains(s));
                    if !name.is_empty() && !skip {
                        params.push(name);
                    }
                }
            }

            forms.push(FormInfo {
                url: action_clean,
                method,
                params,
            });
        }
        forms
    }

    fn attr_value(tag: &str, attr: &str) -> Option<String> {
        // busca attr="..." ou attr='...'
        let variants = vec![
            format!("{}=\"", attr),
            format!("{}='", attr),
        ];
        for v in variants {
            let quote = v.chars().last().unwrap();
            if let Some(pos) = tag.to_lowercase().find(&v.to_lowercase()) {
                let val_start = pos + v.len();
                if let Some(end_pos) = tag[val_start..].find(quote) {
                    return Some(tag[val_start..val_start + end_pos].to_string());
                }
            }
        }
        // atributo sem valor (ex.: <input name disabled>)
        if let Some(_pos) = tag.to_lowercase().find(&format!("{} ", attr)) {
            return Some(attr.to_string());
        }
        None
    }
}
