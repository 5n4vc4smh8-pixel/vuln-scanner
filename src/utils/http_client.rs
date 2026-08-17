#![allow(dead_code)]
use reqwest::{Client, Proxy, Response, Error, header};
use std::time::Duration;
use log::debug;
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub struct SecureHttpClient {
    pub client: Arc<Client>,
    pub cookies: Option<String>,
}

impl SecureHttpClient {
    pub async fn new(
        timeout_secs: u64,
        proxy: Option<String>,
        cookie: Option<String>,
        custom_header: Option<String>,
    ) -> Result<Self, Error> {
        let mut headers = header::HeaderMap::new();
        
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("VulnScanner/0.1.0 (Security Research)")
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
            cookies: cookie 
        })
    }

    pub async fn get(&self, url: &str) -> Result<Response, Error> {
        debug!("GET {}", url);
        self.client.get(url).send().await
    }

    // GET SEM seguir redirects - necessario para detectar Open Redirect (302)
    pub async fn get_no_redirect(&self, url: &str) -> Result<Response, Error> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        client.get(url).send().await
    }

    pub async fn head(&self, url: &str) -> Result<Response, Error> {
        debug!("HEAD {}", url);
        self.client.head(url).send().await
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<Response, Error> {
        debug!("POST {} - Body: {}", url, body);
        self.client.post(url).body(body.to_string()).send().await
    }

    pub async fn post_json(&self, url: &str, body: &str) -> Result<Response, Error> {
        debug!("POST JSON {} - Body: {}", url, body);
        self.client.post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
    }

    pub async fn post_form(&self, url: &str, body: &str) -> Result<Response, Error> {
        debug!("POST FORM {} - Body: {}", url, body);
        self.client.post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string())
            .send()
            .await
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