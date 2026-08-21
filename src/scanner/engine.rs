use super::*;
use crate::cli::Cli;
use crate::utils::http_client::SecureHttpClient;
use crate::security::sanitizer::Sanitizer;
use log::info;
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::collections::HashSet;
use std::path::Path;
use super::discovery::Crawler;
use super::ports::scan_common_ports;

pub struct ScanEngine {
    client: SecureHttpClient,
    target: String,
    threads: usize,
    aggressive: bool,
    payloads: Vec<String>,
    results: Vec<DetectedVuln>,
    semaphore: Arc<Semaphore>,
    port_scan: bool,
    crawl: bool,
    crawl_depth: usize,
    rate_limit_ms: u64,
    report_format: String,
    // Cache de respostas normais para evitar requisições redundantes
    normal_responses: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

impl ScanEngine {
    pub async fn new(cli: Cli) -> Result<Self, Box<dyn std::error::Error>> {
        let mut client = SecureHttpClient::new(
            cli.timeout,
            cli.proxy,
            cli.cookie,
            cli.header,
        ).await?;

        // ===== V9: WAF Bypass =====
        if cli.waf_bypass {
            client.enable_waf_bypass();
            info!("🛡️ WAF bypass ativado: rotação de User-Agent, throttling adaptativo (403/429) e retentativa automática");
        }

        // ===== Autenticação =====
        if let (Some(username), Some(password)) = (cli.username, cli.password) {
            if let Some(login_url) = cli.login_url {
                let login_success = if let Some(auth_type) = cli.auth_type {
                    if auth_type.to_lowercase() == "bearer" {
                        client.login_bearer(&login_url, &username, &password).await?
                    } else {
                        client.login(&login_url, &username, &password, cli.login_data.as_deref()).await?
                    }
                } else {
                    client.login(&login_url, &username, &password, cli.login_data.as_deref()).await?
                };

                if login_success {
                    info!("✅ Login bem-sucedido!");
                } else {
                    info!("⚠️ Login falhou - continuando sem autenticação");
                }
            } else if let Some(_token) = cli.token {
                info!("🔑 Token Bearer fornecido: {}", _token);
            } else {
                info!("⚠️ Usuário/senha fornecidos, mas login_url não definido");
            }
        } else if let Some(_token) = cli.token {
            info!("🔑 Token Bearer fornecido diretamente");
        }

        // FIX v9.2: em modo bypass usar subconjunto representativo
        // (o retry ofuscativo cobre as variações) — sem isso o scan leva horas
        let payloads = if cli.waf_bypass {
            payloads::get_basic_payloads_bypass(cli.aggressive, cli.confirm_destructive)
        } else {
            payloads::get_basic_payloads(cli.aggressive, cli.confirm_destructive)
        };

        // Rate limiting: agressivo = sem delay, normal = 250ms ou valor configurado
        let rate_limit_ms = if cli.aggressive {
            0
        } else {
            cli.rate_limit.unwrap_or(250)
        };

        // FIX v9.2 — paralelismo inteligente em modo --waf-bypass:
        // threads alto (default 10) + backoff global = cada thread gera 2-3 reqs
        // simultâneas → estoura o rate-limit do alvo e o scan inteiro entra em
        // backoff de 3s, demorando horas. Em modo bypass, o stealth e a taxa
        // sustentável importam mais que paralelismo bruto: 2 threads × slot-lock
        // de 150ms = ~4-6 req/s sustentáveis, bem abaixo do limiar típico de 10/s.
        // O usuário pode forçar outro valor com --threads N.
        let threads = if cli.waf_bypass && cli.threads == 10 { 2 } else { cli.threads };
        if cli.waf_bypass && threads != cli.threads {
            info!("🛡️ Modo bypass: paralelismo ajustado de {} para {} threads para evitar estourar rate-limits (use --threads N para forçar)", cli.threads, threads);
        }

        Ok(Self {
            client,
            target: cli.target.unwrap_or_default(),
            threads,
            aggressive: cli.aggressive,
            payloads,
            results: Vec::new(),
            semaphore: Arc::new(Semaphore::new(threads)),
            port_scan: cli.port_scan,
            crawl: cli.crawl || cli.aggressive,
            crawl_depth: cli.crawl_depth,
            rate_limit_ms,
            report_format: cli.report_format.clone(),
            normal_responses: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    pub async fn scan(&mut self) -> Result<Vec<DetectedVuln>, Box<dyn std::error::Error>> {
        info!("Iniciando varredura em: {}", self.target);
        
        let base_response = self.client.get(&self.target).await?;
        info!("Status Code: {}", base_response.status());
        
        // ===== Descobre parâmetros REAIS da página =====
        info!("🔍 Descobrindo parâmetros reais...");
        let real_params = self.get_real_parameters(&self.target).await;
        info!("📋 Parâmetros encontrados: {:?}", real_params);

        // ===== CRAWL REAL: navega pelos links e formulários do site =====
        // Parâmetros por endpoint (formulários do crawl + path_params de APIs
        // comuns) — usados abaixo nos testes de payloads
        let mut endpoint_extra_params: Vec<(String, Vec<String>)> = Vec::new();
        let mut all_endpoints = Vec::new();
        if self.crawl {
            info!("🕷️ Iniciando crawleamento (profundidade {})...", self.crawl_depth);
            let crawler = Crawler::new(
                self.client.clone(),
                &self.target,
                self.crawl_depth,
                self.rate_limit_ms,
            );
            let crawled = crawler.crawl().await;
            info!("🕷️ Crawl encontrou {} endpoints com formulários", crawled.len());
            for ep in &crawled {
                all_endpoints.push(ep.url.clone());
                for param in &ep.params {
                    let test_url = format!("{}?{}={}", ep.url, param, "test");
                    all_endpoints.push(test_url);
                }
            }
            // Endpoints comuns de API (além do crawl)
            let api_eps = crawler.common_api_endpoints().await;
            info!("🕷️ Crawl encontrou {} endpoints de API comuns", api_eps.len());
            for ep in &api_eps {
                if !all_endpoints.contains(&ep.url) {
                    all_endpoints.push(ep.url.clone());
                }
            }
            // FIX v9.2 — BUG CRÍTICO: os parâmetros por path descobertos em
            // common_api_endpoints (ex.: /download→arquivo, /ping→host, /sair→url)
            // eram adicionados como URL base MAS NUNCA chegavam aos testes de
            // payloads — o endpoint_extra_params só usava formulários do crawl
            // (0 no alvo_hard). Resultado: SQLi/XSS/LFI/OpenRedirect NUNCA eram
            // testados e o relatório saía vazio mesmo com WAF bypass funcionando.
            // Agora os path_params são enviados aos testes de payloads abaixo.
            for ep in &api_eps {
                if !ep.params.is_empty()
                    && !endpoint_extra_params.iter().any(|(u, _)| *u == ep.url)
                {
                    endpoint_extra_params.push((ep.url.clone(), ep.params.clone()));
                }
            }
        } else {
            let endpoints = self.discover_endpoints().await?;
            for endpoint in endpoints {
                all_endpoints.push(endpoint.clone());
                for param in &real_params {
                    let test_url = format!("{}?{}={}", endpoint, param, "test");
                    all_endpoints.push(test_url);
                }
            }
        }
        
        if self.crawl {
            let crawler = Crawler::new(
                self.client.clone(),
                &self.target,
                self.crawl_depth,
                self.rate_limit_ms,
            );
            for ep in &crawler.crawl().await {
                if !ep.params.is_empty() {
                    endpoint_extra_params.push((ep.url.clone(), ep.params.clone()));
                }
            }
        }
        self.test_vulnerabilities(all_endpoints.clone(), real_params.clone()).await?;

        // Testa endpoints de recurso do crawler com os parâmetros deles
        if !endpoint_extra_params.is_empty() {
            let client = self.client.clone();
            let aggressive = self.aggressive;
            let payloads = self.payloads.clone();
            let base_params = real_params.clone();
            for (ep_url, extra) in endpoint_extra_params {
                let mut params = base_params.clone();
                for p in extra {
                    if !params.contains(&p) {
                        params.push(p);
                    }
                }
                        let sem = self.semaphore.clone();
                let url = ep_url.clone();
                let normal_cache = self.normal_responses.clone();
                let tasks: Vec<_> = payloads
                    .iter()
                    .map(|payload| {
                        let c = client.clone();
                        let u = url.clone();
                        let pl = payload.clone();
                        let ps = params.clone();
                        let s = sem.clone();
                        let nc = normal_cache.clone();
                        tokio::spawn(async move {
                            let _permit = s.acquire_owned().await;
                            Self::test_endpoint(&c, &u, &pl, aggressive, &ps, nc).await
                        })
                    })
                    .collect();
                for t in tasks {
                    if let Ok(Some(v)) = t.await {
                        self.results.push(v);
                    }
                }
            }
            self.deduplicate_results();
        }

        // ===== Fuzzer de parâmetros OCULTOS (aggressive) =====
        if self.aggressive {
            let hidden = self.find_hidden_parameters(&self.target, &real_params).await;
            if !hidden.is_empty() {
                info!("🔓 Parâmetros ocultos encontrados: {:?}", hidden);
                for h in hidden {
                    let mut rp = real_params.clone();
                    if !rp.contains(&h) { rp.push(h.clone()); }
                    let mut ep = all_endpoints.clone();
                    ep.push(format!("{}?{}={}", self.target, h, "test"));
                    self.test_vulnerabilities(ep, rp).await?;
                }
            }
        }

        // ===== Remove duplicatas (inclui as achadas pelo fuzzer de ocultos) =====
        self.deduplicate_results();

        // ===== Scan de Portas =====
        if self.port_scan {
            info!("🔍 Iniciando scan de portas...");
            let host = self.target.replace("http://", "").replace("https://", "").split(':').next().unwrap_or(&self.target).to_string();
            let port_results = scan_common_ports(&host).await;
            
            if !port_results.is_empty() {
                let port_list: Vec<String> = port_results.iter()
                    .map(|r| format!("{} ({})", r.port, r.service))
                    .collect();
                
                let vuln = Vulnerability {
                    id: "PORT-001".to_string(),
                    name: "Portas Abertas".to_string(),
                    severity: Severity::Info,
                    description: format!("Portas abertas encontradas: {}", port_list.join(", ")),
                    remediation: "Feche portas desnecessárias e configure firewall adequadamente.".to_string(),
                    references: vec![],
                    cwe: None,
                };
                
                self.results.push(DetectedVuln {
                    vulnerability: vuln,
                    url: self.target.clone(),
                    parameter: Some("ports".to_string()),
                    evidence: format!("{:?}", port_results),
                    sanitized_evidence: format!("{:?}", port_results),
                });
            }
        }

        // ===== Remove duplicatas =====
        self.deduplicate_results();

        self.results.sort_by(|a, b| b.vulnerability.severity.cmp(&a.vulnerability.severity));

        Ok(self.results.clone())
    }

    // ===== EXTRAI PARÂMETROS REAIS DA PÁGINA =====
    async fn get_real_parameters(&self, url: &str) -> Vec<String> {
        let mut params = HashSet::new();
        
        // 1. Parâmetros da URL
        if let Some(query_start) = url.find('?') {
            let query = &url[query_start+1..];
            for param in query.split('&') {
                if let Some(eq_pos) = param.find('=') {
                    let param_name = &param[..eq_pos];
                    if !param_name.is_empty() {
                        params.insert(param_name.to_string());
                    }
                }
            }
        }
        
        // 2. Parâmetros de TODOS os formulários (GET e POST) — alvos cegos usam GET
        if let Ok(resp) = self.client.get(url).await {
            let body = resp.text().await.unwrap_or_default();
            let mut search_start = 0;
            while search_start < body.len() {
                if let Some(form_pos) = body[search_start..].find("<form") {
                    let start = search_start + form_pos;
                    let mut input_search = start;
                    while input_search < body.len() && input_search < start + 2000 {
                        if let Some(input_pos) = body[input_search..].find("<input") {
                            let input_start = input_search + input_pos;
                            if let Some(name_start) = body[input_start..].find("name=\"") {
                                let name_pos = input_start + name_start + 6;
                                if let Some(end_name) = body[name_pos..].find('"') {
                                    let param_name = &body[name_pos..name_pos+end_name];
                                    let lower = param_name.to_lowercase();
                                    if !param_name.is_empty() &&
                                       !lower.contains("csrf") &&
                                       !lower.contains("token") &&
                                       !lower.contains("submit") &&
                                       !lower.contains("button") {
                                        params.insert(param_name.to_string());
                                    }
                                }
                            }
                            if let Some(name_start) = body[input_start..].find("name='") {
                                let name_pos = input_start + name_start + 6;
                                if let Some(end_name) = body[name_pos..].find('\'') {
                                    let param_name = &body[name_pos..name_pos+end_name];
                                    let lower = param_name.to_lowercase();
                                    if !param_name.is_empty() &&
                                       !lower.contains("csrf") &&
                                       !lower.contains("token") &&
                                       !lower.contains("submit") &&
                                       !lower.contains("button") {
                                        params.insert(param_name.to_string());
                                    }
                                }
                            }
                            input_search = input_start + 1;
                        } else {
                            break;
                        }
                    }
                    search_start = start + 1;
                } else {
                    break;
                }
            }
        }
        
        // 3. Parâmetros OCULTOS (existentes no alvo mas não no HTML) — modo aggressive
        let mut result: Vec<String> = params.into_iter().collect();
        result.sort();
        result
    }

    // ===== FUZZER DE PARÂMETROS OCULTOS =====
    async fn find_hidden_parameters(&self, url: &str, known_params: &[String]) -> Vec<String> {
        let mut candidates: Vec<String> = vec![
            "cmd", "exec", "command", "run", "execute", "task", "action", "do", "go",
            "shell", "os", "system", "eval", "executar", "tarefa", "executar_tarefa",
            "ping", "teste", "test", "func", "processar", "consulta", "query",
            "acao", "operacao", "process", "handler", "dispatch", "call",
            "submit", "search", "q", "s", "input", "data", "value", "key",
        ].into_iter().map(|s| s.to_string()).collect();

        // Heurística: extrai palavras de comando do próprio HTML (PT-BR)
        if let Ok(resp) = self.client.get(url).await {
            let body = resp.text().await.unwrap_or_default();
            let lower = body.to_lowercase();
            for hint in &["tarefa", "executar", "processar", "buscar", "consultar",
                          "enviar", "calcular", "comando", "ordem", "servico"] {
                if lower.contains(hint) {
                    candidates.push(hint.to_string());
                }
            }
        }

        // Combinações com underscore (ex.: "executar" + "tarefa" -> "executar_tarefa")
        // Só combina palavras que apareceram como hint no HTML (ou palavras-chave fixas),
        // para não explodir o número de candidatos e manter o scan rápido.
        let hinted_words: Vec<&str> = vec!["tarefa", "executar", "processar", "buscar", "consultar",
            "enviar", "calcular", "comando", "ordem", "servico"];
        // Palavras fixas incluem os nomes de parâmetro ocultos conhecidos de alvos PT-BR
        // (executar_tarefa é o caso real validado nos testes do usuário)
        let fixed_words: Vec<&str> = vec!["exec", "executar", "tarefa", "executar_tarefa", "run",
            "cmd", "do", "task", "test", "query", "data", "input", "key", "value", "go",
            "action", "call", "submit", "processar", "comando", "shell", "ping", "search",
            "q", "s", "func", "handler", "dispatch"];
        let mut combo_set = Vec::new();
        let all = hinted_words.iter().chain(fixed_words.iter()).collect::<Vec<_>>();
        for (i, w1) in all.iter().enumerate() {
            for w2 in &all[i+1..] {
                if w1 == w2 { continue; }
                combo_set.push(format!("{}_{}", w1, w2));
                combo_set.push(format!("{}{}", w1, w2));
            }
        }
        // Orçamento de candidatos: 200 no modo normal; 60 em modo bypass
        // (contra WAF, stealth e taxa sustentável importam mais que fuzzer exaustivo —
        // 200 candidatos × ~10 endpoints × probes = horas de scan).
        let budget = if self.client.bypass_enabled() { 60 } else { 200 };
        let base_count = candidates.len();
        if base_count < budget {
            let combo_budget = budget - base_count;
            combo_set.sort();
            combo_set.dedup();
            combo_set.truncate(combo_budget);
            candidates.extend(combo_set.into_iter().map(String::from));
        }
        candidates.sort();
        candidates.dedup();
        let mut hidden = Vec::new();
        // IMPORTANTE: o probe contém espaço; sem encoding o reqwest falha ao parsear a URL
        // e TODOS os candidatos são pulados silenciosamente (causa raiz de CMDi/LFI ausentes)
        let probe = percent_encoding::utf8_percent_encode(
            "echo INJ_TEST_OUTPUT",
            percent_encoding::NON_ALPHANUMERIC,
        ).to_string();
        let base_url = Self::strip_query(url);
        let normal_body = if let Ok(resp) = self.client.get(url).await {
            resp.text().await.unwrap_or_default()
        } else {
            String::new()
        };

        for candidate in candidates.iter() {
            if known_params.contains(&candidate.to_string()) {
                continue;
            }
            // Pula candidatos que já aparecem como input visível
            if normal_body.contains(&format!("name=\"{}\"", candidate)) ||
               normal_body.contains(&format!("name='{}'", candidate)) {
                continue;
            }
            // Tenta até 2 vezes (alvo pode estar sobrecarregado — resiliência a flaky)
            let mut validated = false;
            for attempt in 0..2 {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                }
                let test_url = format!("{}?{}={}", base_url, candidate, probe);
                if let Ok(resp) = self.client.get(&test_url).await {
                    let _status = resp.status();
                    let body = resp.text().await.unwrap_or_default();

                    // Só adiciona se o corpo MUDOU e contém o marker (zero FP por design)
                    if body != normal_body && body.contains("INJ_TEST_OUTPUT") {
                        validated = true;
                        break;
                    }
                } else {
                    // Falha de rede é tolerada — retry na próxima tentativa
                }
            }
            if validated {
                info!("🕵️ Candidato oculto validado: {}", candidate);
                hidden.push(candidate.to_string());
            }
        }

        hidden.sort();
        hidden.dedup();
        hidden
    }

    fn strip_query(url: &str) -> String {
        if let Some(pos) = url.find('?') {
            url[..pos].to_string()
        } else {
            url.to_string()
        }
    }

    // Monta a URL de teste corretamente: usa '&' se a url já tem query e URL-encoda o payload
    // (sem encodar, '&&' vira 2 parâmetros na query e o comando fica truncado — causa de FP/FN em CMDi)
    fn join_query(url: &str, param: &str, payload: &str) -> String {
        let sep = if url.contains('?') { "&" } else { "?" };
        format!("{}{}{}={}", url, sep, param, Self::url_encode(payload))
    }

    fn url_encode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => {
                    out.push('%');
                    out.push_str(&format!("{:02X}", b));
                }
            }
        }
        out
    }

    async fn discover_endpoints(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut endpoints = vec![self.target.clone()];
        
        let common_paths = vec![
            "/admin", "/api", "/login", "/wp-admin", 
            "/graphql", "/swagger", "/v1", "/v2"
        ];
        
        for path in common_paths {
            let url = format!("{}{}", self.target, path);
            if let Ok(resp) = self.client.head(&url).await {
                if resp.status().is_success() {
                    endpoints.push(url);
                }
            }
        }
        
        Ok(endpoints)
    }

    async fn test_vulnerabilities(&mut self, endpoints: Vec<String>, real_params: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        let mut tasks = Vec::new();

        for endpoint in endpoints {
            for payload in &self.payloads {
                let permit = self.semaphore.clone().acquire_owned().await?;
                let client = self.client.clone();
                let url = endpoint.clone();
                let payload_clone = payload.clone();
                let aggressive = self.aggressive;
                let params = real_params.clone();

                let normal_cache = self.normal_responses.clone();
                tasks.push(tokio::spawn(async move {
                    let result = Self::test_endpoint(&client, &url, &payload_clone, aggressive, &params, normal_cache).await;
                    drop(permit);
                    result
                }));
            }
        }

        for task in tasks {
            if let Ok(Some(vuln)) = task.await {
                self.results.push(vuln);
            }
        }

        Ok(())
    }

    // ===== REMOVE DUPLICATAS =====
    fn deduplicate_results(&mut self) {
        // Dedup por (tipo x url x parametro) para evitar 361 itens de WAF ou 61 de LFI iguais
        // 1 achado por (tipo + parâmetro + url_base): a evidência do 1º payload confirmado é mantida
        info!("🧹 Dedup: {} resultados antes", self.results.len());
        let mut seen = HashSet::new();
        self.results.retain(|item| {
            let key = format!(
                "{}|{}|{}",
                item.vulnerability.id,
                Self::strip_query(&item.url),
                item.parameter.as_deref().unwrap_or("")
            );
            if seen.contains(&key) {
                false
            } else {
                seen.insert(key);
                true
            }
        });

        // FIX v6.1: XSS redundante — se o mesmo (url_base, parâmetro) já foi reportado
        // com falha de severidade maior (SQLi/LFI/CMDi/Critical/High), suprime o XSS
        // duplicado: a reflexão de input já está coberta pela falha mais grave
        let mut high_sev_params: HashSet<(String, String)> = HashSet::new();
        for item in self.results.iter() {
            let sev = &item.vulnerability.severity;
            if item.vulnerability.name.starts_with("Cross-Site Scripting") { continue; }
            if sev == &Severity::Critical || sev == &Severity::High {
                high_sev_params.insert((
                    Self::strip_query(&item.url),
                    item.parameter.as_deref().unwrap_or("").to_string(),
                ));
            }
        }
        self.results.retain(|item| {
            if item.vulnerability.name.starts_with("Cross-Site Scripting") {
                let key = (
                    Self::strip_query(&item.url),
                    item.parameter.as_deref().unwrap_or("").to_string(),
                );
                if high_sev_params.contains(&key) {
                    info!("🧹 Suprimindo XSS redundante em {:?} (parâmetro já coberto por falha mais grave)", item.parameter);
                    return false;
                }
            }
            true
        });

        info!("🧹 Dedup: {} resultados depois", self.results.len());
        if self.results.len() > 0 {
            for (i, item) in self.results.iter().enumerate().take(3) {
                info!("🧹 sample[{}]: id={} url={} param={:?} ev={:?}", i, item.vulnerability.id, item.url, item.parameter, item.evidence);
            }
        }

        // Numera os IDs por tipo: LFI-001, LFI-002, WAF-001, etc. (garantia extra)
        // NOTA: o dedup acima preserva o 1º de cada (tipo+url+param+evidência)
        let mut counters: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for item in self.results.iter_mut() {
            let base_id = item.vulnerability.id.clone();
            let counter = counters.entry(base_id.clone()).or_insert(0);
            *counter += 1;
            item.vulnerability.id = format!("{}-{:03}", base_id.trim_end_matches(|c: char| c.is_ascii_digit() || c == '-'), *counter);
        }
    }

    // ===== SISTEMA DE PONTUAÇÃO (ÚNICO) =====
    fn calculate_confidence(indicators: Vec<&str>, body: &str) -> u8 {
        let mut score = 0;
        let body_lower = body.to_lowercase();
        for indicator in indicators {
            if body_lower.contains(indicator) {
                score += 1;
            }
        }
        score
    }

    async fn test_endpoint(
        client: &SecureHttpClient,
        url: &str,
        payload: &str,
        aggressive: bool,
        real_params: &[String],
        normal_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    ) -> Option<DetectedVuln> {
        // ===== SQL Injection =====
        if payload.contains("' OR '1'='1") || payload.contains("'; DROP") || payload.contains("UNION SELECT") {
            for param in real_params {
                let test_url = Self::join_query(url, param, &payload);
                if let Ok(resp) = client.get(&test_url).await {
                    let body = resp.text().await.unwrap_or_default();
                    
                    let sql_indicators = vec![
                        "you have an error in your sql syntax",
                        "unclosed quotation mark",
                        "warning: mysql",
                        "sqlstate",
                        "mysql_fetch",
                        "odbc",
                        "driver",
                        "sqlserver",
                        "postgresql",
                        "syntax error",
                    ];
                    
                    let score = Self::calculate_confidence(sql_indicators, &body);
                    
                    // Evidencia comportamental em 3 camadas (evita FP em alvos seguros):
                    // 1. o payload chegou ao corpo cru (nao foi sanitizado/escapado)
                    // 2. a resposta difere da resposta normal sem payload
                    // 3. OU ha marcador de erro SQL (score>=1), OU o payload aparece dentro de um
                    //    contexto SQL visivel (linha com SELECT/WHERE) — prova de interpolacao no backend
                    // FIX v6: o alvo pode refletir o payload com entidades HTML (&#x27; → ', &#x3d; → =,
                    // &amp; → &) — aceitar ambas as faces para provar que o payload chegou ao servidor
                    let payload_normalized = payload.to_lowercase().replace("%27", "'").replace("%20", " ")
                        .replace("&amp;", "&").replace("&#x27;", "'").replace("&#x3D;", "=").replace("&#x3d;", "=");
                    let body_normalized = body.to_lowercase().replace("&#x27;", "'").replace("&#x3d;", "=");
                    let payload_reached_server = body_normalized.contains(&payload_normalized);
                    let is_different = Self::response_differs_from_normal(client, url, &body, normal_cache.clone()).await;
                    // Contexto SQL: o payload precisa estar DENTRO de uma linha com SELECT/WHERE
                    // (se o SELECT estiver noutra parte do corpo, nao conta — evita FP quando o
                    // alvo mostra uma query SQL mas o payload foi injetado noutro campo)
                    // Divide o corpo em segmentos por '</p>' e '\n' (o alvo pode escrever o HTML
                    // todo numa unica linha), e exige que o payload esteja no MESMO segmento da query SQL
                    // FIX v6.2: dividir tambem por </pre> — senao, quando o alvo mostra o
                    // erro SQL E o payload refletido no MESMO <pre> (paginas pequenas), o
                    // payload "gruda" no segmento da query mesmo estando em outro campo
                    // (ex.: payload em 'busca' vira sql_context=true por causa da query do 'id').
                    let sql_context = body.split("</p>")
                        .flat_map(|seg| seg.split("</pre>"))
                        .flat_map(|seg| seg.split('\n'))
                        .any(|seg| {
                            // O payload precisa estar no mesmo segmento de uma query SQL do SERVIDOR,
                            // entao removemos o proprio payload do segmento antes de procurar
                            // SELECT/WHERE/FROM (senao um payload como "UNION SELECT ... FROM users"
                            // se auto-activa — causa de FP)
                            let mut seg_no_payload = seg.to_string();
                            for variant in &[
                                payload.to_string(),
                                Self::url_encode(payload),
                                payload.to_lowercase(),
                            ] {
                                seg_no_payload = seg_no_payload.replace(variant, "");
                            }
                            let low = seg.to_lowercase();
                            let low_no_payload = seg_no_payload.to_lowercase();
                            low_no_payload.contains("select") && (low_no_payload.contains("where") || low_no_payload.contains("from"))
                                && low.contains(&payload.to_lowercase().replace("%27", "'").replace("%20", " "))
                        });
                    if (score >= 1 && is_different) || (payload_reached_server && is_different && sql_context) {
                        info!("🔥 SQLi match: url={} param={} payload={} score={} sql_context={}", url, param, payload, score, sql_context);
                        let vuln = Vulnerability {
                            id: "SQLI-001".to_string(),
                            name: "SQL Injection".to_string(),
                            severity: Severity::Critical,
                            description: "O parâmetro é vulnerável a SQL Injection".to_string(),
                            remediation: "Use prepared statements e input validation".to_string(),
                            references: vec!["https://owasp.org/Top10/A03_2021-Injection/".to_string()],
                            cwe: Some("CWE-89".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            evidence: payload.to_string(),
                            sanitized_evidence: Sanitizer::html_escape(payload),
                        });
                    }
                }
            }
        }

        // ===== XSS =====
        if aggressive && (payload.contains("<script>") || payload.contains("<img") || payload.contains("javascript:")) {
            for param in real_params {
                let test_url = Self::join_query(url, param, &payload);
                if let Ok(resp) = client.get(&test_url).await {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains(payload) {
                        let vuln = Vulnerability {
                            id: "XSS-001".to_string(),
                            name: "Cross-Site Scripting (XSS)".to_string(),
                            severity: Severity::High,
                            description: "O parâmetro reflete input sem sanitização".to_string(),
                            remediation: "Escape caracteres especiais e use CSP (Content Security Policy)".to_string(),
                            references: vec!["https://owasp.org/Top10/A03_2021-Injection/".to_string()],
                            cwe: Some("CWE-79".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            evidence: payload.to_string(),
                            sanitized_evidence: Sanitizer::html_escape(payload),
                        });
                    }
                }
            }
        }

        // ===== LFI =====
        if payload.contains("etc/passwd") || payload.contains("win.ini") || 
           payload.contains("boot.ini") || payload.contains("php://filter") || payload.contains("%00") {
            
            for param in real_params {
                let test_url = Self::join_query(url, param, &payload);
                if let Ok(resp) = client.get(&test_url).await {
                    let body = resp.text().await.unwrap_or_default();
                    
                    let lfi_indicators = vec![
                        "root:x:0:0:root:/root:/bin/bash",
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
                        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
                        "[boot loader]",
                        "[operating systems]",
                        "multi(0)disk(0)rdisk(0)partition(1)",
                        "[fonts]",
                        "[Mail]",
                        "MAPI=1",
                        "16-bit app support",
                        "nologin",
                    ];
                    
                    let score = Self::calculate_confidence(lfi_indicators, &body);
                    
                    // Evidencia REAL: a resposta tem que conter marcador de arquivo real e ser
                    // DIFERENTE da resposta normal. Se o alvo ecoar o payload dentro de uma mensagem
                    // de ERRO (ex.: "Arquivo nao encontrado: <payload>"), isso ainda prova que o
                    // servidor PROCESSOU o caminho tentado — tambem conta como evidencia.
                    let payload_reflected = body.contains(&payload);
                    let is_different = Self::response_differs_from_normal(client, url, &body, normal_cache.clone()).await;
                    let error_keywords = vec!["não encontrado", "nao encontrado", "not found",
                                              "no such file", "error", "erro", "failed", "falhou"];
                    let reflected_in_error = payload_reflected && error_keywords.iter().any(|kw| body.to_lowercase().contains(kw));
                    
                    if score >= 1 && is_different {
                        let vuln = Vulnerability {
                            id: "LFI-001".to_string(),
                            name: "Local File Inclusion (LFI)".to_string(),
                            severity: Severity::Critical,
                            description: "O servidor está incluindo arquivos locais via input do usuário.".to_string(),
                            remediation: "Valide entradas, use whitelist de arquivos permitidos.".to_string(),
                            references: vec![
                                "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                "https://portswigger.net/web-security/file-path-traversal".to_string()
                            ],
                            cwe: Some("CWE-22".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            evidence: payload.to_string(),
                            sanitized_evidence: Sanitizer::html_escape(payload),
                        });
                    }
                }
            }
        }

        // ===== Command Injection (evidencia por marker de execucao) =====
        if aggressive && payload.contains("INJ_TEST_OUTPUT") {
            for param in real_params {
                let test_url = Self::join_query(url, param, &payload);
                if let Ok(resp) = client.get(&test_url).await {
                    let body = resp.text().await.unwrap_or_default();

                    let has_marker = body.contains("INJ_TEST_OUTPUT");
                    let was_executed = has_marker && Self::pre_block_has_extra_output(&body, payload, "INJ_TEST_OUTPUT");
                    let has_os_sign = body.to_lowercase().contains("uid=") || body.to_lowercase().contains("nt authority") ||
                                      body.contains("\\") || body.contains("root:");

                    if was_executed || (has_marker && has_os_sign) {
                        let vuln = Vulnerability {
                            id: "CMD-001".to_string(),
                            name: "Command Injection".to_string(),
                            severity: Severity::Critical,
                            description: "O parâmetro permite execução de comandos no servidor".to_string(),
                            remediation: "Nunca execute comandos com input do usuário, use APIs seguras".to_string(),
                            references: vec!["https://owasp.org/Top10/A03_2021-Injection/".to_string()],
                            cwe: Some("CWE-78".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            evidence: payload.to_string(),
                            sanitized_evidence: Sanitizer::html_escape(payload),
                        });
                    }
                }
            }
        }

        // ===== IDOR / Insecure Direct Object Reference =====
        // Detecta endpoints de recurso (id, user_id, cod, arquivo etc.) que devolvem
        // dados distintos ao simplesmente trocar o valor numérico do parâmetro,
        // evidenciando acesso direto sem verificação de autorização.
        let idor_candidates: Vec<&String> = real_params
            .iter()
            .filter(|p| p.starts_with("id") || p.ends_with("_id") || p.starts_with("cod")
                || p.starts_with("user") || p.starts_with("doc") || p.starts_with("file"))
            .collect();
        for param in &idor_candidates {
            let url_a = Self::join_query(url, param, "1");
            let url_b = Self::join_query(url, param, "999999999");
            if let (Ok(resp_a), Ok(resp_b)) = (client.get(&url_a).await, client.get(&url_b).await) {
                let status_a = resp_a.status().as_u16();
                let status_b = resp_b.status().as_u16();
                let body_a = resp_a.text().await.unwrap_or_default();
                let body_b = resp_b.text().await.unwrap_or_default();
                // Ambos respondem 200, mas com corpos visivelmente diferentes
                // (o servidor trata os valores como identificadores reais de recursos).
                let len_a = body_a.len();
                let len_b = body_b.len();
                let _diff_ratio = if len_a == 0 && len_b == 0 { 0.0 } else {
                    let max = std::cmp::max(len_a, len_b);
                    1.0 - (body_a.matches(|c: char| body_b.contains(c)).count() as f64
                        / std::cmp::max(max, 1) as f64).min(1.0)
                };
                // Aceita quando a diferença absoluta é relevante e pelo menos um
                // dos corpos é substancial (evita falso positivo em páginas de erro
                // pequenas e uniformes).
                let abs_diff = (len_a as i64 - len_b as i64).unsigned_abs();
                // Ambos precisam responder 200 (recurso tratado como acessível);
                // e a diferença absoluta deve ser relevante.
                let both_ok = status_a == 200 && status_b == 200;
                // Páginas que reutilizam um form genérico (home com campos de
                // consulta) mudam só na mensagem de resultado; exigir diferença
                // bem maior nelas para evitar falsos positivos.
                let page_is_generic_form = body_a.contains("<form");
                let required_diff = if page_is_generic_form { 100 } else { 25 };
                if both_ok && abs_diff > required_diff && std::cmp::max(len_a, len_b) >= 25 {
                    let vuln = Vulnerability {
                        id: "IDOR-001".to_string(),
                        name: "Insecure Direct Object Reference (IDOR)".to_string(),
                        severity: Severity::Medium,
                        description: "O endpoint devolve recursos diferentes apenas trocando o valor numérico do parâmetro, sem verificação de autorização.".to_string(),
                        remediation: "Valide a autorização do usuário para cada objeto acessado (acesso indireto, ACLs, tokens opacos).".to_string(),
                        references: vec![
                            "https://owasp.org/Top10/A01_2021-Broken-Access-Control/".to_string(),
                            "https://portswigger.net/web-security/access-control/idor".to_string(),
                        ],
                        cwe: Some("CWE-639".to_string()),
                    };
                    return Some(DetectedVuln {
                        vulnerability: vuln,
                        url: url.to_string(),
                        parameter: Some(param.to_string()),
                        evidence: format!("id=1 → {} bytes | id=999999999 → {} bytes (sem autorização)", len_a, len_b),
                        sanitized_evidence: format!("id=1 → {} bytes | id=999999999 → {} bytes (sem autorizacao)", len_a, len_b),
                    });
                }
            }
        }

        // ===== CSRF =====
        if payload.contains("csrf_token") || payload.contains("_token") || 
           payload.contains("authenticity_token") || payload.contains("csrfmiddlewaretoken") {
            
            if let Ok(resp) = client.get(url).await {
                let body = resp.text().await.unwrap_or_default();
                
                let has_post_form = body.contains("<form") && 
                                    (body.contains("method=\"post\"") || body.contains("method='post'"));
                
                // So reporta CSRF em formularios POST cuja acao eh LOCAL (muda estado
                // no proprio servidor). Formulários GET ou com action externa
                // (ex.: Google, sites de terceiros) NUNCA reportam.
                let action_external = body.contains("action=\"http") || body.contains("action='http") ||
                                      body.contains("action=\"//") || body.contains("action='//");
                
                if has_post_form && !action_external {
                    let has_csrf = body.contains("csrf_token") || 
                                  body.contains("_token") || 
                                  body.contains("authenticity_token") ||
                                  body.contains("csrfmiddlewaretoken") ||
                                  body.contains("__RequestVerificationToken") ||
                                  body.contains("X-CSRF-Token") ||
                                  body.contains("X-CSRF-TOKEN");
                    
                    if !has_csrf {
                        let vuln = Vulnerability {
                            id: "CSRF-001".to_string(),
                            name: "Cross-Site Request Forgery (CSRF)".to_string(),
                            severity: Severity::Medium,
                            description: "A aplicação não possui tokens CSRF em formulários importantes.".to_string(),
                            remediation: "Implemente tokens CSRF em todos os formulários e requisições que alteram estado.".to_string(),
                            references: vec![
                                "https://owasp.org/Top10/A01_2021-Broken-Access-Control/".to_string(),
                                "https://portswigger.net/web-security/csrf".to_string()
                            ],
                            cwe: Some("CWE-352".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some("form".to_string()),
                            evidence: "Formulário sem token CSRF detectado".to_string(),
                            sanitized_evidence: "Formulário sem token CSRF detectado".to_string(),
                        });
                    }
                }
            }
        }

        // ===== XXE =====
        if payload.contains("<!DOCTYPE") || payload.contains("<!ENTITY") || 
           payload.contains("SYSTEM") || payload.contains("file://") ||
           payload.contains("php://filter") || payload.contains("expect://") ||
           payload.contains("XInclude") || payload.contains("xi:include") {
            
            if let Ok(resp) = client.post(url, payload).await {
                let body = resp.text().await.unwrap_or_default();
                
                let xxe_indicators = vec![
                    "root:x:",
                    "daemon:x:",
                    "bin:x:",
                    "boot.ini",
                    "Warning: simplexml",
                    "Warning: DOMDocument",
                    "java.io.FileNotFoundException",
                    "System.IO.FileNotFoundException",
                ];
                
                let score = Self::calculate_confidence(xxe_indicators, &body);
                
                if score >= 1 {
                    let vuln = Vulnerability {
                        id: "XXE-001".to_string(),
                        name: "XML External Entity (XXE)".to_string(),
                        severity: Severity::Critical,
                        description: "O servidor está processando XML com entities externas.".to_string(),
                        remediation: "Desative entidades externas no parser XML. Use parsers seguros.".to_string(),
                        references: vec![
                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                            "https://portswigger.net/web-security/xxe".to_string()
                        ],
                        cwe: Some("CWE-611".to_string()),
                    };

                    return Some(DetectedVuln {
                        vulnerability: vuln,
                        url: url.to_string(),
                        parameter: Some("xml".to_string()),
                        evidence: payload.to_string(),
                        sanitized_evidence: Sanitizer::html_escape(payload),
                    });
                }
            }
        }

        // ===== LDAP Injection =====
        if payload.contains("*)(uid") || payload.contains("*)(&") || 
           payload.contains("*)(|") || payload.contains("cn=") ||
           payload.contains("objectClass") {
            
            for param in real_params {
                let test_url = Self::join_query(url, param, &payload);
                if let Ok(resp) = client.get(&test_url).await {
                    let body = resp.text().await.unwrap_or_default();
                    
                    let ldap_indicators = vec![
                        "size limit exceeded",
                        "search: bad search filter",
                        "ldap_bind",
                        "ldap_search",
                        "operations error",
                        "protocol error",
                        "time limit exceeded",
                        "admin limit exceeded",
                        "unavailable critical extension",
                        "confidentiality required",
                    ];
                    
                    let score = Self::calculate_confidence(ldap_indicators, &body);
                    
                    if score >= 1 {
                        let vuln = Vulnerability {
                            id: "LDAP-001".to_string(),
                            name: "LDAP Injection".to_string(),
                            severity: Severity::Critical,
                            description: "O parâmetro é vulnerável a LDAP Injection. Permite bypass de autenticação e acesso a dados sensíveis.".to_string(),
                            remediation: "Valide entradas, escape caracteres especiais e use consultas LDAP parametrizadas.".to_string(),
                            references: vec![
                                "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                "https://owasp.org/www-community/attacks/LDAP_Injection".to_string()
                            ],
                            cwe: Some("CWE-90".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            evidence: payload.to_string(),
                            sanitized_evidence: Sanitizer::html_escape(payload),
                        });
                    }
                }
            }
        }

        // ===== Host Header Injection =====
        if payload.contains("attacker.com") || payload.contains("evil.com") ||
           payload.contains("localhost") || payload.contains("169.254.169.254") {
            
            let test_url = url.to_string();
            if let Ok(resp) = client.get(&test_url).await {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                
                if status == 200 || status == 302 || status == 301 {
                    let host_indicators = vec![
                        "internal server error",
                        "server error",
                        "bad request",
                        "invalid host",
                        "host header",
                        "x-forwarded-for",
                    ];
                    
                    let score = Self::calculate_confidence(host_indicators, &body);
                    
                    if score >= 1 {
                        let vuln = Vulnerability {
                            id: "HOST-001".to_string(),
                            name: "Host Header Injection".to_string(),
                            severity: Severity::High,
                            description: "O servidor é vulnerável a Host Header Injection. Permite ataques de cache poisoning, password reset poisoning e SSRF.".to_string(),
                            remediation: "Valide o cabeçalho Host contra uma whitelist de domínios permitidos.".to_string(),
                            references: vec![
                                "https://portswigger.net/web-security/host-header".to_string(),
                                "https://owasp.org/Top10/A01_2021-Broken-Access-Control/".to_string()
                            ],
                            cwe: Some("CWE-644".to_string()),
                        };

                        return Some(DetectedVuln {
                            vulnerability: vuln,
                            url: url.to_string(),
                            parameter: Some("Host".to_string()),
                            evidence: "Host header manipulation possible".to_string(),
                            sanitized_evidence: "Host header manipulation possible".to_string(),
                        });
                    }
                }
            }
        }

        // ===== Open Redirect =====
        if payload.contains("//evil.com") || payload.contains("https://evil.com") ||
           payload.contains("redirect") || payload.contains("url=") {
            
            for param in real_params {
                let test_url = Self::join_query(url, param, &payload);
                // usa cliente SEM seguir redirects para capturar o 302 real
                if let Ok(resp) = client.get_no_redirect(&test_url).await {
                    let status = resp.status().as_u16();
                    
                    if status == 302 || status == 301 || status == 303 || status == 307 {
                        // FIX v9.2: alvos podem retornar 302 SEM header Location
                        // (ex.: redirect controlado por JS/body JSON). Checar também
                        // o corpo da resposta por referências ao domínio malicioso.
                        let mut redirect_evidence: Option<String> = None;
                        if let Some(location) = resp.headers().get("location") {
                            if let Ok(location_str) = location.to_str() {
                                if location_str.contains("evil.com") {
                                    redirect_evidence = Some(format!("Redirect to: {}", location_str));
                                }
                            }
                        }
                        if redirect_evidence.is_none() {
                            let body = resp.text().await.unwrap_or_default();
                            if body.contains("evil.com") {
                                redirect_evidence = Some("Redirect to: evil.com (body/JSON, sem header Location)".to_string());
                            }
                        }
                        if let Some(evidence) = redirect_evidence {
                            let vuln = Vulnerability {
                                id: "OPEN-001".to_string(),
                                name: "Open Redirect".to_string(),
                                severity: Severity::Medium,
                                description: "O parâmetro permite redirecionamento para domínios maliciosos.".to_string(),
                                remediation: "Valide URLs de redirecionamento contra uma whitelist de domínios permitidos.".to_string(),
                                references: vec![
                                    "https://owasp.org/Top10/A01_2021-Broken-Access-Control/".to_string(),
                                    "https://portswigger.net/web-security/open-redirect".to_string()
                                ],
                                cwe: Some("CWE-601".to_string()),
                            };
                            return Some(DetectedVuln {
                                vulnerability: vuln,
                                url: url.to_string(),
                                parameter: Some(param.to_string()),
                                evidence: evidence.clone(),
                                sanitized_evidence: evidence,
                            });
                        }
                    }
                }
            }
        }
        // ===== Information Disclosure (independente de payload/parâmetro) =====
        // Roda no corpo normal de cada endpoint.
        let normal_url_info = url.split('?').next().unwrap_or(url);
        let cached_info = {
            let cache = normal_cache.lock().unwrap();
            cache.get(normal_url_info).cloned()
        };

        let body = if let Some(b) = cached_info {
            b
        } else {
            client.bypass.wait().await;
            if let Ok(resp) = client.get(normal_url_info).await {
                let b = resp.text().await.unwrap_or_default();
                let mut cache = normal_cache.lock().unwrap();
                cache.insert(normal_url_info.to_string(), b.clone());
                b
            } else {
                String::new()
            }
        };

        if !body.is_empty() {
        let disclosure_indicators = vec![
                "senha_hash", "senha admin", "senha_admin",
                "password_hash", "secret_key", "api_secret",
                "usuarios", "db_password", "database_url", "private_key",
                "stack trace", "traceback", "at line",
                "debug", "debug mode", "debug=1",
                "internal error", "verbose", "dump",
            ];
            let score = Self::calculate_confidence(disclosure_indicators, &body);
            if score >= 2 {
                let vuln = Vulnerability {
                    id: "INFO-DISC-001".to_string(),
                    name: "Information Disclosure".to_string(),
                    severity: Severity::High,
                    description: "O endpoint expõe dados sensíveis (usuários, hashes de senha, dados internos de debug) sem autenticação.".to_string(),
                    remediation: "Remova endpoints de debug em produção, autentique as APIs que expõem dados sensíveis e nunca retorne hashes de senha ao cliente.".to_string(),
                    references: vec![
                        "https://owasp.org/Top10/A01_2021-Broken-Access-Control/".to_string(),
                        "https://cwe.mitre.org/data/definitions/200.html".to_string()
                    ],
                    cwe: Some("CWE-200".to_string()),
                };
                return Some(DetectedVuln {
                    vulnerability: vuln,
                    url: url.to_string(),
                    parameter: Some("response_body".to_string()),
                    evidence: format!("Sensitive data found in response body: {}", &body[..body.len().min(120)]),
                    sanitized_evidence: "Sensitive data found in response body".to_string(),
                });
            }
        }
        // ===== WAF =====
        if aggressive {
            let test_url = format!("{}?test={}", url, "' OR '1'='1");
            // Nota: WAF detection propositalmente NÃO usa cache pois queremos ver o bloqueio real
            if let Ok(resp) = client.get(&test_url).await {
                let body = resp.text().await.unwrap_or_default();
                
                let waf_indicators = vec![
                    "cloudflare",
                    "aws waf",
                    "modsecurity",
                    "akamai",
                    "imperva",
                    "request blocked",
                    "access denied",
                    "forbidden",
                ];
                
                let score = Self::calculate_confidence(waf_indicators, &body);
                
                // Exige pelo menos 2 indicadores fortes OU "request blocked"/"forbidden"
                // (adiciona o padrão "forbidden: padrão malicioso" típico de WAF customizado;
                // evita "access denied" genéricos de sites comuns)
                if score >= 2 || body.to_lowercase().contains("request blocked") || body.to_lowercase().contains("forbidden") {
                    let vuln = Vulnerability {
                        id: "WAF-001".to_string(),
                        name: "WAF Detectado".to_string(),
                        severity: Severity::Info,
                        description: "Um WAF foi detectado. Testes podem ser bloqueados.".to_string(),
                        remediation: "Use payloads encoded, case variation, ou comentários para bypass do WAF".to_string(),
                        references: vec![
                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                            "https://portswigger.net/web-security/error-handling".to_string()
                        ],
                        cwe: Some("CWE-200".to_string()),
                    };

                    return Some(DetectedVuln {
                        vulnerability: vuln,
                        url: url.to_string(),
                        parameter: Some("waf".to_string()),
                        evidence: "WAF detected".to_string(),
                        sanitized_evidence: "WAF detected".to_string(),
                    });
                }
            }
        }

        None
    }

    // Verifica se a resposta com o payload e DIFERENTE da resposta normal (sem payload)
    // Essencial para nao confundir "eco do payload" com vulnerabilidade real
    async fn response_differs_from_normal(
        client: &SecureHttpClient, 
        url: &str, 
        payload_body: &str,
        normal_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>
    ) -> bool {
        let normal_url = if let Some(base) = url.split('?').next() {
            base.to_string()
        } else {
            url.to_string()
        };

        let cached = {
            let cache = normal_cache.lock().unwrap();
            cache.get(&normal_url).cloned()
        };

        if let Some(cached_body) = cached {
            return cached_body != payload_body;
        }

        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            
            client.bypass.wait().await;
            if let Ok(resp) = client.get(&normal_url).await {
                if let Ok(normal) = resp.text().await {
                    {
                        let mut cache = normal_cache.lock().unwrap();
                        cache.insert(normal_url.clone(), normal.clone());
                    }
                    return normal != payload_body;
                }
            }
        }
        false
    }

    // Verifica se o marker de execucao (INJ_TEST_OUTPUT) aparece dentro de um bloco <pre>
    // junto com output EXTRA alem do payload espelhado (prova de execucao real concatenada).
    // Ex.: payload "echo INJ_TEST_OUTPUT && whoami" -> <pre>INJ_TEST_OUTPUT\njose</pre>
    // Funciona em Windows e Linux (independente de "desktop-" ou "\\" no whoami).
    fn pre_block_has_extra_output(body: &str, payload: &str, marker: &str) -> bool {
        let mut search_from = 0;
        while let Some(pre_start) = body[search_from..].find("<pre") {
            let start = search_from + pre_start;
            if let Some(pre_end) = body[start..].find("</pre") {
                let pre_content = &body[start..start + pre_end];
                // FIX v6: o alvo pode refletir o payload com entidades HTML (&amp; → &&),
                // então normaliza ambas as faces para não confundir espelho com execução.
                let after_marker = pre_content.split(marker).nth(1).unwrap_or("");
                let after_unescaped = after_marker.replace("&amp;", "&").replace("&#x27;", "'")
                    .replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">");
                // Remove o que é só o resto do comando espelhado (parte do payload)
                let mut extra = after_unescaped.to_string();
                extra = extra.replace(payload, "");
                extra = extra.replace("&&", "");
                extra = extra.replace("||", "");
                extra = extra.replace('&', "");
                extra = extra.replace('|', "");
                extra = extra.replace(';', "");
                // FIX v6: quando o alvo REFLETE o payload inteiro dentro do <pre>, o trecho
                // após o marker (ex.: " whoami") é apenas resíduo da reflexão — exigir que o
                // resíduo NÃO seja sufixo do payload limpo (prova de execução real, não espelho).
                // A comparação usa a versão decodificada de entidades HTML para não falsear
                // quando o alvo reflete "&amp;&amp;" no lugar de "&&".
                let mut payload_stripped = payload.to_string();
                payload_stripped = payload_stripped.replace("&&", "");
                payload_stripped = payload_stripped.replace("||", "");
                payload_stripped = payload_stripped.replace('&', "");
                payload_stripped = payload_stripped.replace('|', "");
                payload_stripped = payload_stripped.replace(';', "");
                let is_mirrored_reflection = extra.trim().len() <= payload_stripped.trim().len()
                    && payload_stripped.trim().contains(extra.trim());
                // FIX v6.1: se o alvo reflete o payload dentro de um texto maior (ex.: path de
                // erro '/dir/echo X && whoami'), o extra pode ser apenas o sufixo do payload
                // grudado em outros caracteres — dividir em tokens e exigir que algum token
                // seja UMA EVIDENCIA REAL (independente do payload, ex.: saida de whoami).
                let mirrored_by_tokens = if is_mirrored_reflection {
                    true
                } else {
                    let ps = payload_stripped.trim();
                    let candidate_tokens: Vec<&str> = extra.split_whitespace()
                        .filter(|t| !t.is_empty())
                        .collect();
                    // Cada token deve ser prefixo OU sufixo do payload limpo; se algum token
                    // nao for parte do payload, e evidencia real de execucao.
                    candidate_tokens.iter().all(|t| ps.starts_with(t.trim_matches('\''))
                        || ps.ends_with(t.trim_matches('\''))
                        || ps.contains(*t))
                };
                if extra.len() > 1 && !mirrored_by_tokens {
                    return true;
                }
                search_from = start + pre_end + 5;
            } else {
                break;
            }
        }
        false
    }

    /// Gera o relatório no caminho compartilhado (pasta `reports/`) com nome
    /// determinista. `suffix` diferencia sessões do painel web (id) do CLI.
    pub async fn generate_report_for(&self, results: Vec<DetectedVuln>, suffix: &str) -> Result<(), Box<dyn std::error::Error>> {
        let md_filename = report_path::report_path(&self.target, suffix);
        reporter::generate_markdown_report(&self.target, results, Some(&md_filename)).await?;

        if self.report_format == "pdf" || self.report_format == "both" {
            let pdf_filename = md_filename.replace(".md", ".pdf");
            let script = Path::new("tools/md_to_pdf.py");
            let status = std::process::Command::new("python3")
                .arg(script)
                .arg(&md_filename)
                .arg(&pdf_filename)
                .status();
            match status {
                Ok(s) if s.success() => println!("✅ Relatório PDF gerado: {}", pdf_filename),
                _ => println!("⚠️ PDF não gerado: weasyprint não disponível. Instale com `pip install weasyprint` (o relatório MD já está pronto)."),
            }
        }
        Ok(())
    }

    /// Gera o relatório no diretório atual (comportamento CLI clássico).
    pub async fn generate_report(&self, results: Vec<DetectedVuln>) -> Result<(), Box<dyn std::error::Error>> {
        // Guarda o caminho do relatório MD para conversão a PDF se solicitado
        let md_filename = {
            let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
            let clean = self.target
                .replace("https://", "").replace("http://", "")
                .replace("/", "_").replace(":", "_").replace(".", "_")
                .replace("?", "_").replace("&", "_").replace("=", "_")
                .replace("-", "_").replace(" ", "_");
            format!("report_{}_{}.md", clean, timestamp)
        };
        reporter::generate_markdown_report(&self.target, results, Some(&md_filename)).await?;

        if self.report_format == "pdf" || self.report_format == "both" {
            let pdf_filename = md_filename.replace(".md", ".pdf");
            let script = Path::new("tools/md_to_pdf.py");
            let status = std::process::Command::new("python3")
                .arg(script)
                .arg(&md_filename)
                .arg(&pdf_filename)
                .status();
            match status {
                Ok(s) if s.success() => println!("✅ Relatório PDF gerado: {}", pdf_filename),
                _ => println!("⚠️ PDF não gerado: weasyprint não disponível. Instale com `pip install weasyprint` (o relatório MD já está pronto)."),
            }
        }
        Ok(())
    }
}