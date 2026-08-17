#![allow(dead_code)]
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::Semaphore;
use log::{info, debug};

// Portas comuns para scan
pub const COMMON_PORTS: [(u16, &str); 20] = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (111, "RPC"),
    (135, "MS RPC"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1723, "PPTP"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
];

// Portas para scan agressivo (CORRIGIDO: 13 elementos)
pub const AGGRESSIVE_PORTS: [(u16, &str); 13] = [
    (27017, "MongoDB"),
    (5984, "CouchDB"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (9000, "MinIO"),
    (9092, "Kafka"),
    (15672, "RabbitMQ"),
    (5000, "HTTP-Alt"),
    (8000, "HTTP-Alt"),
    (8008, "HTTP-Alt"),
    (9042, "Cassandra"),
];

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub service: String,
    pub open: bool,
    pub latency_ms: u64,
}

pub async fn scan_port(host: &str, port: u16) -> Option<PortScanResult> {
    let addr = format!("{}:{}", host, port);
    
    // Verifica se o endereço é válido
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            let timeout = Duration::from_secs(2);
            
            debug!("Escaneando {}:{}...", host, port);
            
            let start = std::time::Instant::now();
            let result = tokio::task::spawn_blocking(move || {
                TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
            }).await;
            
            let latency = start.elapsed().as_millis() as u64;
            
            if let Ok(true) = result {
                info!("✅ Porta {} aberta", port);
                return Some(PortScanResult {
                    port,
                    service: get_service_name(port),
                    open: true,
                    latency_ms: latency,
                });
            }
        }
    }
    None
}

pub fn get_service_name(port: u16) -> String {
    let all_ports = COMMON_PORTS.iter().chain(AGGRESSIVE_PORTS.iter());
    for (p, name) in all_ports {
        if *p == port {
            return name.to_string();
        }
    }
    format!("Porta {} desconhecida", port)
}

pub async fn scan_common_ports(host: &str) -> Vec<PortScanResult> {
    // Remove protocolo e barras do host
    let clean_host = host
        .replace("http://", "")
        .replace("https://", "")
        .split('/')
        .next()
        .unwrap_or(host)
        .split(':')
        .next()
        .unwrap_or(host)
        .to_string();
    
    info!("🔍 Iniciando scan de portas em {}", clean_host);
    
    let mut results = Vec::new();
    let semaphore = Arc::new(Semaphore::new(10));
    let mut tasks = Vec::new();
    
    let host_owned = clean_host.clone();
    let all_ports = COMMON_PORTS.iter().chain(AGGRESSIVE_PORTS.iter());
    let ports: Vec<(u16, &str)> = all_ports.map(|(p, n)| (*p, *n)).collect();
    
    for (port, _) in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let host_clone = host_owned.clone();
        
        tasks.push(tokio::spawn(async move {
            let result = scan_port(&host_clone, port).await;
            drop(permit);
            result
        }));
    }
    
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            results.push(result);
        }
    }
    
    results.sort_by_key(|r| r.port);
    info!("✅ Scan de portas concluído: {} portas abertas", results.len());
    results
}