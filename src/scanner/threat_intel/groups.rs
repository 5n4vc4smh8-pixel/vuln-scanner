/// Banco estático de grupos de ransomware emergentes (monitorados por Threat Intelligence).
///
/// Mantido manualmente com base em fontes públicas (Critical Intel, Cyble, Proven Data,
/// Ransom Database, Halcyon AI, PICUS Security). Atualizar conforme novas publicações.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareGroup {
    pub name: String,
    pub status: String,
    pub since: String,
    pub model: String,
    pub summary: String,
    pub victim_profile: String,
    pub initial_access: Vec<String>,
    /// Técnicas e vulnerabilidades exploradas (TTPs, CVEs, vetores técnicos).
    pub technical_indicators: Vec<String>,
    /// Tipos de vulnerabilidade que este grupo costuma explorar (nomes usados pelo scanner).
    pub exploited_vuln_types: Vec<String>,
    pub victims_published: u32,
    pub brazil_flagged: bool,
    pub source_urls: Vec<String>,
    /// Data em que a entrada foi verificada (AAAA-MM-DD).
    pub last_verified: String,
}

/// Base de conhecimento de grupos emergentes de ransomware.
pub fn emerging_groups() -> Vec<RansomwareGroup> {
    vec![
        RansomwareGroup {
            name: "DireWolf".to_string(),
            status: "Ativo — operação em aceleração".to_string(),
            since: "Maio/2025".to_string(),
            model: "Ransomware autônomo + dupla extorsão (criptografia + exfiltração + vazamento público)".to_string(),
            summary: "Saiu de ator secundário para uma das maiores operações de 2026, com 75+ organizações \
                publicadas em seu leak site (Proven Data). Utiliza negociador Tox e pressão pública agressiva \
                contra vítimas que não pagam. Foco global com forte presença em Manufacturing e Serviços Profissionais.".to_string(),
            victim_profile: "Manufacturing (21%), Serviços Profissionais (19%), Saúde (9%), 30+ países, incluindo Brasil".to_string(),
            initial_access: vec![
                "Credenciais comprometidas / phishing".to_string(),
                "Acesso inicial via VPN (Fortinet, Cisco) exposta".to_string(),
                "RDP exposto com credenciais fracas".to_string(),
            ],
            technical_indicators: vec![
                "Encryptor escrito em Go, empacotado com UPX".to_string(),
                "Extensão .direwolf nos arquivos criptografados".to_string(),
                "Nota de resgate: HowToRecoveryFiles.txt".to_string(),
                "Criptografia ChaCha20 + Curve25519 com criptografia parcial de arquivos grandes".to_string(),
                "Negociação exclusivamente via Tox".to_string(),
            ],
            exploited_vuln_types: vec![
                "SQL Injection".to_string(),
                "Command Injection".to_string(),
                "Authentication Bypass".to_string(),
                "Local File Inclusion (LFI)".to_string(),
            ],
            victims_published: 75,
            brazil_flagged: true,
            source_urls: vec![
                "https://www.provendata.com/blog/dire-wolf-ransomware".to_string(),
                "https://www.ransom-db.com/blog/direwolf-ransomware-group-analysis-2026".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "Devman".to_string(),
            status: "Ativo — alta cadência de vítimas".to_string(),
            since: "2026 (vinculado ao ecossistema DragonForce RaaS)".to_string(),
            model: "Operação fast-and-light vinculada a RaaS (DragonForce): acesso rápido, exfiltração e criptografia rápida".to_string(),
            summary: "Grupo de estilo 'minimal branding, maximum reuse' com 53 vítimas publicadas. Foco em \
                Ásia e África, com incursões pontuais na América Latina e Europa — inclusive organizações \
                brasileiras já publicadas em seu leak site. Reutiliza ferramentas e TTPs do ecossistema DragonForce.".to_string(),
            victim_profile: "Ásia e África predominantes; América Latina e Europa ocasionais; Brasil citado".to_string(),
            initial_access: vec![
                "Exploração de vulnerabilidades conhecidas sem patch".to_string(),
                "Credenciais vazadas de sistemas legados".to_string(),
            ],
            technical_indicators: vec![
                "Extensão .DEVMAN nos arquivos criptografados".to_string(),
                "Nota de resgate com identificador determinístico: e47qfsnz2trbkhnt.devman".to_string(),
                "Ciclo de ataque curto (acesso → exfiltração → criptografia em poucas horas)".to_string(),
            ],
            exploited_vuln_types: vec![
                "SQL Injection".to_string(),
                "Remote Code Execution".to_string(),
                "File Upload Vulnerabilities".to_string(),
                "Local File Inclusion (LFI)".to_string(),
            ],
            victims_published: 53,
            brazil_flagged: true,
            source_urls: vec![
                "https://www.provendata.com".to_string(),
                "https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "Vect".to_string(),
            status: "Ativo — recém-emergido (dez/2025)".to_string(),
            since: "Dez/2025 (recrutamento de afiliados); operações desde Jan/2026".to_string(),
            model: "Ransomware-as-a-Service (RaaS) com recrutamento ativo de afiliados".to_string(),
            summary: "RaaS emergente que anunciou afiliados em 31/dez/2025 e começou a operar em jan/2026. Sua \
                primeira vítima foi publicada no BRASIL (jan/2026). O grupo já foi flagrado comprando acesso a \
                redes via VPNs Fortinet comprometidas. Criptografia multi-plataforma incluindo VMware ESXi.".to_string(),
            victim_profile: "Brasil (1ª vítima publicada), África do Sul; alvos em crescimento".to_string(),
            initial_access: vec![
                "Acesso comprado via VPNs comprometidas (Fortinet)".to_string(),
                "Credenciais RDP vendidas em fóruns criminosos".to_string(),
            ],
            technical_indicators: vec![
                "Criptografia ChaCha20-Poly1305 com criptografia intermitente (skip)".to_string(),
                "Execução e evasão de EDR em modo de segurança (Safe Mode)".to_string(),
                "Infraestrutura de C2 e negociação via TOR".to_string(),
                "Encryptor multiplataforma: Windows, Linux e VMware ESXi".to_string(),
            ],
            exploited_vuln_types: vec![
                "Authentication Bypass".to_string(),
                "Remote Code Execution".to_string(),
                "Remote Access Exposure (RDP/VPN)".to_string(),
            ],
            victims_published: 5,
            brazil_flagged: true,
            source_urls: vec![
                "https://www.halcyon.ai/ransomware-alerts/emerging-ransomware-group-vect".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "Tengu".to_string(),
            status: "Ativo — RaaS emergente".to_string(),
            since: "2025/2026".to_string(),
            model: "RaaS com foco em exploração de fraquezas conhecidas e exfiltração via nuvem".to_string(),
            summary: "RaaS emergente que reutiliza ferramentas vivas-do-sistema (LOLBins) para evadir detecção e \
                exfiltra dados para serviços de nuvem antes de criptografar. Explora o padrão de 'fraquezas \
                familiares': vulnerabilidades públicas antigas em sistemas legados sem patch.".to_string(),
            victim_profile: "Organizações com sistemas legados e infraestrutura desatualizada".to_string(),
            initial_access: vec![
                "Exploração de CVEs públicos e antigos em sistemas legados".to_string(),
                "Credenciais fracas ou reutilizadas".to_string(),
            ],
            technical_indicators: vec![
                "Uso intensivo de LOLBins (binários legítimos do sistema) para evasão".to_string(),
                "Exfiltração via serviços de nuvem antes da criptografia".to_string(),
                "Dupla extorsão com publicação em leak site".to_string(),
            ],
            exploited_vuln_types: vec![
                "Remote Code Execution".to_string(),
                "SQL Injection".to_string(),
                "Local File Inclusion (LFI)".to_string(),
                "Outdated Software / Known CVEs".to_string(),
            ],
            victims_published: 10,
            brazil_flagged: false,
            source_urls: vec![
                "https://www.picussecurity.com/resource/blog/tengu-ransomware-attack-chain-from-initial-access-to-encryption".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "MintEye".to_string(),
            status: "Ativo — grupo emergente".to_string(),
            since: "2025/2026".to_string(),
            model: "Ransomware emergente (em reorganização de identidade)".to_string(),
            summary: "Grupo emergente citado por fontes de CTI brasileiras (Critical Intel). Ilustra o padrão de \
                rebranding rápido típico do ecossistema: operações que mudam de identidade para escapar de \
                reputação negativa e do monitoramento de ferramentas defensivas. Comportamento específico em \
                evolução — manter observação contínua.".to_string(),
            victim_profile: "Em evolução; grupos de rebranding tipicamente escolhem vítimas de baixo perfil de defesa".to_string(),
            initial_access: vec![
                "Credenciais comprometidas".to_string(),
                "Exploração de vulnerabilidades em softwares públicos".to_string(),
            ],
            technical_indicators: vec![
                "Identidade em rebranding — TTPs e infraestrutura em mutação".to_string(),
                "Padrão de mudança de nome para contornar detecções".to_string(),
            ],
            exploited_vuln_types: vec![
                "Remote Code Execution".to_string(),
                "SQL Injection".to_string(),
                "Authentication Bypass".to_string(),
            ],
            victims_published: 0,
            brazil_flagged: false,
            source_urls: vec![
                "https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "NightSpire".to_string(),
            status: "Ativo — grupo emergente".to_string(),
            since: "2025/2026".to_string(),
            model: "Ransomware emergente (em reorganização de identidade)".to_string(),
            summary: "Grupo emergente citado por fontes de CTI brasileiras (Critical Intel) como exemplo de \
                operador que muda de identidade rapidamente. Operações de rebranding costumam herdar \
                ferramentas, infraestrutura e listas de vítimas do grupo anterior, tornando o rastreamento \
                essencial para antecipar campanhas.".to_string(),
            victim_profile: "Em evolução; rebranding tipicamente precede nova campanha de extorsão".to_string(),
            initial_access: vec![
                "Credenciais comprometidas".to_string(),
                "Exploração de vulnerabilidades conhecidas".to_string(),
            ],
            technical_indicators: vec![
                "Identidade em rebranding — TTPs e infraestrutura em mutação".to_string(),
                "Possível herança de ferramentas do grupo predecessor".to_string(),
            ],
            exploited_vuln_types: vec![
                "Remote Code Execution".to_string(),
                "SQL Injection".to_string(),
                "Local File Inclusion (LFI)".to_string(),
            ],
            victims_published: 0,
            brazil_flagged: false,
            source_urls: vec![
                "https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "Kazu".to_string(),
            status: "Ativo — grupo emergente".to_string(),
            since: "2025/2026".to_string(),
            model: "Ransomware emergente".to_string(),
            summary: "Grupo emergente citado por fontes de CTI brasileiras (Critical Intel) entre os sete \
                operadores de crescimento rápido em 2026. Dados públicos detalhados ainda escassos; grupos \
                nessa fase exploram tipicamente vulnerabilidades públicas recentes em software empresarial \
                antes de amadurecer suas ferramentas próprias.".to_string(),
            victim_profile: "Em evolução; alvos típicos de grupos emergentes: servidores públicos de PME".to_string(),
            initial_access: vec![
                "Exploração de vulnerabilidades em aplicações web públicas".to_string(),
                "Credenciais comprometidas".to_string(),
            ],
            technical_indicators: vec![
                "Fase inicial de operação — TTPs em maturação".to_string(),
                "Uso de vulnerabilidades públicas recentes (CVEs com exploit)".to_string(),
            ],
            exploited_vuln_types: vec![
                "Remote Code Execution".to_string(),
                "SQL Injection".to_string(),
                "File Upload Vulnerabilities".to_string(),
            ],
            victims_published: 0,
            brazil_flagged: false,
            source_urls: vec![
                "https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
        RansomwareGroup {
            name: "Warlock".to_string(),
            status: "Ativo — vetor especializado (SharePoint)".to_string(),
            since: "2026".to_string(),
            model: "Exploração de vulnerabilidades de software empresarial (SharePoint on-prem) com deploy de web shells".to_string(),
            summary: "Ator que explora CVEs críticos do Microsoft SharePoint on-premises (CVE-2025-49704/49706, \
                CVE-2025-53770/53771) para implantar web shells (spinstall0.aspx e variantes). Serve de alerta \
                para organizações com software empresarial desatualizado: vulnerabilidades públicas são o \
                vetor inicial dominante de grupos emergentes em 2026.".to_string(),
            victim_profile: "Organizações com SharePoint on-premises sem patches recentes".to_string(),
            initial_access: vec![
                "CVE-2025-49704/49706 (RCE no SharePoint)".to_string(),
                "CVE-2025-53770/53771 (SQL injection no SharePoint)".to_string(),
            ],
            technical_indicators: vec![
                "Web shells spinstall0.aspx e variantes".to_string(),
                "Persistência via web shells após acesso inicial".to_string(),
                "Exploração de CVEs de software empresarial público".to_string(),
            ],
            exploited_vuln_types: vec![
                "Remote Code Execution".to_string(),
                "SQL Injection".to_string(),
            ],
            victims_published: 0,
            brazil_flagged: false,
            source_urls: vec![
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string(),
            ],
            last_verified: "2026-08-15".to_string(),
        },
    ]
}
