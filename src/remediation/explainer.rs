use crate::evidence::VulnerabilityEvidence;

pub fn explain_vulnerability(evidence: &VulnerabilityEvidence) -> String {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => {
            format!(
                "A aplicação concatena diretamente o input do usuário (parâmetro '{}') em uma query SQL sem parametrização. Isso permite que um atacante injete comandos SQL maliciosos para acessar, modificar ou deletar dados do banco.",
                evidence.parameter.as_deref().unwrap_or("desconhecido")
            )
        }
        "XSS-001" => {
            format!(
                "A aplicação reflete o input do usuário (parâmetro '{}') no HTML sem sanitização. Isso permite que um atacante injete scripts maliciosos que serão executados no navegador de outros usuários.",
                evidence.parameter.as_deref().unwrap_or("desconhecido")
            )
        }
        "LFI-001" => {
            format!(
                "A aplicação usa o input do usuário (parâmetro '{}') para incluir arquivos locais sem validação adequada. Isso permite que um atacante leia arquivos sensíveis do servidor.",
                evidence.parameter.as_deref().unwrap_or("desconhecido")
            )
        }
        "CMD-001" => {
            format!(
                "A aplicação executa comandos do sistema usando input do usuário (parâmetro '{}') sem sanitização. Isso permite que um atacante execute comandos arbitrários no servidor.",
                evidence.parameter.as_deref().unwrap_or("desconhecido")
            )
        }
        "XXE-001" => {
            "A aplicação processa XML com entities externas habilitadas. Isso permite que um atacante leia arquivos internos, faça SSRF, ou cause DoS.".to_string()
        }
        "LDAP-001" => {
            format!(
                "A aplicação insere input do usuário (parâmetro '{}') em queries LDAP sem escape adequado. Isso permite bypass de autenticação e acesso não autorizado.",
                evidence.parameter.as_deref().unwrap_or("desconhecido")
            )
        }
        "HOST-001" => {
            "A aplicação confia no header Host sem validação. Isso permite ataques de cache poisoning, password reset poisoning e redirecionamentos maliciosos.".to_string()
        }
        "OPEN-001" => {
            format!(
                "A aplicação redireciona o usuário baseado no parâmetro '{}' sem validar o destino. Isso permite phishing e redirecionamento para sites maliciosos.",
                evidence.parameter.as_deref().unwrap_or("desconhecido")
            )
        }
        "CSRF-001" => {
            "A aplicação não implementa tokens CSRF em formulários que alteram estado. Isso permite que um atacante force usuários autenticados a executar ações não intencionais.".to_string()
        }
        "PORT-001" => {
            "O servidor possui portas desnecessárias abertas, aumentando a superfície de ataque.".to_string()
        }
        _ => {
            format!(
                "Vulnerabilidade de segurança detectada: {}. Recomenda-se análise detalhada e correção imediata.",
                evidence.vulnerability_name
            )
        }
    }
}

pub fn identify_root_cause(evidence: &VulnerabilityEvidence) -> String {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => "Falta de prepared statements e input validation".to_string(),
        "XSS-001" => "Falta de output encoding e Content Security Policy".to_string(),
        "LFI-001" => "Falta de whitelist de arquivos permitidos".to_string(),
        "CMD-001" => "Uso de funções perigosas como system(), exec(), eval()".to_string(),
        "XXE-001" => "Parser XML com entities externas habilitadas".to_string(),
        "LDAP-001" => "Falta de escape de caracteres especiais em queries LDAP".to_string(),
        "HOST-001" => "Confiança implícita no header Host".to_string(),
        "OPEN-001" => "Falta de validação de URLs de redirecionamento".to_string(),
        "CSRF-001" => "Ausência de tokens anti-CSRF".to_string(),
        "PORT-001" => "Firewall mal configurado".to_string(),
        _ => "Falta de validação de input".to_string(),
    }
}