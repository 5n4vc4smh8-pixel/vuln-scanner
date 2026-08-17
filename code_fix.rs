use crate::evidence::VulnerabilityEvidence;
use super::RemediationStep;

pub fn generate_steps(evidence: &VulnerabilityEvidence) -> Vec<RemediationStep> {
    let mut steps = Vec::new();
    let param = evidence.parameter.as_deref().unwrap_or("input");

    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Identificar todas as queries SQL que usam input do usuário".to_string(),
                code_snippet: Some(format!("// Buscar por:\n// format!(\"...{}...\", ...)\n// \"...\" + {} + \"...\"", param, param)),
                description: "Localizar pontos de concatenação de strings em queries SQL".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 2,
                action: "Substituir por prepared statements".to_string(),
                code_snippet: Some("let stmt = db.prepare(\"SELECT * FROM users WHERE id = ?\")?;\nlet result = stmt.query(&[user_id])?;".to_string()),
                description: "Usar prepared statements em todas as queries".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 3,
                action: "Adicionar input validation".to_string(),
                code_snippet: Some("if !user_id.chars().all(|c| c.is_digit(10)) {\n    return Err(\"Invalid input\");\n}".to_string()),
                description: "Validar tipo e formato do input".to_string(),
            });
        }
        "XSS-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Identificar pontos de output não sanitizado".to_string(),
                code_snippet: Some("// Buscar por:\n// innerHTML = ...\n// document.write(...)".to_string()),
                description: "Localizar onde o input do usuário é renderizado".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 2,
                action: "Implementar output encoding".to_string(),
                code_snippet: Some("const escapeHtml = (str) => str.replace(/[&<>\"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));".to_string()),
                description: "Escapar caracteres especiais no output".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 3,
                action: "Usar textContent em vez de innerHTML".to_string(),
                code_snippet: Some("element.textContent = userInput;".to_string()),
                description: "textContent não interpreta HTML".to_string(),
            });
        }
        "LFI-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Criar whitelist de arquivos permitidos".to_string(),
                code_snippet: Some("$allowed = ['home.php', 'about.php', 'contact.php'];".to_string()),
                description: "Definir lista de arquivos que podem ser incluídos".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 2,
                action: "Validar input contra whitelist".to_string(),
                code_snippet: Some("if (in_array($file, $allowed)) { include($file); }".to_string()),
                description: "Só incluir arquivos que estão na whitelist".to_string(),
            });
        }
        "CMD-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Eliminar funções de execução de comandos".to_string(),
                code_snippet: Some("// NUNCA usar:\n// system(), exec(), shell_exec()\n// com input do usuário".to_string()),
                description: "Remover funções perigosas".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 2,
                action: "Usar APIs seguras".to_string(),
                code_snippet: Some("// Usar bibliotecas específicas\n// Ex: para ping, usar API de rede".to_string()),
                description: "Substituir por APIs que não executam shell".to_string(),
            });
        }
        "XXE-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Desabilitar entities externas".to_string(),
                code_snippet: Some("libxml_disable_entity_loader(true);".to_string()),
                description: "Configurar parser XML para não processar entities externas".to_string(),
            });
        }
        "LDAP-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Escapar caracteres especiais LDAP".to_string(),
                code_snippet: Some("ldap_escape($input, '', LDAP_ESCAPE_FILTER)".to_string()),
                description: "Usar função de escape do LDAP".to_string(),
            });
        }
        "OPEN-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Validar URL de redirecionamento".to_string(),
                code_snippet: Some("$allowed = ['/home', '/dashboard'];\nif (in_array($url, $allowed)) { redirect($url); }".to_string()),
                description: "Só redirecionar para URLs permitidas".to_string(),
            });
        }
        "CSRF-001" => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Adicionar token CSRF em todos os formulários".to_string(),
                code_snippet: Some("<input type=\"hidden\" name=\"csrf_token\" value=\"...\">".to_string()),
                description: "Incluir token único em cada formulário".to_string(),
            });
            steps.push(RemediationStep {
                step_number: 2,
                action: "Validar token no servidor".to_string(),
                code_snippet: Some("if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) { die('CSRF detected'); }".to_string()),
                description: "Verificar token antes de processar".to_string(),
            });
        }
        _ => {
            steps.push(RemediationStep {
                step_number: 1,
                action: "Análise manual necessária".to_string(),
                code_snippet: None,
                description: format!("Vulnerabilidade: {}", evidence.vulnerability_name),
            });
        }
    }

    steps
}