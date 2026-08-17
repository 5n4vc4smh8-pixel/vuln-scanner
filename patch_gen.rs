use crate::evidence::VulnerabilityEvidence;

pub fn generate_patch(evidence: &VulnerabilityEvidence) -> (String, String) {
    let param = evidence.parameter.as_deref().unwrap_or("input");
    
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => {
            let before = format!(
                "// Código vulnerável\nlet query = format!(\"SELECT * FROM users WHERE id = {}\", {});\n// Query executada diretamente",
                param, param
            );
            let after = format!(
                "// Código corrigido\nlet query = \"SELECT * FROM users WHERE id = ?\";\n// Usando prepared statement\nlet stmt = db.prepare(query)?;\nlet result = stmt.query(&[{}])?;",
                param
            );
            (before, after)
        }
        "XSS-001" => {
            let before = format!(
                "// Código vulnerável\ndocument.getElementById('output').innerHTML = '{}';",
                param
            );
            let after = format!(
                "// Código corrigido\nconst escapeHtml = (str) => str.replace(/[&<>\"']/g, (c) => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}}[c]));\ndocument.getElementById('output').textContent = escapeHtml({});",
                param
            );
            (before, after)
        }
        "LFI-001" => {
            let before = format!(
                "// Código vulnerável\n$file = $_GET['{}'];\ninclude('/var/www/' . $file);",
                param
            );
            let after = format!(
                "// Código corrigido\n$allowed_files = ['home.php', 'about.php', 'contact.php'];\n$file = $_GET['{}'];\nif (in_array($file, $allowed_files)) {{\n    include('/var/www/' . $file);\n}} else {{\n    die('Arquivo não permitido');\n}}",
                param
            );
            (before, after)
        }
        "CMD-001" => {
            let before = format!(
                "// Código vulnerável\nsystem(\"ping {}\");",
                param
            );
            let after = format!(
                "// Código corrigido\n$allowed_hosts = ['localhost', 'google.com'];\nif (in_array({}, $allowed_hosts)) {{\n    system(\"ping \" . escapeshellarg({}));\n}} else {{\n    die('Host não permitido');\n}}",
                param, param
            );
            (before, after)
        }
        "XXE-001" => {
            let before = r#"// Código vulnerável
$xml = file_get_contents('php://input');
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT);"#.to_string();
            let after = r#"// Código corrigido
$xml = file_get_contents('php://input');
$doc = new DOMDocument();
libxml_disable_entity_loader(true);
$doc->loadXML($xml);"#.to_string();
            (before, after)
        }
        "LDAP-001" => {
            let before = format!(
                "// Código vulnerável\n$filter = \"(uid={})\";\n$result = ldap_search($conn, $base_dn, $filter);",
                param
            );
            let after = format!(
                "// Código corrigido\n$filter = \"(uid={{}})\";\n$result = ldap_search($conn, $base_dn, ldap_escape({}, '', LDAP_ESCAPE_FILTER));",
                param
            );
            (before, after)
        }
        "HOST-001" => {
            let before = r#"// Código vulnerável
$host = $_SERVER['HTTP_HOST'];
$redirect_url = "http://" . $host . "/reset-password";"#.to_string();
            let after = r#"// Código corrigido
$allowed_hosts = ['example.com', 'www.example.com'];
$host = $_SERVER['HTTP_HOST'];
if (in_array($host, $allowed_hosts)) {
    $redirect_url = "http://" . $host . "/reset-password";
} else {
    die('Host não permitido');
}"#.to_string();
            (before, after)
        }
        "OPEN-001" => {
            let before = format!(
                "// Código vulnerável\nheader('Location: ' . $_GET['{}']);",
                param
            );
            let after = format!(
                "// Código corrigido\n$allowed_urls = ['/home', '/dashboard'];\n$url = $_GET['{}'];\nif (in_array($url, $allowed_urls)) {{\n    header('Location: ' . $url);\n}} else {{\n    header('Location: /home');\n}}",
                param
            );
            (before, after)
        }
        "CSRF-001" => {
            let before = r#"<!-- Código vulnerável -->
<form method="POST" action="/transfer">
    <input type="text" name="amount">
    <input type="submit" value="Transferir">
</form>"#.to_string();
            let after = r#"<!-- Código corrigido -->
<form method="POST" action="/transfer">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <input type="text" name="amount">
    <input type="submit" value="Transferir">
</form>"#.to_string();
            (before, after)
        }
        "PORT-001" => {
            let before = r#"// Configuração atual
firewall-cmd --list-ports
# 22/tcp 80/tcp 443/tcp 3306/tcp 8080/tcp"#.to_string();
            let after = r#"// Configuração recomendada
firewall-cmd --list-ports
# 22/tcp 80/tcp 443/tcp
# Removidas: 3306/tcp (MySQL externo), 8080/tcp (admin)"#.to_string();
            (before, after)
        }
        _ => {
            let before = format!("// Código vulnerável para: {}", evidence.vulnerability_name);
            let after = format!("// Código corrigido para: {}\n// Aplicar validação de input e boas práticas de segurança", evidence.vulnerability_name);
            (before, after)
        }
    }
}

pub fn generate_diff(before: &str, after: &str) -> String {
    let mut diff = String::new();
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();

    let max_lines = before_lines.len().max(after_lines.len());
    
    for i in 0..max_lines {
        let before_line = before_lines.get(i).unwrap_or(&"");
        let after_line = after_lines.get(i).unwrap_or(&"");
        
        if before_line != after_line {
            if !before_line.is_empty() {
                diff.push_str(&format!("- {}\n", before_line));
            }
            if !after_line.is_empty() {
                diff.push_str(&format!("+ {}\n", after_line));
            }
        }
    }

    if diff.is_empty() {
        diff.push_str("(Sem diferenças significativas)");
    }

    diff
}

pub fn detect_language(evidence: &VulnerabilityEvidence) -> String {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => "Rust/Java/PHP/Python (depende do backend)".to_string(),
        "XSS-001" => "JavaScript".to_string(),
        "LFI-001" => "PHP".to_string(),
        "CMD-001" => "PHP/Python".to_string(),
        "XXE-001" => "PHP/Java".to_string(),
        "LDAP-001" => "PHP".to_string(),
        "HOST-001" => "PHP/Node.js".to_string(),
        "OPEN-001" => "PHP/JavaScript".to_string(),
        "CSRF-001" => "HTML/PHP".to_string(),
        "PORT-001" => "Shell/Firewall".to_string(),
        _ => "Multi-linguagem".to_string(),
    }
}

pub fn detect_framework(evidence: &VulnerabilityEvidence) -> String {
    // Tenta detectar framework das evidências
    if let Some(stack) = &evidence.stack_technology {
        return stack.clone();
    }
    
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" => "Framework web genérico".to_string(),
        "XSS-001" => "Frontend (React/Angular/Vue)".to_string(),
        "LFI-001" => "PHP puro".to_string(),
        "CMD-001" => "Backend genérico".to_string(),
        "XXE-001" => "Parser XML".to_string(),
        _ => "Não identificado".to_string(),
    }
}

pub fn estimate_time(complexity: &str) -> String {
    match complexity {
        "low" => "15-30 minutos".to_string(),
        "medium" => "1-2 horas".to_string(),
        "high" => "2-4 horas".to_string(),
        "informational" => "N/A".to_string(),
        _ => "1 hora".to_string(),
    }
}

pub fn can_auto_fix(evidence: &VulnerabilityEvidence) -> bool {
    match evidence.vulnerability_id.as_str() {
        "SQLI-001" | "XSS-001" | "LFI-001" | "CMD-001" | 
        "XXE-001" | "LDAP-001" | "OPEN-001" | "CSRF-001" => true,
        _ => false,
    }
}