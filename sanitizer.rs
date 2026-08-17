#![allow(dead_code)]
/// Sanitiza conteúdo para prevenir XSS em relatórios
pub struct Sanitizer;

impl Sanitizer {
    /// Escapa caracteres HTML especiais
    pub fn html_escape(input: &str) -> String {
        let mut escaped = String::with_capacity(input.len() * 2);
        
        for c in input.chars() {
            match c {
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '&' => escaped.push_str("&amp;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#x27;"),
                '/' => escaped.push_str("&#x2F;"),
                _ => escaped.push(c),
            }
        }
        
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape() {
        let malicious = "<script>alert('XSS')</script>";
        let safe = Sanitizer::html_escape(malicious);
        assert!(!safe.contains("<script>"));
        assert!(safe.contains("&lt;script&gt;"));
    }
}