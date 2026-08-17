/// Helpers compartilhados para o caminho dos relatórios.
///
/// O painel web e o modo CLI precisam concordar EXATAMENTE no local onde o
/// relatório Markdown é gravado e lido. Para eliminar qualquer divergência
/// (timestamp diferente, diretório de trabalho diferente, sanitização
/// diferente), o nome do arquivo é DETERMINISTA:
///
///     reports/report_<alvo_sanitizado>_<id_da_sessão ou "cli">.md
///
/// A pasta `reports/` é criada automaticamente no diretório do projeto.
use std::path::PathBuf;

/// Direção comum onde os relatórios ficam.
pub fn reports_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("reports")
}

/// Nome de arquivo determinista a partir do alvo. O `suffix` diferencia
/// sessões do painel web (id) ou do CLI ("cli" + timestamp).
pub fn report_filename(target: &str, suffix: &str) -> String {
    let safe = target
        .replace("https://", "")
        .replace("http://", "")
        .replace('/', "_")
        .replace(':', "_")
        .replace('.', "_")
        .replace('?', "_")
        .replace('&', "_")
        .replace('=', "_")
        .replace('-', "_")
        .replace(' ', "_");
    format!("report_{}_{}.md", safe, suffix)
}

/// Caminho completo do relatório.
pub fn report_path(target: &str, suffix: &str) -> String {
    let dir = reports_dir();
    std::fs::create_dir_all(&dir).ok();
    dir.join(report_filename(target, suffix)).display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizacao_consistente() {
        let a = report_filename("http://127.0.0.1:9999", "cli");
        let b = report_filename("http://127.0.0.1:9999", "cli");
        assert_eq!(a, b);
        assert_eq!(a, "report_127_0_0_1_9999_cli.md");
    }

    #[test]
    fn https_e_http_sao_iguais() {
        let a = report_filename("https://exemplo.com/alvo", "1");
        let b = report_filename("http://exemplo.com/alvo", "1");
        assert_eq!(a, b);
    }
}
