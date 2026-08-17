use super::DetectedVuln;
use chrono::Local;
use std::fs::File;
use std::io::Write;

pub async fn generate_markdown_report(target: &str, results: Vec<DetectedVuln>, force_filename: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    // Limpa o nome do alvo para ser usado como nome de arquivo
let clean_target = target
    .replace("https://", "")
    .replace("http://", "")
    .replace("/", "_")
    .replace(":", "_")
    .replace(".", "_")
    .replace("?", "_")
    .replace("&", "_")
    .replace("=", "_")
    .replace("-", "_")
    .replace(" ", "_");

let filename = force_filename
    .map(|f| f.to_string())
    .unwrap_or_else(|| format!("report_{}_{}.md", clean_target, timestamp));
    
    let mut file = File::create(&filename)?;
    
    // Cabeçalho
    writeln!(file, "# Relatório de Vulnerabilidades\n")?;
    writeln!(file, "**Alvo:** {}", target)?;
    writeln!(file, "**Data:** {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "**Total de Vulnerabilidades:** {}\n", results.len())?;
    
    // ===== Inteligência de Ameaças (Threat Intelligence) =====
    let ti_result = super::threat_intel::correlation::CorrelationResult::correlate(&results).await;
    let ti_section = super::threat_intel::report_section::generate_threat_intel_section(&ti_result);
    writeln!(file, "{}", ti_section)?;

    // Sumário
    if !results.is_empty() {
        writeln!(file, "## Sumário Executivo\n")?;
        writeln!(file, "| Severidade | Quantidade |")?;
        writeln!(file, "|------------|------------|")?;
        
        let critical = results.iter().filter(|r| r.vulnerability.severity == super::Severity::Critical).count();
        let high = results.iter().filter(|r| r.vulnerability.severity == super::Severity::High).count();
        let medium = results.iter().filter(|r| r.vulnerability.severity == super::Severity::Medium).count();
        let low = results.iter().filter(|r| r.vulnerability.severity == super::Severity::Low).count();
        
        writeln!(file, "| **Crítica** | {} |", critical)?;
        writeln!(file, "| **Alta** | {} |", high)?;
        writeln!(file, "| **Média** | {} |", medium)?;
        writeln!(file, "| **Baixa** | {} |", low)?;
        writeln!(file, "| **Info** | {} |", results.len() - critical - high - medium - low)?;
    }
    
    // Detalhamento
    writeln!(file, "\n## Detalhamento das Vulnerabilidades\n")?;
    
    for (i, vuln) in results.iter().enumerate() {
        writeln!(file, "### {}. {} (Severidade: {:?})\n", i+1, vuln.vulnerability.name, vuln.vulnerability.severity)?;
        writeln!(file, "**ID:** {}", vuln.vulnerability.id)?;
        writeln!(file, "**CWE:** {}", vuln.vulnerability.cwe.clone().unwrap_or_else(|| "N/A".to_string()))?;
        writeln!(file, "**URL:** {}", vuln.url)?;
        if let Some(param) = &vuln.parameter {
            writeln!(file, "**Parâmetro:** {}", param)?;
        }
        writeln!(file, "**Descrição:** {}", vuln.vulnerability.description)?;
        writeln!(file, "**Remediação:** {}", vuln.vulnerability.remediation)?;
        writeln!(file, "**Evidência:** `{}`", vuln.sanitized_evidence)?;
        writeln!(file, "**Referências:**")?;
        for ref_link in &vuln.vulnerability.references {
            writeln!(file, "  - {}", ref_link)?;
        }
        writeln!(file, "---\n")?;
    }
    
    println!("✅ Relatório gerado: {}", filename);
    Ok(())
}