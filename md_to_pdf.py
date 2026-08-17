#!/usr/bin/env python3
"""Converte relatórios Markdown do vuln-scanner em PDF corporativo.

Uso:
    python3 tools/md_to_pdf.py relatorio.md [saida.pdf]

Requisito: weasyprint (pip install weasyprint)
"""
import sys
import re
from pathlib import Path

try:
    from weasyprint import HTML
except ImportError:
    print("Erro: weasyprint não instalado. Execute: pip install weasyprint")
    sys.exit(1)


def md_to_html(md_text: str) -> str:
    """Conversor Markdown→HTML mínimo focado no formato do relatório."""
    lines = md_text.split("\n")
    html = ["<html><head><meta charset='utf-8'>",
            "<style>",
            "body { font-family: 'Helvetica', 'Arial', sans-serif; color: #1a1a2e; margin: 40px; }",
            "h1 { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 8px; }",
            "h2 { color: #2c3e50; margin-top: 28px; }",
            "h3 { color: #c0392b; }",
            "table { border-collapse: collapse; width: 100%; margin: 12px 0; }",
            "th, td { border: 1px solid #bdc3c7; padding: 7px 10px; text-align: left; }",
            "th { background: #2c3e50; color: white; }",
            "tr:nth-child(even) { background: #f2f3f4; }",
            "code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }",
            "hr { border: 0; border-top: 1px solid #ddd; margin: 18px 0; }",
            "ul { line-height: 1.6; }",
            "</style></head><body>"]

    in_table = False
    for raw in lines:
        line = raw.rstrip()

        # tabela
        if line.startswith("|") and "|" in line[1:]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(re.fullmatch(r"-{3,}", c) for c in cells):
                continue
            if not in_table:
                html.append("<table>")
                in_table = True
            tag = "th" if html[-1].endswith("<table>") or all(
                re.fullmatch(r"-{3,}", c) for c in cells) else "td"
            html.append("<tr>" + "".join(
                f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        elif in_table:
            html.append("</table>")
            in_table = False

        if line.startswith("# "):
            html.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            html.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("### "):
            html.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line == "---":
            html.append("<hr>")
        elif line.startswith("- "):
            html.append(f"<ul><li>{_inline(line[2:])}</li></ul>")
        elif line.strip():
            html.append(f"<p>{_inline(line)}</p>")
        else:
            html.append("")

    if in_table:
        html.append("</table>")
    html.append("</body></html>")
    return "\n".join(html)


def _inline(text: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".pdf")
    html = md_to_html(src.read_text(encoding="utf-8"))
    HTML(string=html).write_pdf(str(dst))
    print(f"PDF gerado: {dst}")


if __name__ == "__main__":
    main()
