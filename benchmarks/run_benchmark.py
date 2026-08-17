#!/usr/bin/env python3
"""Suíte de benchmark do vuln-scanner.

Executa cada alvo vulnerável em subprocess, roda o scanner contra ele,
coleta os achados do relatório Markdown e calcula a matriz de precisão,
recall e taxa de falsos positivos.

Requisito: o binário `vuln-scanner` (cargo build --release) no PATH ou
no diretório target/release/.

Saída: benchmark_report.md (matriz oficial)
"""
import subprocess
import time
import re
import os
import signal
import sys
import glob
import socket

BIN = os.environ.get("SCANNER_BIN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "vuln-scanner"))

ALVOS = {
    "alvo_real (Loja Tech — falhas reais)": {
        "script": "target_real/alvo_real.py",
        "port": 8701,
        "esperadas": ["SQL Injection", "SQL Injection", "Cross-Site Scripting",
                      "Command Injection", "Local File Inclusion", "Open Redirect"],
        "esperadas_count": 6,
    },
    "alvo_xss (reflexão + IDOR)": {
        "script": "benchmarks/alvo_xss.py",
        "port": 8702,
        "esperadas": ["Cross-Site Scripting", "IDOR"],
        "esperadas_count": 2,
    },
    "alvo_limpo (zero falsos positivos)": {
        "script": "benchmarks/alvo_limpo.py",
        "port": 8703,
        "esperadas": [],
        "esperadas_count": 0,
    },
}


def start_target(script, port):
    # Paths dos alvos são relativos à RAIZ do projeto (um nível acima de benchmarks/)
    abs_script = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), os.pardir, script))
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            f".target_{port}.log")
    # Garante porta livre (alvo travado de runs anteriores) e DB limpo
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            try:
                subprocess.run(
                    ["fuser", "-k", f"{port}/tcp"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except OSError:
                pass
            time.sleep(1.0)
    except OSError:
        pass
    log_fp = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, abs_script, str(port)],
        stdout=log_fp, stderr=log_fp, start_new_session=True,
    )
    # aguarda o alvo levantar
    for _ in range(20):
        time.sleep(0.5)
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://localhost:{port}/", timeout=2) as r:
                if r.status == 200:
                    return proc
        except Exception as exc:
            if _ == 10:
                print("health err:", type(exc).__name__, exc)
            pass
    raise RuntimeError(f"Alvo {script} não subiu na porta {port}")


def scan_target(port):
    report = None
    before = set(glob.glob("report_*.md"))
    subprocess.run([BIN, "--target", f"http://127.0.0.1:{port}", "--aggressive"],
                   capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
    time.sleep(1)
    after = set(glob.glob("report_*.md"))
    new = sorted(after - before)
    if new:
        report = new[-1]
    return report


def parse_vuln_names(report_path):
    names = []
    with open(report_path, encoding="utf-8") as f:
        content = f.read()
    for m in re.finditer(r"### \d+\. (.+?) \(Severidade:", content):
        names.append(m.group(1).strip())
    return names


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isfile(BIN):
        print(f"Binário não encontrado: {BIN}. Execute `cargo build --release` na raiz.")
        sys.exit(1)

    total_tp, total_fp, total_fn = 0, 0, 0
    rows = []
    for nome, cfg in ALVOS.items():
        target = f"http://127.0.0.1:{cfg['port']}"
        proc = start_target(cfg["script"], cfg["port"])
        try:
            report = scan_target(cfg["port"])
            if not report:
                rows.append((nome, "ERRO", "-", "-", "-", "-"))
                continue
            achados = parse_vuln_names(report)
            esperadas = dict.fromkeys(cfg["esperadas"], 0)
            for e in cfg["esperadas"]:
                if any(e.lower() in a.lower() for a in achados):
                    esperadas[e] += 1
            tp = sum(min(v, esperadas[e]) for e, v in esperadas.items())
            fn = sum(1 for e, v in esperadas.items() if v == 0)
            fp = len(achados) - sum(esperadas.values())
            total_tp += tp
            total_fp += fp
            total_fn += fn
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            rows.append((nome, "OK", f"{tp}/{cfg['esperadas_count']}",
                         f"{prec:.0%}", f"{rec:.0%}", f"{fp} FP"))
            print(f"[{nome}] achados={len(achados)} tp={tp} fn={fn} fp={fp}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            time.sleep(0.5)

    total_vulns = total_tp + total_fn
    prec_geral = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    rec_geral = total_tp / total_vulns if total_vulns else 0.0

    lines = ["# Benchmark Oficial — vuln-scanner v8.0", "",
             "Matriz de precisão e recall executada automaticamente contra alvos com falhas reais.",
             "",
             "| Alvo | Status | Detectadas | Precisão | Recall | Falsos Positivos |",
             "|------|--------|------------|----------|--------|------------------|"]
    for r in rows:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} |")
    lines += ["",
              f"**Geral:** precisão **{prec_geral:.0%}** | recall **{rec_geral:.0%}** | "
              f"falsos positivos totais: **{total_fp}**", "",
              "Metodologia: cada alvo é um app Python real com banco SQLite e falhas autênticas "
              "(não simuladas). O scanner é executado com `--aggressive` apontando apenas para a raiz "
              "do alvo; o discovery/crawler deve encontrar os endpoints sozinho. "
              "Um alvo sem nenhuma vulnerabilidade valida a taxa de falsos positivos.", ""]
    out = "BENCHMARK.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nBenchmark concluído → {out}")
    print(f"Geral: precisão {prec_geral:.0%} | recall {rec_geral:.0%} | FP {total_fp}")


if __name__ == "__main__":
    main()
