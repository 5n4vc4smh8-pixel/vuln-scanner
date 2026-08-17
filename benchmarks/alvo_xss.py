#!/usr/bin/env python3
"""Alvo para benchmark de XSS / reflection / IDOR básico.

App real com formulários vulneráveis autênticos (XSS refletido, XSS armazenado,
IDOR em download de arquivo) — SQLite real.

Falhas reais esperadas: XSS (High), IDOR (Medium)
Sem SQLi, sem CMDi, sem LFI — para medir especificidade do motor.

Uso: python3 alvo_xss.py [porta]   (padrão 8899)
"""
import sqlite3
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import html

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
DB = "app_xss.db"
UP_DIR = "uploads_xss"


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS comentarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        autor TEXT NOT NULL, texto TEXT NOT NULL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS documentos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        arquivo TEXT NOT NULL, titulo TEXT NOT NULL)""")
    conn.commit()
    conn.close()
    os.makedirs(UP_DIR, exist_ok=True)
    with open(os.path.join(UP_DIR, "aviso.txt"), "w") as f:
        f.write("Documento público de aviso.\n")
    with open(os.path.join(UP_DIR, "relatorio_interno.txt"), "w") as f:
        f.write("RELATÓRIO INTERNO — CONFIDENCIAL\nOrçamento Q4: R$ 1.200.000,00.\n")
    conn = sqlite3.connect(DB)
    conn.executemany("INSERT INTO documentos (arquivo, titulo) VALUES (?, ?)", [
        ("aviso.txt", "Aviso Geral"),
        ("relatorio_interno.txt", "Relatório Interno"),
    ])
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    CSRF_TOKEN = "token_simulado"

    def send_page(self, title, html_body):
        content = (f"<!DOCTYPE html><html lang='pt-BR'><head><meta charset='utf-8'>"
                   f"<title>{title}</title></head><body>"
                   f"<nav><a href='/'>Início</a> <a href='/comentarios'>Comentários</a> <a href='/docs'>Documentos</a></nav>"
                   f"<h1>{title}</h1>{html_body}</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        def get_param(name, default=None):
            values = params.get(name, [])
            return values[0] if values else default

        if parsed.path in ("/", "/index"):
            nome = get_param("nome")
            if nome:
                # VULNERÁVEL: XSS refletido autêntico
                self.send_page("Boas-vindas", f"<p>Olá, {nome}!</p>")
            else:
                self.send_page("Início", "<form action='/' method='get'><input name='nome' placeholder='Seu nome'><button>Entrar</button></form>")

        elif parsed.path == "/comentarios":
            conn = sqlite3.connect(DB)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT autor, texto FROM comentarios ORDER BY id DESC").fetchall()
            conn.close()
            rows_html = "".join(
                f"<div><b>{c['autor']}</b>: {c['texto']}</div><hr>"
                for c in rows
            )
            self.send_page("Comentários", f"{rows_html}"
                           "<form action='/comentarios' method='post'>"
                           f"<input type='hidden' name='csrf_token' value='{self.CSRF_TOKEN}'>"
                           "<input name='autor' placeholder='Autor'><input name='texto' placeholder='Comentário'>"
                           "<button>Enviar</button></form>")

        elif parsed.path == "/docs":
            # VULNERÁVEL: IDOR — download por ID numérico sem autorização,
            # qualquer ID acessa qualquer documento
            doc_id = get_param("id")
            if doc_id is None:
                conn = sqlite3.connect(DB)
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT id, titulo FROM documentos").fetchall()
                conn.close()
                links = "".join(
                    f"<li><a href='/docs?id={d['id']}'>{html.escape(str(d['titulo']))}</a></li>" for d in rows
                )
                self.send_page("Documentos", f"<ul>{links}</ul>")
                return
            try:
                doc_id = int(doc_id)
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            # Comportamento de app com IDOR: mesmo IDs inexistentes retornam
            # 200 (vazios), enquanto IDs válidos retornam 200 com o conteudo.
            conn = sqlite3.connect(DB)
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT arquivo FROM documentos WHERE id = ?", (doc_id,)).fetchone()
            conn.close()
            if row:
                path = os.path.join(UP_DIR, row["arquivo"])
                if os.path.exists(path):
                    self.send_response(200)
                    self.end_headers()
                    with open(path, "rb") as f:
                        self.wfile.write(f.read())
                    return
            self.send_response(200)
            self.end_headers()
            # IDOR: app retorna 200 vazio para IDs inexistentes (não nega acesso)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        params = parse_qs(body)

        def get_param(name, default=None):
            values = params.get(name, [])
            return values[0] if values else default

        if parsed.path == "/comentarios":
            autor = get_param("autor", "Anônimo")
            texto = get_param("texto", "")
            if texto:
                # VULNERÁVEL: XSS armazenado autêntico
                conn = sqlite3.connect(DB)
                conn.execute("INSERT INTO comentarios (autor, texto) VALUES (?, ?)", (autor, texto))
                conn.commit()
                conn.close()
            self.send_response(302)
            self.send_header("Location", "/comentarios")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Alvo XSS/IDOR rodando em http://127.0.0.1:{PORT}")
    server.serve_forever()
