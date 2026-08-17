#!/usr/bin/env python3
"""Alvo LIMPO para benchmark de falsos positivos.

App web real e funcional (cadastro de produtos com SQLite, busca,
exportação e navegação por links), SEM nenhuma vulnerabilidade.
O scanner deve reportar ZERO vulnerabilidades neste alvo.

Uso: python3 alvo_limpo.py [porta]   (padrão 8888)
"""
import sqlite3
import html
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import unicodedata
import re

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
DB = "produtos_limpo.db"


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS produtos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        preco REAL NOT NULL,
        categoria TEXT NOT NULL DEFAULT 'geral')""")
    if cur.execute("SELECT COUNT(*) FROM produtos").fetchone()[0] == 0:
        cur.executemany("INSERT INTO produtos (nome, preco, categoria) VALUES (?, ?, ?)", [
            ("Notebook Pro 15", 4299.00, "informatica"),
            ("Teclado Mecânico RGB", 459.90, "informatica"),
            ("Monitor UltraWide 34\"", 2199.00, "informatica"),
            ("Mouse Ergonômico", 189.90, "informatica"),
            ("Headset Gamer 7.1", 329.90, "informatica"),
        ])
    conn.commit()
    conn.close()


def sanitize(value):
    """Sanitização defensiva: permite apenas caracteres seguros."""
    value = unicodedata.normalize("NFKD", str(value))
    value = "".join(c for c in value if unicodedata.category(c) != "Mn")
    value = re.sub(r"[^a-zA-Z0-9À-ÿ\s\-._]", "", value)
    return value.strip()


def query_db(sql, params):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


TEMPLATE_TOP = """<!DOCTYPE html>
<html lang='pt-BR'><head><meta charset='utf-8'>
<title>Loja Limpa — Produtos</title>
<style>body{{font-family:Arial,sans-serif;margin:24px}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:6px 10px}} th{{background:#2c3e50;color:#fff}}
nav a{{margin-right:14px}}</style></head><body>
<nav><a href='/'>Início</a><a href='/produtos'>Produtos</a><a href='/buscar'>Buscar</a><a href='/novo'>Novo Produto</a><a href='/sobre'>Sobre</a></nav>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_page(self, title, body):
        content = f"{TEMPLATE_TOP}<h1>{title}</h1>{body}</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    # ---- Rotas GET ----
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        def get_param(name, default=None):
            values = params.get(name, [])
            return values[0] if values else default

        if parsed.path == "/" or parsed.path == "/index":
            self.send_page("Início", "<p>Bem-vindo à <b>Loja Limpa</b>.</p>")

        elif parsed.path == "/produtos":
            rows = query_db("SELECT id, nome, preco, categoria FROM produtos", ())
            rows_html = "".join(
                f"<tr><td>{html.escape(str(r['nome']))}</td>"
                f"<td>R$ {float(r['preco']):.2f}</td>"
                f"<td>{html.escape(str(r['categoria']))}</td></tr>"
                for r in rows
            )
            self.send_page("Produtos", f"<table><tr><th>Nome</th><th>Preço</th><th>Categoria</th></tr>{rows_html}</table>")

        elif parsed.path == "/buscar":
            q = get_param("q")
            if q is None:
                self.send_page("Buscar", """<form action='/buscar' method='get'>
<input name='q' placeholder='Nome do produto'><button>Buscar</button></form>""")
                return
            q_safe = sanitize(q)
            if not q_safe:
                self.send_page("Buscar", "<p>Termo inválido.</p>")
                return
            # Busca por LIKE ESCAPED via sqlite3 (parâmetro parametrizado)
            rows = query_db("SELECT nome, preco FROM produtos WHERE nome LIKE '%' || ? || '%' ESCAPE '\\'", (q_safe,))
            if not rows:
                body = f"<p>Nenhum produto encontrado para '{html.escape(q_safe)}'.</p>"
            else:
                body = "".join(f"<p>{html.escape(str(r['nome']))} — R$ {float(r['preco']):.2f}</p>" for r in rows)
            self.send_page(f"Resultados para {html.escape(q_safe)}", body)

        elif parsed.path == "/sobre":
            self.send_page("Sobre", "<p>Loja Limpa — demonstração de aplicação segura.</p>")

        else:
            self.send_response(404)
            self.end_headers()

    # ---- Rotas POST ----
    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        params = parse_qs(body)

        def get_param(name, default=None):
            values = params.get(name, [])
            return values[0] if values else default

        if parsed.path == "/novo":
            if get_param("submit") is None:
                self.send_page("Novo Produto", """<form action='/novo' method='post'>
<input name='nome' placeholder='Nome do produto'><input name='preco' type='number' step='0.01' placeholder='Preço'>
<input name='categoria' placeholder='Categoria'><button name='submit' value='1'>Cadastrar</button></form>""")
                return
            nome = sanitize(get_param("nome", ""))
            preco_str = get_param("preco", "0")
            categoria = sanitize(get_param("categoria", "geral"))
            try:
                preco = float(preco_str)
            except ValueError:
                self.send_page("Novo Produto", "<p>Preço inválido.</p>")
                return
            if not nome or preco <= 0:
                self.send_page("Novo Produto", "<p>Dados inválidos.</p>")
                return
            conn = sqlite3.connect(DB)
            conn.execute("INSERT INTO produtos (nome, preco, categoria) VALUES (?, ?, ?)",
                         (nome, preco, categoria if categoria else "geral"))
            conn.commit()
            conn.close()
            self.send_page("Novo Produto", f"<p>Produto <b>{html.escape(nome)}</b> cadastrado.</p>")
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Alvo LIMPO rodando em http://127.0.0.1:{PORT}")
    server.serve_forever()
