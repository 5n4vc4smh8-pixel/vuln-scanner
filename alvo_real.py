"""
Alvo REAL de teste - "Sistema de Gerenciamento de Produtos"

Este aplicativo simula um sistema web real escrito de forma DESCUIDADA,
com falhas AUTENTICAS (como um desenvolvedor iniciante faria sem saber
de boas praticas de seguranca):

- SQL Injection: queries montadas com concatenacao de strings
- XSS: valores refletidos sem escape no HTML
- LFI: abertura de arquivos com path montado a partir do input
- Command Injection: subprocess com shell=True e input do usuario
- Open Redirect: redirecionamento com URL de query sem validacao

O banco e um SQLite REAL em disco (produtos.db), com dados reais.
"""
import os
import sys
import sqlite3
import html as html_mod
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import socketserver
import subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "produtos.db")
CATALOFO_DIR = os.path.join(BASE, "catalogo")  # pasta de "documentos" do sistema


def init_db():
    """Cria o banco REAL com dados de exemplo."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS produtos (
        id INTEGER PRIMARY KEY, nome TEXT, preco TEXT, categoria TEXT)""")
    c.execute("SELECT COUNT(*) FROM produtos")
    if c.fetchone()[0] == 0:
        dados = [
            (1, "Notebook Gamer Pro", "4599.90", "eletronicos"),
            (2, "Teclado Mecanico RGB", "349.90", "perifericos"),
            (3, "Monitor 27 144Hz", "1299.90", "eletronicos"),
            (4, "Mouse Sem Fio Ergonomico", "189.90", "perifericos"),
            (5, "Headset 7.1 Surround", "279.90", "audio"),
        ]
        c.executemany("INSERT INTO produtos VALUES (?,?,?,?)", dados)
    conn.commit()
    conn.close()


os.makedirs(CATALOFO_DIR, exist_ok=True)
# Cria um documento "do sistema" (arquivo real) que o LFI pode ler
with open(os.path.join(CATALOFO_DIR, "notas_internas.txt"), "w") as f:
    f.write("NOTA INTERNA - CONFIDENCIAL\nAcesso restrito ao time financeiro.\nCodigo promocional: DESCONTO2026\n")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silencia os logs de requisicao

    # ============ FALHA REAL 1: SQL INJECTION ============
    # Desenvolvedor concatenou o input na query (a falha classica)
    def consultar_produto(self, produto_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # BUG: concatenacao direta do input na SQL (sem prepared statement)
        query = "SELECT * FROM produtos WHERE id = " + produto_id
        try:
            c.execute(query)
            rows = c.fetchall()
            if rows:
                return "<pre>Produto: %s | %s | R$ %s</pre>" % rows[0]
            else:
                return "<pre>Nenhum produto encontrado.</pre>"
        except Exception as e:
            # O banco DEVOLVE O ERRO SQL NA PAGINA (padrao do SQLi classico)
            return "<p style='color:red'>Erro de SQL: %s</p><pre>Query: %s</pre>" % (str(e)[:300], query)

    def listar_produtos(self, categoria):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # BUG: filtro por categoria tambem concatenado
        query = "SELECT nome, preco FROM produtos WHERE categoria = '" + categoria + "'"
        try:
            c.execute(query)
            rows = c.fetchall()
            out = "<ul>"
            for r in rows:
                out += "<li>%s - R$ %s</li>" % (r[0], r[1])
            out += "</ul>"
            return out
        except Exception as e:
            return "<p style='color:red'>Erro de SQL: %s</p><pre>Query: %s</pre>" % (str(e)[:300], query)

    # ============ FALHA REAL 2: XSS (reflexao sem escape) ============
    # O nome de busca e refletido na pagina SEM escapar HTML
    def busca_produtos(self, termo):
        # BUG: termo refletido cru (sem html.escape)
        return "<p>Resultados para: <b>%s</b></p>" % termo

    # ============ FALHA REAL 3: LFI ============
    # O documento e aberto montando o path com o input, sem validar ".."
    def ler_documento(self, nome_doc):
        path = os.path.join(CATALOFO_DIR, nome_doc)
        try:
            # BUG: leitura real de arquivo com path controlavel
            with open(path, "r", errors="replace") as f:
                conteudo = f.read(1024)
            return "<pre>%s</pre>" % conteudo
        except Exception as e:
            # Bug bonus: o erro revela o path interno do servidor (information disclosure)
            return "<pre>Erro ao ler documento: %s</pre>" % str(e)[:200]

    def ler_documento_completo(self, nome_doc):
        # Variante: resolve o path REAL absoluto (como a maioria dos alvos LFI faz)
        path = os.path.realpath(os.path.join(CATALOFO_DIR, nome_doc))
        try:
            with open(path, "r", errors="replace") as f:
                conteudo = f.read(2048)
            return "<pre>%s</pre>" % conteudo
        except Exception as e:
            return "<pre>Erro ao ler documento: %s</pre>" % str(e)[:200]

    # ============ FALHA REAL 4: COMMAND INJECTION ============
    # Gera um relatorio em PDF "executando um utilitario do sistema"
    def gerar_relatorio(self, comando):
        try:
            # BUG: shell=True com input do usuario
            out = subprocess.run(comando, shell=True, capture_output=True,
                                 text=True, timeout=8)
            return "<pre>Saida do utilitario:\n%s%s</pre>" % (out.stdout[:500], out.stderr[:500])
        except Exception as e:
            return "<pre>Erro ao executar utilitario: %s</pre>" % str(e)[:200]

    # ============ FALHA REAL 5: OPEN REDIRECT ============
    # Redireciona para qualquer URL passada na query, sem whitelist
    def redirecionar(self, destino, status=302):
        self.send_response(status)
        self.send_header("Location", destino)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        g = lambda name: params.get(name, [None])[0]

        produto_id = g("id")
        categoria = g("categoria")
        busca = g("busca")
        nome_doc = g("documento")
        utilitario = g("utilitario")
        destino = g("destino")

        corpo = ""

        if produto_id:
            corpo += self.consultar_produto(produto_id)
        if categoria:
            corpo += "<h3>Categoria: " + html_mod.escape(categoria) + "</h3>"
            corpo += self.listar_produtos(categoria)
        if busca:
            # XSS: refletido cru
            corpo += self.busca_produtos(busca)
        if nome_doc:
            corpo += self.ler_documento_completo(nome_doc)
        if utilitario:
            corpo += self.gerar_relatorio(unquote(utilitario))

        # Monta o HTML da pagina (formulario real)
        pagina = """<html><head><title>Loja Tech - Gerenciamento de Produtos</title></head>
<body>
<h1>Loja Tech - Painel de Produtos</h1>
<form method='GET' action='/'>
  <label>Buscar produto: <input name='busca' value='%(busca)s'></label>
  <button type='submit'>Buscar</button><br><br>
  <label>ID do produto: <input name='id' value='%(id)s'></label>
  <button type='submit'>Consultar</button><br><br>
  <label>Categoria: <input name='categoria' value='%(categoria)s'></label>
  <button type='submit'>Filtrar</button><br><br>
  <label>Documento interno: <input name='documento' value='%(documento)s'></label>
  <button type='submit'>Abrir</button><br><br>
  <label>Utilitario do sistema: <input name='utilitario' value='%(utilitario)s'></label>
  <button type='submit'>Executar</button><br><br>
  <label>Pagina externa: <input name='destino' value='%(destino)s'></label>
  <button type='submit'>Ir</button><br><br>
</form>
<hr>
%(corpo)s
<hr>
<a href='/?destino=https://evil.com'>Ir para site parceiro</a>
</body></html>""" % {
            "busca": busca or "",
            "id": produto_id or "",
            "categoria": categoria or "",
            "documento": nome_doc or "",
            "utilitario": utilitario or "",
            "destino": destino or "",
            "corpo": corpo,
        }

        if destino:
            # BUG: open redirect real (302 com Location)
            self.redirecionar(destino)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(pagina.encode("utf-8"))


def main():
    init_db()
    porta = 59599 if len(sys.argv) < 2 else int(sys.argv[1])
    print("Sistema real (com falhas autenticas) rodando em http://localhost:%d" % porta, flush=True)
    print("Banco SQLite: " + DB_PATH, flush=True)
    ThreadedHTTPServer(("localhost", porta), Handler).serve_forever()


if __name__ == "__main__":
    main()
