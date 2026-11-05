#!/usr/bin/env python3
import http.server
import os
import ssl
import socketserver
import threading


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"edge-http-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"tcp:" + self.request.recv(4096))


http_server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), HTTP)
tcp_server = socketserver.ThreadingTCPServer(("127.0.0.1", 19001), TCP)
tcp_server.daemon_threads = True
mtls_server = socketserver.ThreadingTCPServer(("127.0.0.1", 19443), TCP)
mtls_server.daemon_threads = True
mtls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
mtls_context.load_cert_chain(
    os.path.join(os.environ["EDGE_CI_MTLS_DIR"], "server.crt"),
    os.path.join(os.environ["EDGE_CI_MTLS_DIR"], "server.key"),
)
mtls_context.load_verify_locations(os.path.join(os.environ["EDGE_CI_MTLS_DIR"], "ca.crt"))
mtls_context.verify_mode = ssl.CERT_REQUIRED
mtls_server.socket = mtls_context.wrap_socket(mtls_server.socket, server_side=True)

threading.Thread(target=tcp_server.serve_forever, daemon=True).start()
threading.Thread(target=mtls_server.serve_forever, daemon=True).start()
http_server.serve_forever()
