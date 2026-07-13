# SPDX-License-Identifier: GPL-2.0-only
#
# Minimal dual-stack HTTP file server used by the gwproxy integration tests.
#
# Usage: httpd.py <port> <docroot> [http_version]
#
# The server binds "::" with IPV6_V6ONLY disabled, so a target given as
# 127.0.0.1, [::1] or "localhost" all reach it. http_version "1.0" makes the
# server close the connection after each response (Connection: close), which
# exercises the proxy's peer-close handling; "1.1" keeps it alive.

import http.server
import os
import socket
import socketserver
import sys


def main():
    port = int(sys.argv[1])
    root = sys.argv[2]
    version = sys.argv[3] if len(sys.argv) > 3 else "1.1"

    os.chdir(root)

    class Handler(http.server.SimpleHTTPRequestHandler):
        protocol_version = "HTTP/" + version

        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_V6ONLY, 0)
            super().server_bind()

    Server(("::", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
