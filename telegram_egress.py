"""Restricted HTTP CONNECT proxy for Telegram Bot API over an exit-node SSH session.

Only api.telegram.org:443 is allowed. This keeps the panel's ordinary traffic
untouched and fails closed when the selected exit node cannot be reached.
"""
import select
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


_ALLOWED_HOSTS = {"api.telegram.org"}


class _ConnectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        # Do not log Telegram URLs or bot tokens.
        return

    def do_CONNECT(self):
        target = self.path.strip()
        if target.count(":") != 1:
            self.send_error(400, "Invalid CONNECT target")
            return
        host, port_text = target.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            self.send_error(400, "Invalid CONNECT port")
            return
        if host.lower() not in _ALLOWED_HOSTS or port != 443:
            self.send_error(403, "Only Telegram Bot API HTTPS is allowed")
            return

        ssh_manager = self.server.ssh_manager
        ssh_client = getattr(ssh_manager, "client", None)
        transport = ssh_client.get_transport() if ssh_client else None
        if not transport or not transport.is_active():
            self.send_error(502, "Exit-node SSH connection is unavailable")
            return

        channel = None
        try:
            channel = transport.open_channel(
                "direct-tcpip",
                (host, port),
                self.client_address,
                timeout=15,
            )
            self.connection.sendall(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: Amnezia-Web-Panel\r\n\r\n"
            )
            while True:
                readable, _, exceptional = select.select(
                    [self.connection, channel], [], [self.connection, channel], 60
                )
                if exceptional or not readable:
                    if not readable:
                        continue
                    break
                for source in readable:
                    try:
                        chunk = source.recv(65536)
                    except (OSError, EOFError):
                        return
                    if not chunk:
                        return
                    destination = channel if source is self.connection else self.connection
                    destination.sendall(chunk)
        except Exception:
            # Do not leak proxy details or credentials to the HTTP client.
            try:
                self.connection.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
        finally:
            if channel is not None:
                channel.close()


class _ThreadedProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TelegramExitProxy:
    """Loopback-only CONNECT proxy whose upstream TCP channels use SSH."""

    def __init__(self, ssh_manager):
        self.ssh_manager = ssh_manager
        self._server = _ThreadedProxyServer(("127.0.0.1", 0), _ConnectHandler)
        self._server.ssh_manager = ssh_manager
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self):
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="telegram-exit-proxy",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self):
        if self._thread and self._thread.is_alive():
            self._server.shutdown()
            self._thread.join(timeout=2)
        self._server.server_close()
