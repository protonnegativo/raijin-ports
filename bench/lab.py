"""Local lab for the raijin-ports benchmark: fake services on loopback addresses, one process.

Each argument is ip:port=kind. The loopback range (127.0.0.0/8) gives several "hosts" on one machine.
Each kind answers just enough for nmap -sV to fingerprint it: a web server, an SSH banner, a Redis,
MySQL and Memcached server, VNC, Telnet, and the Docker and Elasticsearch REST APIs.

usage: python3 lab.py 127.0.0.1:19080=nginx 127.0.0.2:19379=redis 127.0.0.3:19500-19699=closer ...
"""
import asyncio
import struct
import sys


def http(server, body=b"<html><head><title>Welcome</title></head><body>ok</body></html>", ctype=b"text/html"):
    def reply(data):
        if not data.startswith((b"GET ", b"HEAD ", b"POST ", b"OPTIONS ")):
            return b"HTTP/1.1 400 Bad Request\r\nServer: " + server + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", True
        return (b"HTTP/1.1 200 OK\r\nServer: " + server + b"\r\nContent-Type: " + ctype + b"\r\nContent-Length: " +
                str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body), True
    return None, reply


def redis():
    def reply(data):
        cmd = data.split()[:1]
        if cmd and cmd[0].isalpha():
            return b"-ERR wrong number of arguments for '" + cmd[0].lower() + b"' command\r\n", False
        return b"-ERR unknown command\r\n", False
    return None, reply


def mysql():
    payload = (b"\x0a" + b"8.0.33-0ubuntu0.22.04.2\x00" + struct.pack("<I", 11) + b"abcdefgh\x00" +
               struct.pack("<H", 0xffff) + b"\xff" + struct.pack("<H", 2) + struct.pack("<H", 0xdfff) +
               b"\x15" + b"\x00" * 10 + b"ijklmnopqrst\x00" + b"caching_sha2_password\x00")
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload, None


def memcached():
    # Memcached answers ERROR to every line it does not know, VERSION to "version".
    def reply(data):
        out = b""
        for line in data.split(b"\r\n")[:-1] or [data]:
            out += b"VERSION 1.6.14\r\n" if line.strip() == b"version" else b"ERROR\r\n"
        return out, False
    return None, reply


def docker():
    def reply(data):
        if data.startswith(b"OPTIONS "):
            return (b"HTTP/1.0 200 OK\r\nApi-Version: 1.43\r\nDocker-Experimental: false\r\nOstype: linux\r\n"
                    b"Server: Docker/24.0.5 (linux)\r\nDate: Sat, 24 Oct 2026 21:00:00 GMT\r\nContent-Length: 0\r\n\r\n"), True
        body = b'{"message":"page not found"}\n'
        return (b"HTTP/1.0 404 Not Found\r\nContent-Type: application/json\r\nDate: Sat, 24 Oct 2026 21:00:00 GMT\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body), True
    return None, reply


ES = (b'{\n  "name" : "node-1",\n  "cluster_name" : "elasticsearch",\n  "cluster_uuid" : "kD3tQ0rXRbmW5ZyN8b9ZQw",\n'
      b'  "version" : {\n    "number" : "7.17.9",\n    "build_flavor" : "default",\n    "lucene_version" : "8.11.1"\n'
      b'  },\n  "tagline" : "You Know, for Search"\n}\n')


def elastic():
    def reply(data):
        return (b"HTTP/1.0 200 OK\r\ncontent-type: application/json; charset=UTF-8\r\ncontent-length: " +
                str(len(ES)).encode() + b"\r\n\r\n" + ES), True
    return None, reply


KINDS = {
    "nginx": lambda: http(b"nginx/1.18.0 (Ubuntu)"),
    "apache": lambda: http(b"Apache/2.4.52 (Ubuntu)"),
    "ssh": lambda: (b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n", None),
    "redis": redis,
    "mysql": mysql,
    "memcached": memcached,
    "vnc": lambda: (b"RFB 003.008\n", None),
    "telnet": lambda: (b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27", None),
    "docker": docker,
    "elastic": elastic,
    # closer accepts and closes at once, like a firewall or tarpit that answers on every port: nmap says
    # tcpwrapped.
    "closer": lambda: (None, None),
}


def handler(kind):
    greet, reply = KINDS[kind]()

    async def handle(reader, writer):
        try:
            if kind == "closer":
                return
            if greet:
                writer.write(greet)
                await writer.drain()
            while True:
                data = await asyncio.wait_for(reader.read(4096), 30)
                if not data or not reply:
                    break
                out, done = reply(data)
                writer.write(out)
                await writer.drain()
                if done:
                    break
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
    return handle


async def main(specs):
    servers = []
    for spec in specs:
        addr, kind = spec.split("=", 1)
        ip, ports = addr.rsplit(":", 1)
        first, _, last = ports.partition("-")
        for port in range(int(first), int(last or first) + 1):
            servers.append(await asyncio.start_server(handler(kind), ip, port))
    print(f"lab: {len(servers)} services", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
