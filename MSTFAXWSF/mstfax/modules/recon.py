"""Automated reconnaissance using only the standard library.

DNS resolution, light web-port check, HTTP probe (redirects are only followed to
hosts that are themselves in scope), TLS summary, security headers, cookies,
robots.txt / sitemap.xml / security.txt.
"""
from __future__ import annotations

import html
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from .. import scope, ui
from ..models import ModuleResult, now_iso
from .base import BaseModule, Context

WEB_PORTS = (80, 443, 8000, 8080, 8443, 3000)
MAX_REDIRECTS = 5

SECURITY_HEADERS = [
    # header, severity, advice, https_only
    ("strict-transport-security", "low", "Add HSTS so browsers always use HTTPS.", True),
    ("content-security-policy", "low", "Add a Content-Security-Policy to limit script/content sources.", False),
    ("x-content-type-options", "low", "Send 'X-Content-Type-Options: nosniff'.", False),
    ("x-frame-options", "low", "Send X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking.", False),
    ("referrer-policy", "info", "Set a Referrer-Policy to limit URL leakage.", False),
    ("permissions-policy", "info", "Set a Permissions-Policy to restrict browser features.", False),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # we follow redirects ourselves
        return None


def http_fetch(url: str, ua: str, timeout: int = 8, max_bytes: int = 200_000) -> dict:
    """GET without auto-redirects. Certificate errors are tolerated here (TLS is checked separately)."""
    tls = ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=tls))
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    out = {"url": url, "status": 0, "headers": {}, "cookies": [], "body": "", "error": ""}
    try:
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            resp = exc
        out["status"] = getattr(resp, "status", None) or getattr(resp, "code", 0)
        hdrs = resp.headers
        out["headers"] = {k.lower(): v for k, v in hdrs.items()}
        out["cookies"] = hdrs.get_all("Set-Cookie") or []
        out["body"] = resp.read(max_bytes).decode("utf-8", errors="replace")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError, ValueError) as exc:
        out["error"] = str(getattr(exc, "reason", exc))
    except Exception as exc:  # http.client.HTTPException etc.
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def resolve(host: str):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], str(exc)
    return sorted({i[4][0] for i in infos}), ""


def tls_info(host: str, port: int) -> dict:
    info: dict = {}

    def grab(context: ssl.SSLContext, want_cert: bool) -> None:
        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                info["protocol"] = wrapped.version()
                cipher = wrapped.cipher()
                info["cipher"] = cipher[0] if cipher else ""
                if want_cert:
                    cert = wrapped.getpeercert() or {}
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    info["subject"] = subject.get("commonName", "")
                    info["issuer"] = issuer.get("organizationName") or issuer.get("commonName", "")
                    info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:20]
                    if cert.get("notAfter"):
                        info["not_after"] = cert["notAfter"]
                        info["days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)

    try:
        grab(ssl.create_default_context(), True)
        info["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_error"] = exc.verify_message
        try:
            loose = ssl.create_default_context()
            loose.check_hostname = False
            loose.verify_mode = ssl.CERT_NONE
            grab(loose, False)
        except (OSError, ssl.SSLError):
            pass
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
    return info


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return html.unescape(" ".join(m.group(1).split()))[:120] if m else ""


class ReconModule(BaseModule):
    key = "recon"
    title = "Recon"
    description = "DNS, HTTP, TLS, headers, robots/sitemap"

    def run(self, ctx: Context) -> ModuleResult:
        res = ModuleResult(key=self.key, name=self.title, started=now_iso())
        t0 = time.monotonic()
        target = ctx.target
        say = lambda text, color=None: ctx.say("recon", text, color)  # noqa: E731

        # DNS ----------------------------------------------------------------
        ips, dns_err = resolve(target.host)
        res.data.update(host=target.host, ips=ips)
        if not ips:
            res.status, res.error = "failed", f"DNS resolution failed: {dns_err}"
            ctx.reachable = False
            res.duration = round(time.monotonic() - t0, 1)
            return res
        say(f"resolved {target.host} -> {', '.join(ips[:4])}", ui.WHITE)
        try:
            res.data["reverse_dns"] = socket.gethostbyaddr(ips[0])[0]
            say(f"reverse DNS: {res.data['reverse_dns']}")
        except (socket.herror, socket.gaierror, OSError):
            res.data["reverse_dns"] = ""

        # Light web-port check ---------------------------------------------------
        ports = [target.port] if target.port else list(WEB_PORTS)
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((ips[0], port), timeout=1.5):
                    open_ports.append(port)
            except OSError:
                continue
        res.data["open_web_ports"] = open_ports
        say(f"open web ports: {', '.join(map(str, open_ports)) or 'none found'}")

        # HTTP probe ---------------------------------------------------------------
        final = self._probe(ctx, res, say)
        if not final:
            res.status = "failed"
            res.error = "No HTTP(S) response from the target."
            ctx.reachable = False
            res.duration = round(time.monotonic() - t0, 1)
            return res

        # Analysis -------------------------------------------------------------------
        self._analyse_headers(ctx, res, final)
        self._analyse_cookies(res, final)
        if urlsplit(ctx.base_url).scheme == "https":
            self._tls(ctx, res, say)
        self._well_known(ctx, res, say)

        res.data["count"] = len(res.findings)
        res.status = "ok"
        res.duration = round(time.monotonic() - t0, 1)
        return res

    # -- helpers -------------------------------------------------------------------
    def _probe(self, ctx: Context, res: ModuleResult, say):
        target = ctx.target
        if target.scheme:
            schemes = [target.scheme]
        elif target.port in (80, 8000, 8080, 3000, 5000):
            schemes = ["http", "https"]
        else:
            schemes = ["https", "http"]

        chain, final, final_url, blocked = [], None, "", ""
        for scheme in schemes:
            url = target.url_for(scheme) + "/"
            resp = http_fetch(url, ctx.user_agent)
            hops = 0
            while resp["status"] in (301, 302, 303, 307, 308) and hops < MAX_REDIRECTS:
                location = resp["headers"].get("location", "")
                if not location:
                    break
                nxt = urljoin(url, location)
                nxt_host = (urlsplit(nxt).hostname or "").lower()
                if nxt_host != target.host and not scope.check_target(nxt_host).allowed:
                    blocked = nxt
                    break
                chain.append({"status": resp["status"], "to": nxt})
                url, hops = nxt, hops + 1
                resp = http_fetch(url, ctx.user_agent)
            if resp["status"]:
                final, final_url = resp, url
                break
        if not final:
            return None

        parts = urlsplit(final_url)
        target.base_url = f"{parts.scheme}://{parts.netloc}{target.path}".rstrip("/")
        if parts.hostname and parts.hostname.lower() != target.host:
            say(f"following redirect to in-scope host {parts.hostname}", ui.GREY)
        if blocked:
            res.add("info", "Redirect to out-of-scope host was not followed",
                    f"Target redirects to {blocked}. MSTFAXWSF only tests hosts that are in scope.")
            say(f"redirect to out-of-scope host NOT followed: {blocked}", ui.ORANGE)

        headers = final["headers"]
        res.data["http"] = {
            "url": final_url, "status": final["status"], "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""), "title": _title(final["body"]),
            "redirect_chain": chain, "headers": headers,
        }
        say(f"HTTP {final['status']} {final_url}", ui.WHITE)
        if headers.get("server"):
            say(f"server: {headers['server']}")
        if res.data["http"]["title"]:
            say(f"title: {res.data['http']['title']}")
        return final

    def _analyse_headers(self, ctx: Context, res: ModuleResult, final: dict) -> None:
        headers = final["headers"]
        https = urlsplit(ctx.base_url).scheme == "https"
        csp = headers.get("content-security-policy", "")
        for name, severity, advice, https_only in SECURITY_HEADERS:
            if https_only and not https:
                continue
            if name in headers:
                continue
            if name == "x-frame-options" and "frame-ancestors" in csp.lower():
                continue
            res.add(severity, f"Missing security header: {name}", advice, ctx.base_url + "/")
        server = headers.get("server", "")
        if re.search(r"\d+\.\d+", server):
            res.add("low", "Server version disclosed in Server header", server, ctx.base_url + "/")
        if headers.get("x-powered-by"):
            res.add("low", "Technology disclosed in X-Powered-By header",
                    headers["x-powered-by"], ctx.base_url + "/")
        if https is False and "443" in map(str, res.data.get("open_web_ports", [])):
            res.add("low", "HTTP is served without redirecting to HTTPS",
                    "Port 443 is open but the plain-HTTP site does not redirect to HTTPS.",
                    ctx.base_url + "/")

    def _analyse_cookies(self, res: ModuleResult, final: dict) -> None:
        https = final["url"].startswith("https")
        for cookie in final["cookies"]:
            name = cookie.split("=", 1)[0].strip()
            lower = cookie.lower()
            missing = []
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if https and "secure" not in lower:
                missing.append("Secure")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                res.add("low", f"Cookie '{name}' missing flags: {', '.join(missing)}",
                        "Set-Cookie attributes protect against theft and CSRF.", final["url"])

    def _tls(self, ctx: Context, res: ModuleResult, say) -> None:
        parts = urlsplit(ctx.base_url)
        port = parts.port or 443
        info = tls_info(parts.hostname or ctx.target.host, port)
        res.data["tls"] = info
        if info.get("error"):
            say(f"TLS error: {info['error']}", ui.ORANGE)
            return
        say(f"TLS {info.get('protocol', '?')} / {info.get('cipher', '?')}")
        if info.get("verified") is False:
            res.add("medium", "TLS certificate failed validation",
                    info.get("verify_error", "Certificate could not be verified."), ctx.base_url)
            say(f"certificate not trusted: {info.get('verify_error', '')}", ui.ORANGE)
        days = info.get("days_left")
        if days is not None:
            if days < 0:
                res.add("high", "TLS certificate has expired", f"Expired {-days} days ago.", ctx.base_url)
            elif days < 30:
                res.add("low", "TLS certificate expires soon", f"{days} days remaining.", ctx.base_url)

    def _well_known(self, ctx: Context, res: ModuleResult, say) -> None:
        base = ctx.base_url

        robots = http_fetch(base + "/robots.txt", ctx.user_agent)
        if robots["status"] == 200 and "disallow" in robots["body"].lower():
            paths = [l.split(":", 1)[1].strip() for l in robots["body"].splitlines()
                     if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()]
            res.data["robots_disallow"] = paths[:100]
            if paths:
                res.add("info", f"robots.txt lists {len(paths)} disallowed path(s)",
                        ", ".join(paths[:15]), base + "/robots.txt")
                say(f"robots.txt: {len(paths)} disallowed paths")

        sitemap = http_fetch(base + "/sitemap.xml", ctx.user_agent)
        if sitemap["status"] == 200 and ("<urlset" in sitemap["body"] or "<sitemapindex" in sitemap["body"]):
            count = len(re.findall(r"<loc>", sitemap["body"]))
            res.data["sitemap_urls"] = count
            res.add("info", f"sitemap.xml present ({count} URLs)", url=base + "/sitemap.xml")
            say(f"sitemap.xml: {count} URLs")

        sectxt = http_fetch(base + "/.well-known/security.txt", ctx.user_agent)
        has = sectxt["status"] == 200 and "contact:" in sectxt["body"].lower()
        res.data["security_txt"] = has
        if not has:
            res.add("info", "No security.txt published",
                    "A /.well-known/security.txt file tells researchers how to report issues.",
                    base + "/.well-known/security.txt")
