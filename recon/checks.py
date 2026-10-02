"""Проверки рекон / siteINFO+. Набор легаси-проверок и источников.

Каждая проверка — функция, принимающая context (модуль recon.context.Context)
и возвращающая (name, форматированная строка, keywords[]) или None.
Любые ошибки ловятся и не роняют прогон: ошибочные/пустые данные отбрасываются.
"""
import re
import ssl
import socket
import json
import base64
import hashlib
import urllib.parse
from datetime import datetime

import requests
import whois as pywhois
import dns.resolver
import dns.reversename

from recon import context

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
HTTP_RE = re.compile(r"^https?://", re.I)


def _err(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc)[:140]}"


def _url(ctx) -> str:
    u = ctx.url
    return u if HTTP_RE.match(u) else "http://" + u


def _hget(ctx, path="/", **kw):
    kw.setdefault("timeout", 12)
    kw.setdefault("headers", kw.pop("headers", {"User-Agent": UA, "Accept": "text/html"}))
    kw.setdefault("verify", bool(getattr(ctx, "verify", True)))
    kw.setdefault("allow_redirects", kw.pop("redirects", True))
    return requests.get(_url(ctx) + path, **kw)


def _hreq(ctx, method, path="/", **kw):
    kw.setdefault("timeout", 12)
    kw.setdefault("headers", kw.pop("headers", {"User-Agent": UA}))
    kw.setdefault("verify", True)
    kw.setdefault("allow_redirects", kw.pop("redirects", True))
    return requests.request(method, _url(ctx) + path, **kw)


# ---------------------------------------------------------------- DNS ---
def dns_a(ctx):
    try:
        ans = dns.resolver.resolve(ctx.host, "A")
        v = ", ".join(sorted({r.address for r in ans}))
        return "A-записи (IPv4)", v, ["DNS", "IP"]
    except Exception as e:
        ctx.err(e); return None


def dns_aaaa(ctx):
    try:
        ans = dns.resolver.resolve(ctx.host, "AAAA")
        v = ", ".join(sorted({r.address for r in ans}))
        return "AAAA-записи (IPv6)", v, []
    except Exception as e:
        ctx.err(e); return None


def dns_ns(ctx):
    try:
        vals = sorted({str(r) for r in dns.resolver.resolve(ctx.host, "NS")})
        return "NS (серверы имён)", "\n".join(vals), ["DNS"]
    except Exception as e:
        ctx.err(e); return None


def dns_mx(ctx):
    try:
        vals = sorted({f"{r.preference} {r.exchange}" for r in dns.resolver.resolve(ctx.host, "MX")})
        return "MX (почта, приоритет хост)", "\n".join(vals) or "нет MX", ["MX"]
    except Exception as e:
        ctx.err(e); return None


def dns_txt(ctx):
    try:
        vals = {str(r) for r in dns.resolver.resolve(ctx.host, "TXT")}
        out = "\n".join(f"- {v}" for v in sorted(vals)) if vals else "нет TXT"
        return "TXT-записи", out, ["TXT"]
    except Exception as e:
        ctx.err(e); return None


def dns_spf(ctx):
    try:
        spf = {str(r) for r in dns.resolver.resolve(ctx.host, "TXT")
               if str(r).lower().startswith("v=spf1")}
        if spf:
            return "SPF-запись (антиспам)", "\n".join(sorted(spf)), ["SPF"]
    except Exception:
        pass
    try:
        apx = [c for c in ctx.domain.split(".")]
        base = ".".join(apx[-2:])
        spf = {str(r) for r in dns.resolver.resolve(base, "TXT")
               if str(r).lower().startswith("v=spf1")}
        if spf:
            return "SPF-запись (домен)", "\n".join(sorted(spf)), ["SPF"]
    except Exception as e:
        ctx.err(e)
    return None


def dns_dmarc(ctx):
    for probe in ("_dmarc." + ctx.domain, "_dmarc." + ctx.host):
        try:
            recs = {str(r) for r in dns.resolver.resolve(probe, "TXT")}
            if recs:
                return f"DMARC (для {probe})", "\n".join(recs), ["DMARC"]
        except Exception:
            continue
    return None


def dns_cname(ctx):
    try:
        ans = dns.resolver.resolve(ctx.host, "CNAME")
        return "CNAME (каноническое имя)", str(ans[0].target), ["CNAME"]
    except Exception:
        return None


def dns_dkim(ctx):
    cand = ("default", "google", "s1", "selector1", "k1", "mail", "dkim", "20120113")
    found = []
    for sel in cand:
        try:
            for r in dns.resolver.resolve(f"{sel}._domainkey.{ctx.domain}", "TXT"):
                found.append(f"{sel}._domainkey: {str(r)[:200]}")
        except Exception:
            continue
    if found:
        return "DKIM (селекторы)", "\n".join(found), ["DKIM"]
    return None


def dns_soa(ctx):
    try:
        ans = dns.resolver.resolve(ctx.domain, "SOA")
        r = ans[0]
        return ("SOA", f"mname={r.mname}\nrnser={r.rname}\nserial={r.serial}\n"
                f"refresh={r.refresh} retry={r.retry} expire={r.expire} minimum={r.minimum}", [])
    except Exception as e:
        ctx.err(e); return None


def dns_ptr(ctx):
    try:
        rev = dns.reversename.from_address(ctx.ip)
        ans = dns.resolver.resolve(rev, "PTR")
        return "PTR (обратный DNS)", ", ".join(str(x) for x in ans), ["PTR"]
    except Exception as e:
        ctx.err(e); return None


def dns_any_wildcard(ctx):
    probe = "nx-does-not-exist-" + hashlib.md5(ctx.host.encode()).hexdigest()[:8]
    try:
        dns.resolver.resolve(probe + "." + ctx.domain, "A")
        return "Wildcard DNS", "ЕСТЬ wildcard (поддомены резолвятся все)", ["DNS"]
    except Exception:
        return None


def dns_find_subdomains(ctx):
    cn = ("www", "mail", "ftp", "admin", "api", "cpanel", "webmail", "mx", "ns1",
          "ns2", "dashboard", "dev", "test", "shop", "store", "blog", "vpn", "secure")
    found = []
    for sub in cn:
        try:
            dns.resolver.resolve(f"{sub}.{ctx.domain}", "A")
            found.append(f"{sub}.{ctx.domain}")
        except Exception:
            continue
    if found:
        return "Известные поддомены", "\n".join(sorted(set(found))), ["subdomain"]
    return None


# ---------------------------------------------------------------- WHOIS ---
def whois_main(ctx):
    try:
        w = pywhois.whois(ctx.domain)
        pairs = []
        for k in ("name", "org", "registrar", "creation_date", "expiration_date",
                  "updated_date", "status", "registrant", "rdap_service", "abuse"):
            val = getattr(w, k, None)
            if val is None:
                continue
            if isinstance(val, (list, tuple)):
                val = ", ".join(str(x) for x in val)
            if k in ("creation_date", "expiration_date", "updated_date"):
                try:
                    if isinstance(val, str) and "," in val:
                        val = val.split(",")[0]
                    d = datetime.fromisoformat(str(val)[:19].replace("Z", "+00:00"))
                    val = d.strftime("%Y-%m-%d %H:%M %Z")
                except Exception:
                    pass
            pairs.append(f"- {k}: {val}")
        if not pairs:
            return None
        return "WHOIS (регистрационные данные)", "\n".join(pairs), ["whois", "регистрант"]
    except Exception as e:
        ctx.err(e); return None


def whois_registrar(ctx):
    try:
        w = pywhois.whois(ctx.domain)
        reg = w.registrar
        if not reg:
            # fallback: сырой текст
            raw = getattr(w, "text", "") or ""
            m = re.search(r"Registrar:\s*(.+)", raw)
            reg = m.group(1).strip() if m else None
        if reg:
            return "Регистратор (WHOIS)", str(reg), ["whois"]
    except Exception as e:
        ctx.err(e)
    return None


def whois_server_info(ctx):
    import whois as _w, whois.parser as _p
    try:
        r = pywhois.whois(ctx.domain)
        raw = getattr(r, "text", "") or ""
        if not raw:
            return None
        lines = [l for l in raw.splitlines() if l.strip()]
        cap = "\n".join(lines[:25])
        for word in ("%", "#"):
            cap = cap.replace(word, "//")
        return "WHOIS сырой (первый блок)", cap, ["whois"]
    except Exception as e:
        ctx.err(e); return None


def whois_ip_ranges(ctx):
    # кто владеет IP блоками (примерный lookup по RDAP-ish пулу)
    import ipaddress
    try:
        data = ctx.http_json(f"https://ipinfo.io/{ctx.ip}/json")
        if not data:
            return None
        org = data.get("org") or data.get("asn")
        cidr = data.get("range") or data.get("cidr")
        parts = []
        if org:
            parts.append(f"- владелец AS: {org}")
        if cidr:
            parts.append(f"- диапазон: {cidr}")
        if city := data.get("city"):
            parts.append(f"- гео: {city}, {data.get('region', '')}, {data.get('country', '')}")
        if parts:
            return "AS / владелец IP (ipinfo)", "\n".join(parts), ["ASN", "гео"]
    except Exception as e:
        ctx.err(e)
    return None


def asn_lookup(ctx):
    try:
        # Cymru DNS-based whois
        parts = ctx.ip.strip().split(".")
        rev = ".".join(reversed(parts)) + ".origin.asn.cymru.com"
        ans = dns.resolver.resolve(rev, "TXT")
        raw = str(ans[0])
        return "ASN (Team Cymru)", raw, ["ASN"]
    except Exception as e:
        ctx.err(e); return None


def ip_country_geo(ctx):
    try:
        data = ctx.http_json(f"https://ipapi.co/{ctx.ip}/json/") or ctx.http_json(f"https://ipinfo.io/{ctx.ip}/json")
        if not data:
            return None
        rows = []
        for k in ("ip", "city", "region", "region_code", "country", "country_name", "postal", "latitude", "longitude", "timezone", "asn", "as", "org"):
            if v := data.get(k):
                rows.append(f"- {k}: {v}")
        if rows:
            return "Геолокация IP (ipapi/ipinfo)", "\n".join(rows), ["гео"]
    except Exception as e:
        ctx.err(e); return None


# ---------------------------------------------------------------- HTTP ---
def http_server_header(ctx):
    try:
        r = ctx.http_get()
        h = r.headers.get("Server")
        if h:
            return "Server header", h, ["fingerprint"]
    except Exception as e:
        ctx.err(e)
    return None


def http_tech_headers(ctx):
    try:
        r = ctx.http_get()
        hs = r.headers
        piv = {
            "X-Powered-By": "X-Powered-By",
            "X-AspNet-Version": "X-AspNet-Version",
            "X-Generator": "X-Generator",
            "X-Frame-Options": "X-Frame-Options",
            "Strict-Transport-Security": "Strict-Transport-Security",
            "Content-Security-Policy": "Content-Security-Policy",
            "CF-Ray": "Cloudflare ray",
            "X-Runtime": "X-Runtime (Rails)",
            "X-Pingback": "X-Pingback",
        }
        found = [f"- {piv[k]}: {hs[k]}" for k in piv if hs.get(k)]
        if found:
            return "Технологические заголовки", "\n".join(found), ["fingerprint", "tech"]
    except Exception as e:
        ctx.err(e)
    return None


def http_redirect_chain(ctx):
    try:
        r = ctx.http_get()
        if r.history:
            chain = " -> ".join(x.status_code and f"{x.status_code} {x.url}" for f in r.history for x in [f]) + \
                    f" -> {r.status_code} {r.url}"
            return "Цепочка редиректов", chain, []
        return None
    except Exception as e:
        ctx.err(e); return None


def http_final_url(ctx):
    try:
        r = ctx.http_get(redirects=True)
        return "Итоговый URL", f"{r.status_code} {r.url}", []
    except Exception as e:
        ctx.err(e); return None


def http_status_codes(ctx):
    try:
        r = ctx.http_get(redirects=False)
        return "HTTP статус (без редиректов)", f"{r.status_code}", ["HTTP"]
    except Exception as e:
        ctx.err(e); return None


def http_all_methods(ctx):
    try:
        out = []
        for m in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE"):
            try:
                s = requests.Session()
                kw = {"timeout": 10, "headers": {"User-Agent": UA}, "allow_redirects": False}
                if m in ("POST", "PUT", "PATCH"):
                    kw["data"] = ""
                rr = s.request(m, _url(ctx), **kw)
                out.append(f"- {m}: {rr.status_code}")
            except Exception:
                out.append(f"- {m}: error/блок")
        return "HTTP методы (options)", "\n".join(out), ["HTTP"]
    except Exception as e:
        ctx.err(e); return None


def http_security_headers(ctx):
    try:
        r = ctx.http_get()
        hs = r.headers
        want = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
                "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"]
        present = [w for w in want if hs.get(w)]
        missing = [w for w in want if not hs.get(w)]
        score = len(present)
        out = [f"- настроены ({score}/{len(want)}): " + (", ".join(present) if present else "нет")]
        if missing:
            out.append(f"- отсутствуют: {', '.join(missing)}")
        return "Security headers (оценка)", "\n".join(out), ["security"]
    except Exception as e:
        ctx.err(e); return None


def http_cookies(ctx):
    try:
        r = ctx.http_get()
        if not r.cookies:
            return None
        return "Cookies (флаги)", "\n".join(f"- {c.name}: {c.value[:40]}" for c in r.cookies), ["cookie"]
    except Exception as e:
        ctx.err(e); return None


def http_title_meta(ctx):
    try:
        r = ctx.http_get()
        if "html" not in (r.headers.get("Content-Type", "")):
            return None
        t = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.S | re.I)
        title = re.sub(r"\s+", " ", t.group(1)).strip() if t else ""
        desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', r.text, re.S | re.I)
        desc_alt = re.search(r'<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']', r.text, re.S | re.I)
        d = (desc or desc_alt)
        rows = [f"- title: {title}"] if title else []
        if d:
            rows.append(f"- meta description: {d.group(1)[:300]}")
        if rows:
            return "Заголовок и описание страницы", "\n".join(rows), ["content"]
    except Exception as e:
        ctx.err(e)
    return None


def http_generator_meta(ctx):
    try:
        r = ctx.http_get()
        g = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', r.text, re.I)
        if g:
            return "CMS / генератор (meta)", g.group(1)[:120], ["cms", "fingerprint"]
    except Exception as e:
        ctx.err(e)
    return None


def http_favicon_hash(ctx):
    try:
        r = ctx.http_get()
        m = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\'](.*?)["\']', r.text, re.I)
        href = m.group(1) if m else "/favicon.ico"
        if href.startswith("//"):
            href = ("https:" if ctx.url.startswith("https") else "http:") + href
        elif not href.startswith("http"):
            href = urllib.parse.urljoin(_url(ctx), href)
        fr = requests.get(href, timeout=10, headers={"User-Agent": UA})
        h = hashlib.md5(fr.content).hexdigest()
        return "Favicon hash (mmh3/md5)", f"md5={h} [{len(fr.content)} b]", ["fingerprint"]
    except Exception as e:
        ctx.err(e); return None


def http_robots(ctx):
    try:
        r = _hget(ctx, "/robots.txt")
        if r.status_code == 200 and r.text:
            lines = [l for l in r.text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
            if lines:
                return "robots.txt", "\n".join(lines[:40]), ["crawl"]
    except Exception as e:
        ctx.err(e)
    return None


def http_sitemap(ctx):
    try:
        r = _hget(ctx, "/sitemap.xml")
        if r.status_code == 200 and "<urlset" in r.text[:500]:
            n = len(re.findall(r"<url>", r.text))
            return "sitemap.xml", f"обнаружен, ~{n} URL", ["crawl"]
    except Exception as e:
        ctx.err(e)
    return None


def http_wellknown_security(ctx):
    try:
        r = _hget(ctx, "/.well-known/security.txt")
        if r.status_code == 200:
            return "security.txt", r.text[:400], ["security"]
    except Exception as e:
        ctx.err(e)
    return None


def http_server_tech_probe(ctx):
    # тех-стек по заголовкам + cookie атрибутам
    try:
        r = ctx.http_get()
        hs = r.headers
        res = []
        for probe in ("wp-content", "wp-json"):
            if probe in r.text[:6000]:
                res.append("WordPress")
                break
        if any(c.name == "PHPSESSID" for c in r.cookies):
            res.append("PHP")
        if any(c.name == "sessionid" for c in r.cookies):
            res.append("Django")
        if any(c.name == "JSESSIONID" for c in r.cookies):
            res.append("Java/JSP")
        if "ASP.NET" in (r.headers.get("Server", "") or ""):
            res.append("ASP.NET")
        if "wp" in (hs.get("X-Powered-By", "") or "").lower():
            res.append("WordPress")
        if res:
            return "CMS / фреймворк (профиль)", ", ".join(sorted(set(res))), ["cms", "tech"]
    except Exception as e:
        ctx.err(e)
    return None


def http_ssl_redirect_only(ctx):
    try:
        r = _hget(ctx, "/", headers={"User-Agent": UA}, redirects=False)
        body = r.text[:4000].lower()
        if any(x in body for x in ("must verify your identity", "unusual traffic", "captcha", "access denied", "verifying you")):
            return "WAF / защита запроса", "Обнаружена страница проверки (вероятно WAF)", ["WAF"]
    except Exception as e:
        ctx.err(e)
    return None


def http_cdn_provider(ctx):
    try:
        r = ctx.http_get()
        h = r.headers
        prov = None
        if h.get("CF-Ray") or "cloudflare" in (h.get("Server", "") or "").lower():
            prov = "Cloudflare"
        elif "akamai" in (h.get("Server", "") or "").lower():
            prov = "Akamai"
        elif "Fastly" in (h.get("Server", "") or ""):
            prov = "Fastly"
        elif h.get("X-Cache") and "nginx" in r.text[:3000].lower():
            prov = "CDN (nginx)"
        if prov:
            return "CDN / прокси", prov, ["CDN", "WAF"]
    except Exception as e:
        ctx.err(e)
    return None


def http_error_pages(ctx):
    try:
        probe = hashlib.md5(b"err").hexdigest()[:10]
        r = _hget(ctx, "/" + probe + ".php")
        body = (r.text or "").lower()
        tech = []
        if "stack trace" in body or "<b>warning</b>" in body:
            tech.append("PHP error display")
        if "traceback" in body and "flask" not in body:
            tech.append("Python traceback")
        if '<h1>server error</h1>' in body:
            tech.append("ASP.NET default error")
        if tech:
            return "Информация об ошибках (verbose)", ", ".join(tech) + " — включено подробно", ["fingerprint"]
    except Exception as e:
        ctx.err(e)
    return None


def http_exposed_files(ctx):
    try:
        found = []
        for f in ("/.git/config", "/.env", "/.htaccess", "/.gitignore", "/web.config", "/server-status", "/config.php"):
            try:
                rr = _hget(ctx, f, headers={"User-Agent": UA})
                if rr.status_code == 200 and "page not found" not in rr.text[:400].lower():
                    if f == "/.env" and "=" not in rr.text[:800]:
                        continue
                    if f == "/.git/config" and 'repositoryformatversion' not in rr.text[:2000]:
                        continue
                    found.append(f)
            except Exception:
                continue
        if found:
            return "Возможные открытые служебные файлы", "\n".join("- " + x for x in found), ["exposed", "security"]
    except Exception as e:
        ctx.err(e)
    return None


def http_common_dirs(ctx):
    try:
        found = []
        for p in ("/admin", "/login", "/wp-admin", "/phpmyadmin", "/cpanel", "/api", "/docs",
                  "/backup", "/uploads", "/console"):
            try:
                rr = _hget(ctx, p, headers={"User-Agent": UA}, redirects=False)
                if rr.status_code == 200:
                    found.append(f"{p} (200)")
            except Exception:
                continue
        if found:
            return "Популярные пути (просканировано)", "\n".join(found), ["enum"]
    except Exception as e:
        ctx.err(e)
    return None


# ---------------------------------------------------------------- TLS ---
def tls_certificate(ctx):
    try:
        h = ctx.host
        ctx_data = ssl.create_default_context()
        with socket.create_connection((h, 443), timeout=12) as sock:
            with ctx_data.wrap_socket(sock, server_hostname=h) as t:
                der = t.getpeercert(binary_form=True)
                import cryptography.x509 as x509
                cert = x509.load_der_x509_certificate(der)
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M")
                not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M")
                sn = cert.serial_number
                sans = []
                try:
                    for ext in cert.extensions:
                        if ext.oid._name == "subjectAltName":
                            sans = [str(x.value) for x in ext.value]
                except Exception:
                    pass
                sig = cert.signature_algorithm_oid._name
                ver = cert.version.name.upper()
                days = (cert.not_valid_after_utc - datetime.utcnow()).days
                rows = [
                    f"- subject: {subject}",
                    f"- issuer: {issuer}",
                    f"- срок: {not_before} .. {not_after} (осталось {days} дн.)",
                    f"- серийный: {sn}",
                    f"- сигнатура: {sig} ({ver})",
                ]
                if sans:
                    rows.append("- SAN: " + ", ".join(sans[:12]))
                return "TLS-сертификат", "\n".join(rows), ["TLS", "cert"]
    except Exception as e:
        ctx.err(e)
    return None


def tls_protocols(ctx):
    try:
        h = ctx.host
        res = []
        for proto, ctxm in (("TLSv1.0", ssl._create_unverified_context()), ("TLSv1.1", ssl._create_unverified_context()),
                            ("TLSv1.2", ssl._create_unverified_context()), ("TLSv1.3", ssl._create_unverified_context())):
            try:
                try:
                    ctxm.minimum_version = {"TLSv1.0": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                                            "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}[proto]
                    ctxm.maximum_version = ctxm.minimum_version
                except Exception:
                    pass
                with socket.create_connection((h, 443), timeout=8) as s:
                    with ctxm.wrap_socket(s, server_hostname=h) as t:
                        v = t.version()
                        res.append(f"- {proto}: OK ({v})")
            except Exception:
                res.append(f"- {proto}: не поддерживается")
        return "TLS протоколы", "\n".join(res), ["TLS"]
    except Exception as e:
        ctx.err(e); return None


# ---------------------------------------------------------------- Порты ---
def port_scan(ctx):
    try:
        h = ctx.ip
        common = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 7001, 8000, 8080, 8443, 9200, 27017]
        openp = []
        for p in common:
            try:
                with socket.create_connection((h, p), timeout=1.6):
                    openp.append(p)
            except Exception:
                continue
        if openp:
            return "Открытые TCP-порты (топ-24)", ", ".join(f"{p}" for p in openp), ["ports"]
    except Exception as e:
        ctx.err(e)
    return None


def port_banners(ctx):
    try:
        h = ctx.ip
        out = []
        for p in (21, 22, 25, 110, 143, 3306, 5432, 8080):
            try:
                with socket.create_connection((h, p), timeout=2.5) as s:
                    s.settimeout(2.5)
                    try:
                        b = s.recv(200).decode("utf-8", "ignore").strip()
                    except Exception:
                        b = ""
                    if b:
                        out.append(f"- {p}: {b[:120]}")
            except Exception:
                continue
        if out:
            return "Banner служб (базовый)", "\n".join(out), ["banner"]
    except Exception as e:
        ctx.err(e)
    return None


# ---------------------------------------------------------------- Прочее ---
def email_domain_probe(ctx):
    try:
        # MX присутствует?
        try:
            dns.resolver.resolve(ctx.host, "MX")
            mx_ok = "MX есть"
        except Exception:
            mx_ok = "MX нет — почта, возможно, у провайдера"
        return "Почтовая инфраструктура", mx_ok, ["mail"]
    except Exception as e:
        ctx.err(e)
    return None


def dns_caa(ctx):
    try:
        try:
            vals = {str(r).strip('"') for r in dns.resolver.resolve(ctx.host, "CAA")}
        except Exception:
            vals = {str(r).strip('"') for r in dns.resolver.resolve(ctx.domain, "CAA")}
        if vals:
            return "CAA (кто может выпускать TLS-серт)", "\n".join(sorted(vals)), ["DNS", "TLS"]
    except Exception as e:
        ctx.err(e)
    return None


def dns_https_svcb(ctx):
    try:
        for probe in (ctx.host, ctx.domain):
            try:
                ans = dns.resolver.resolve(probe, "HTTPS")
                if ans:
                    out = "\n".join(str(r) for r in ans)[:400]
                    return "HTTPS/SVCB (параметры соединения)", out, ["DNS"]
            except Exception:
                continue
    except Exception as e:
        ctx.err(e)
    return None


def whois_domain_status(ctx):
    try:
        w = pywhois.whois(ctx.domain)
        st = getattr(w, "status", None)
        if st:
            if not isinstance(st, (list, tuple)):
                st = [st]
            return "Статусы домена (политика регистратора)", "\n".join("- " + str(x) for x in st), ["whois"]
    except Exception as e:
        ctx.err(e)
    return None


def whois_created_expires(ctx):
    try:
        w = pywhois.whois(ctx.domain)
        rows = []
        for lab, attr in (("создан", "creation_date"), ("истекает", "expiration_date"), ("обновлён", "updated_date")):
            v = getattr(w, attr, None)
            if not v:
                continue
            if isinstance(v, (list, tuple)):
                v = v[0]
            try:
                d = datetime.fromisoformat(str(v)[:19].replace("Z", "+00:00"))
                rows.append(f"- {lab}: {d.strftime('%Y-%m-%d')}")
            except Exception:
                rows.append(f"- {lab}: {v}")
        if rows:
            return "Даты WHOIS", "\n".join(rows), ["whois"]
    except Exception as e:
        ctx.err(e)
    return None


def whois_nameservers(ctx):
    try:
        w = pywhois.whois(ctx.domain)
        ns = getattr(w, "name_servers", None)
        if ns:
            if not isinstance(ns, (list, tuple)):
                ns = [ns]
            return "Именные серверы (WHOIS)", "\n".join("- " + str(x) for x in ns), ["whois", "DNS"]
    except Exception as e:
        ctx.err(e)
    return None


def http_allow_methods(ctx):
    try:
        r = _hreq(ctx, "OPTIONS", "/")
        allow = r.headers.get("Allow") or r.headers.get("Public") or r.headers.get("Access-Control-Allow-Methods")
        if allow:
            return "Allowed HTTP методы (Allow)", allow, ["HTTP"]
    except Exception as e:
        ctx.err(e)
    return None


def http_www_vs_root(ctx):
    try:
        www = "www." + ctx.domain
        if www == ctx.host:
            return None
        rows = []
        r1 = requests.get(_url(ctx) if ctx.host == ctx.domain else "http://" + www, timeout=8, allow_redirects=False)
        rows.append(f"- без www: {ctx.host} → {r1.status_code} {r1.headers.get('Location', '')[:60]}")
        r2 = requests.get(f"https://{www}", timeout=8, allow_redirects=False, headers={"User-Agent": UA})
        rows.append(f"- https://www → {r2.status_code} {r2.headers.get('Location', '')[:60]}")
        return "Переходы www ↔ без www", "\n".join(rows), []
    except Exception as e:
        ctx.err(e)
    return None


def http_cache_headers(ctx):
    try:
        r = ctx.http_get()
        hs = r.headers
        rows = []
        for k in ("Cache-Control", "Expires", "ETag", "Last-Modified", "Pragma", "Age"):
            if v := hs.get(k):
                rows.append(f"- {k}: {v}")
        if rows:
            return "Кэш-заголовки", "\n".join(rows), ["HTTP"]
    except Exception as e:
        ctx.err(e)
    return None


def http_compression(ctx):
    try:
        s = requests.Session()
        r = s.get(_url(ctx), timeout=10, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate, br"})
        enc = r.headers.get("Content-Encoding")
        if enc:
            return "Сжатие ответа", f"поддерживается: {enc}", ["HTTP"]
    except Exception as e:
        ctx.err(e)
    return None


def http_cookie_flags(ctx):
    try:
        r = ctx.http_get()
        rows = []
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                rows.append("- " + v[:140])
        if rows:
            return "Set-Cookie (атрибуты безопасности)", "\n".join(rows), ["cookie", "security"]
    except Exception as e:
        ctx.err(e)
    return None


def ip_reverse_ptr_multi(ctx):
    try:
        # эхо через запрос к нескольким IP? Возьмём первичный PTR по нашему IP
        rev = dns.reversename.from_address(ctx.ip)
        ans = dns.resolver.resolve(rev, "PTR")
        return "PTR (первичный)", ", ".join(str(x) for x in ans), ["PTR"]
    except Exception as e:
        ctx.err(e)
    return None


def asn_details_cymru(ctx):
    try:
        data = ctx.http_json(f"https://rdap.org/ip/{ctx.ip}")
        if not data:
            return None
        rows = []
        if handle := data.get("handle"):
            rows.append(f"- handle: {handle}")
        if name := data.get("name"):
            rows.append(f"- имя сети: {name}")
        for kw in ("startAddress", "endAddress", "type", "country", "status"):
            if v := data.get(kw):
                rows.append(f"- {kw}: {v if not isinstance(v, (list, tuple)) else ', '.join(v)}")
        # ASN-группа
        try:
            asn = ctx.http_json(f"https://rdap.org/autnum/{data.get('handle','').replace('AS','')}")
            if asn and asn.get("name"):
                rows.append(f"- автономная система: {asn.get('name')}")
        except Exception:
            pass
        if rows:
            return "Сеть/ASN (RDAP)", "\n".join(rows), ["ASN"]
    except Exception as e:
        ctx.err(e)
    return None


def tls_ocsp_uri(ctx):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        h = ctx.host
        c = ssl.create_default_context()
        with socket.create_connection((h, 443), timeout=10) as s:
            with c.wrap_socket(s, server_hostname=h) as t:
                der = t.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der)
        for ext in cert.extensions:
            if ext.oid._name == "authorityInformationAccess":
                aia = ext.value
                for ad in aia:
                    if ad.access_method._name == "OCSP":
                        return "OCSP responder", ad.access_location.value, ["TLS"]
    except Exception as e:
        ctx.err(e)
    return None


def email_security_sts(ctx):
    try:
        for probe in ("_smtp._tls." + ctx.domain, "smtp." + ctx.domain):
            try:
                rows = []
                try:
                    for r in dns.resolver.resolve("_mta-sts." + ctx.domain, "TXT"):
                        rows.append("MTA-STS: " + str(r)[:200])
                except Exception:
                    pass
                try:
                    raw = {str(r) for r in dns.resolver.resolve(ctx.domain, "TXT")}
                    if any("v=spf1" in x for x in raw):
                        pass
                except Exception:
                    pass
                if rows:
                    return "MTA-STS (рассылка по TLS)", "\n".join(rows), ["mail", "security"]
            except Exception:
                continue
    except Exception as e:
        ctx.err(e)
    return None


def http_powered_by(ctx):
    try:
        r = ctx.http_get()
        pb = r.headers.get("X-Powered-By")
        if pb:
            return "X-Powered-By", pb, ["fingerprint", "tech"]
    except Exception as e:
        ctx.err(e)
    return None


def http_permissions_policy(ctx):
    try:
        r = ctx.http_get()
        pp = r.headers.get("Permissions-Policy")
        if pp:
            return "Permissions-Policy", pp[:160], ["security"]
    except Exception as e:
        ctx.err(e)
    return None


def tls_issuer_chain_len(ctx):
    try:
        h = ctx.host
        c = ssl.create_default_context()
        with socket.create_connection((h, 443), timeout=10) as s:
            with c.wrap_socket(s, server_hostname=h) as t:
                chain = []
                if hasattr(t, "get_verified_chain"):
                    chain = t.get_verified_chain()
                if not chain and hasattr(t, "getpeercertchain"):
                    chain = t.getpeercertchain()
        n = len(chain or [])
        return "Цепочка сертификатов", f"{n} звеньев в цепочке доверия" if n else "данные по цепочке недоступны", ["TLS", "cert"]
    except Exception as e:
        ctx.err(e)
    return None


def http_redirect_www_bare(ctx):
    try:
        if ctx.host.startswith("www."):
            base = ctx.host[4:]
        else:
            base = None
            return None
        r = requests.get(f"http://{base}", timeout=8, allow_redirects=False, headers={"User-Agent": UA})
        if r.status_code in (301, 302):
            return "Канонический домен", f"{base} → {r.headers.get('Location','')[:60]}", []
    except Exception as e:
        ctx.err(e)
    return None


def http_security_framework_hint(ctx):
    try:
        r = ctx.http_get()
        hs = r.headers
        hints = []
        if "azure" in r.url or "azurewebsites" in r.url:
            hints.append("Azure App Service")
        if "amazonaws" in r.url or ".cdn.cloudflare" in r.url:
            hints.append("AWS/CloudFront")
        if "githubusercontent" in r.url or r.headers.get("Via"):
            v = r.headers.get("Via", "")
            if "v0." in v or "github" in v:
                hints.append("GitHub Pages?")
        if hints:
            return "Хостинг / платформа (по URL)", ", ".join(hints), ["hosting"]
    except Exception as e:
        ctx.err(e)
    return None


def ssl_redirect_check(ctx):
    try:
        r = ctx.http_get()
        if r.url.startswith("https://") and ctx.url.startswith("http://"):
            return "HTTP→HTTPS", "Есть принудительный редирект на HTTPS", ["TLS"]
        if ctx.url.startswith("https://") and r.url.startswith("https://"):
            return "HTTPS напрямую", "Отвечает по HTTPS (шифрование активно)", ["TLS"]
    except Exception as e:
        ctx.err(e)
    return None


def http_hsts_preload(ctx):
    try:
        r = ctx.http_get()
        hsts = r.headers.get("Strict-Transport-Security", "")
        if hsts:
            preload = "preload" in hsts
            sub = "includeSubDomains" in hsts
            flag = []
            if preload:
                flag.append("+ preload")
            if sub:
                flag.append("+ includeSubDomains")
            maxage = re.search(r"max-age=(\d+)", hsts)
            return "HSTS (HTTP Strict Transport)", f"max-age={maxage.group(1) if maxage else '?'}" + "".join(flag), ["security", "TLS"]
    except Exception as e:
        ctx.err(e)
    return None


def http_framework_cookie(ctx):
    try:
        r = ctx.http_get()
        hdr = r.headers.get("X-AspNetMvc-Version") or r.headers.get("X-AspNet-Version") or r.headers.get("X-Powered-By")
        if hdr:
            return "Фреймворк (заголовок платформы)", hdr, ["fingerprint", "tech"]
    except Exception as e:
        ctx.err(e)
    return None
    try:
        r = ctx.http_get()
        if r.url.startswith("https://") and ctx.url.startswith("http://"):
            return "HTTP→HTTPS", "Есть редирект на HTTPS", ["TLS"]
        if ctx.url.startswith("https://") and r.url.startswith("https://"):
            return "HTTPS напрямую", "Отвечает по HTTPS", ["TLS"]
    except Exception as e:
        ctx.err(e)
    return None