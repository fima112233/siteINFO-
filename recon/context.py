"""Общий контекст прогона: разбор URL, сетевые хелперы, кэш и маскирование ошибок.

Ошибочные данные не должны попадать в итоговый отчёт — поэтому до 3 одинаковых
ошибок тихо глушатся, дальше показывается обобщённое сообщение без перс. данных.
"""
import re
import json
import socket
import threading
import urllib.parse
from datetime import datetime

import requests


# Таймауты DNS-резолва и сетевых операций по умолчанию (сек).
IP_RESOLVE_TIMEOUT = 8.0
SOCKET_TIMEOUT = 8.0


def _resolve_ip_with_timeout(host: str, period: float = IP_RESOLVE_TIMEOUT):
    """socket.gethostbyname с гарантированным таймаутом (в отдельном потоке).

    gethostbyname синхронный и не поддерживает таймаут, поэтому зовём его
    в потоке и ждём не дольше `period`. Если не успел — возвращаем None.
    """
    box = {}

    def target():
        try:
            box["ip"] = socket.gethostbyname(host)
        except Exception as e:
            box["exc"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=period)
    if t.is_alive():
        return None, TimeoutError(f"DNS-резолв {host} по таймауту > {int(period)}с")
    if "exc" in box:
        return None, box["exc"]
    return box.get("ip"), None


class Context:
    def __init__(self, raw_url: str):
        raw_url = raw_url.strip()
        if not re.match(r"^https?://", raw_url, re.I):
            raw_url = "http://" + raw_url
        self.raw = raw_url
        self.url = raw_url
        p = urllib.parse.urlsplit(raw_url)
        self.scheme = p.scheme
        self.host = p.hostname or ""
        self.port = p.port
        self.path = p.path or ""
        self.qs = p.query
        # домен (без поддоменов)
        parts = self.host.split(".")
        self.domain = ".".join(parts[-2:]) if len(parts) > 2 else self.host
        self._ip = None
        self._ip_error = None
        self._http_cache = {}
        self._json_cache = {}
        self._errors = {}
        self.started = datetime.utcnow()
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"})
        self._ip, self._ip_error = _resolve_ip_with_timeout(self.host)

    @property
    def ip(self) -> str:
        return self._ip

    def err(self, exc: Exception):
        """Тихое добавление ошибки в буфер, чтобы не уронить прогон."""
        key = type(exc).__name__
        self._errors[key] = self._errors.get(key, 0) + 1

    @property
    def _ip_err_text(self) -> str:
        if self._ip:
            return self._ip
        if self._ip_error:
            return self._ip_error
        return "—"

    def http_get(self, path="/", redirects=True, headers=None, timeout=10):
        key = (path, redirects)
        if key in self._http_cache:
            return self._http_cache[key]
        h = dict(self._session.headers)
        if headers:
            h.update(headers)
        url = self.url
        if path != "/":
            base = self.url.rstrip("/")
            url = base + (path if str(path).startswith("/") else "/" + str(path))
        r = self._session.get(url, timeout=timeout, allow_redirects=redirects, headers=h,
                              verify=True)
        self._http_cache[key] = r
        return r

    def http_json(self, url, timeout=10):
        if url in self._json_cache:
            return self._json_cache[url]
        try:
            r = self._session.get(url, timeout=timeout, headers={"User-Agent": "curl/8"})
            r.raise_for_status()
            data = r.json()
            self._json_cache[url] = data
            return data
        except Exception:
            return None

    def summary(self):
        blocks = []
        if self._ip:
            blocks.append(f"   IP: {self._ip}, домен: {self.domain}, хост: {self.host}")
        errs = {k: v for k, v in self._errors.items() if v > 2}
        if errs:
            blocks.append("   (ошибки источников тихо отсеяны: " + ", ".join(
                f"{k}×{v}" for k, v in errs.items()) + ")")
        return "\n".join(blocks)