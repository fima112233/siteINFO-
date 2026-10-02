"""Оркестратор прогона: строит очередь проверок, генерирует события для чат-интерфейса
и собирает итоговый отчёт. Проверки выполняются в отдельных потоках и стримятся в UI.
"""
import threading
from threading import Thread
from queue import Queue
from datetime import datetime

from recon import checks
from recon.context import Context


class Reconsuite:
    NAME = "siteINFO+"
    VERSION = "1.0.0"

    # СКОЛЬКО ждём одну проверку. Если источник «пробивает» дольше —
    # метод умирает по таймауту и НЕ блокирует прогон.
    CHECK_TIMEOUT = 50.0  # секунд

    # проверки, допустимые без резолва IP (когда DNS не отвечает — всё равно покажем что можем)
    NO_IP_OK = {"whois_main", "whois_registrar", "whois_server_info", "dns_ns", "dns_mx", "dns_txt",
                "dns_soa", "dns_dmarc", "dns_spf", "dns_dkim", "dns_cname", "dns_any_wildcard",
                "dns_find_subdomains", "http_*", "tls_*", "email_domain_probe", "ssl_redirect_check",
                "asn_lookup", "ip_country_geo", "whois_ip_ranges"}

    def __init__(self, max_workers: int = 10, timeout: float = 60.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self._stop_evt = None

    # -- события -------------------------------------------------------------
    def _emit(self, evt):
        q = getattr(self, "_events", None)
        # если передан внешний канал (job.q), пишем туда
        ext = getattr(self, "_out_events", None)
        q = ext if ext is not None else q
        if q is not None:
            try:
                q.put_nowait(evt)
            except Exception:
                pass

    def _stage(self, text):
        self._emit({"kind": "stage", "text": text, "ts": datetime.utcnow().isoformat() + "Z"})

    def _ok(self, name, detail):
        self._emit({"kind": "ok", "name": name, "detail": detail,
                    "ts": datetime.utcnow().isoformat() + "Z"})

    def _err(self, name, msg="ошибочные данные отсеяны (в отчёт не попали)"):
        self._emit({"kind": "err", "name": name, "msg": msg,
                    "ts": datetime.utcnow().isoformat() + "Z"})

    def _block(self, name, detail):
        self._emit({"kind": "block", "name": name, "detail": detail,
                    "ts": datetime.utcnow().isoformat() + "Z"})

    def _final(self, text):
        self._emit({"kind": "final", "text": text,
                    "ts": datetime.utcnow().isoformat() + "Z"})

    def _done(self):
        self._emit({"kind": "done", "ts": datetime.utcnow().isoformat() + "Z"})

    # -- планировщик ------------------------------------------------------
    def _plan(self):
        """Возвращает список (name, func) проверок (все ~66)."""
        plan = []
        for n in dir(checks):
            if n.startswith("_"):
                continue
            obj = getattr(checks, n)
            if callable(obj) and getattr(obj, "__module__", None) == "recon.checks":
                plan.append((n, obj))
        # стабильный порядок: группируем по префиксу
        order = {"dns_": 1, "whois_": 2, "asn_": 3, "ip_": 4, "http_": 5, "tls_": 6,
                 "port_": 7, "ssl_": 8, "email_": 8}
        plan.sort(key=lambda it: (order.get(it[0].split("_")[0] + "_", 9), it[0]))
        return plan

    # -- исполнение одной проверки с таймаутом -----------------------------
    def _exec_with_timeout(self, fn, ctx):
        """Выполняет проверку fn(ctx) в отдельном потоке.
        Если она не уложилась в CHECK_TIMEOUT секунд — таймаут, результат None.
        Если запрошена отмена (cancel) — возвращаемся почти сразу.
        """
        box = {}

        def target():
            try:
                box["res"] = fn(ctx)
            except Exception as e:
                box["exc"] = e

        # если отмена запрошена ещё до старта — не запускаем
        if self._stop_evt is not None and self._stop_evt.is_set():
            return None, TimeoutError("отменено")

        t = Thread(target=target, daemon=True)
        t.start()
        # ждём либо завершения, либо таймаута, либо отмены (маленькими шагами)
        waited = 0.0
        STEP = 0.25
        while waited < self.CHECK_TIMEOUT:
            t.join(timeout=STEP)
            waited += STEP
            if not t.is_alive():
                break
            if self._stop_evt is not None and self._stop_evt.is_set():
                return None, TimeoutError("отменено пользователем")
        if t.is_alive():
            return None, TimeoutError(f"таймаут > {int(self.CHECK_TIMEOUT)}с")
        if "exc" in box:
            return None, box["exc"]
        return box.get("res"), None

    # -- запуск ------------------------------------------------------------
    def run(self, raw_url: str, job_id: str = "job", out_events=None, cancel_event=None):
        ctx = Context(raw_url)
        self._out_events = out_events
        self._stop_evt = cancel_event
        self._stage(f"[{job_id}] Домен получен: {ctx.host} | DNS-резолв: {ctx._ip_err_text}")
        if ctx.ip:
            self._block("Целевой IP", ctx.ip)

        plan = self._plan()
        self._stage(f"[{job_id}] Запущен прогон siteINFO+ ({len(plan)} проверок по источникам, "
                    f"лимит на проверку {int(self.CHECK_TIMEOUT)}с)")

        results = {}
        idx = 0
        threads = []

        def _cancelled():
            return cancel_event is not None and cancel_event.is_set()

        def worker():
            nonlocal idx
            while True:
                if _cancelled():
                    return
                with threading.Lock():
                    if ctx._stopped or idx >= len(plan):
                        return
                    n, f = plan[idx]
                    idx += 1
                self._stage(f"[{job_id}] → {n}")
                res, err = self._exec_with_timeout(f, ctx)
                if err is not None:
                    if _cancelled():
                        return
                    if isinstance(err, TimeoutError):
                        self._err(n, f"таймаут > {int(self.CHECK_TIMEOUT)}с — метод остановлен")
                    else:
                        self._err(n)
                    continue
                if res is None:
                    self._err(n)
                    continue
                try:
                    name, detail, kw = res
                    results[n] = detail
                    self._ok(name, detail)
                except Exception as e:
                    self._err(n, str(e)[:80])

        ctx._stopped = False
        for _ in range(min(self.max_workers, len(plan))):
            t = Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Ждём рабочие потоки, прерываясь по отмене. Воркеры сами быстро
        # выходят, когда _exec_with_timeout замечает cancel.
        for t in threads:
            while t.is_alive() and not _cancelled():
                t.join(timeout=0.25)

        # снимаем рабочие потоки с цикла, чтобы освободить лок
        ctx._stopped = True

        if _cancelled():
            self._stage(f"[{job_id}] Прогон остановлен пользователем (частичные результаты)")
            self._done()
            return ctx, results, ""

        self._stage(f"[{job_id}] Сбор завершён, формирую итоговый отчёт…")
        try:
            report = self._build_report(ctx, results)
        except Exception:
            report = "ИТОГОВЫЙ ОТЧЁТ (частичный)\nПроверок успешно: %d" % len(results)
        self._final(report)
        self._done()
        return ctx, results, report

    # -- отчёт -------------------------------------------------------------
    def _build_report(self, ctx, results):
        lines = []
        lines.append(f"═" * 46)
        lines.append(f"  ИТОГОВЫЙ ОТЧЁТ  {self.NAME} v{self.VERSION}")
        lines.append(f"  Цель: {ctx.url}")
        lines.append(f"  Хост: {ctx.host} | Домен: {ctx.domain} | IP: {ctx.ip or '—'}")
        lines.append(f"  Время: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
        lines.append(f"═" * 46)

        # группируем результаты по категории
        groups = {}
        for name, detail in results.items():
            cat = name.split("_")[0]
            groups.setdefault(cat, []).append((name, detail))

        cat_title = {"dns": "DNS / записи", "whois": "WHOIS / регистрация", "asn": "ASN",
                     "ip": "IP / гео", "http": "HTTP / технологи замет", "tls": "TLS / сертификаты",
                     "port": "Порты / службы", "ssl": "SSL / переходы", "email": "Почта"}
        for cat in ("dns", "whois", "asn", "ip", "http", "tls", "port", "ssl", "email"):
            if cat in groups:
                lines.append(f"\n◆ {cat_title.get(cat, cat.upper())}")
                for n, d in sorted(groups[cat]):
                    lines.append(f"  ▪ {n}:")
                    for ln in str(d).splitlines():
                        lines.append(f"      {ln}")

        fail_count = sum(v for k, v in ctx._errors.items())
        lines.append(f"\n{'─' * 46}")
        lines.append(f"Проверок успешно: {len(results)} | тихо отсеяно ошибок: {fail_count}")
        lines.append(f"GET /api/report/{ctx.host} — полный JSON этого прогона")
        return "\n".join(lines)