# siteINFO+
Рекон-тулза на Flask с чат-интерфейсом. Вводишь URL — и она пробивает сайт в **реальном времени** по ~66 источникам/проверкам, выводя процесс прямо в чат. Ошибочные данные в итоговый отчёт **не попадают**.

## Возможности
- **Мультипробив**: в одном чате можно запустить хоть сто пробивов — каждый идёт своим SSE-потоком одновременно.
- **Кнопка «Пробить → Стоп»**: во время прогона превращается в «Стоп» и отменяет активные прогоны.
- **Сообщения видны**: твой URL показывается синим «баблсправа», процесс свёрнут в блок «думаю».
- **История**: все чаты и их сообщения сохранены в SQLite и загружаются при входе (сайдбар).
- **Логин/регистрация**: аккаунты, сессии, пароли хэшируются (вход обязателен).
- **Админка** (`/admin`): статистика, список пользователей (блокировка/назначение админа/удаление), просмотр всех чатов и результатов пробивов.

## Запуск (dev)
```bash
pip install -r requirements.txt
python app.py
```
Открыть http://127.0.0.1:5005

## Запуск (production)
1. Скопируй `.env.example` в `.env` и задай `SECRET_KEY` (длинная случайная строка) и `ADMIN_USERS`.
   - генерация ключа: `python -c "import secrets; print(secrets.token_hex(32))"`
2. Запуск через **waitress**:
   - Windows: `run_prod.bat`
   - или вручную: `$env:PROD=1; $env:WSGI=waitress; $env:HOST=0.0.0.0; python app.py`
   - или `python -m waitress --host=0.0.0.0 --port=5005 --threads=16 app:app`

## Администраторы
- Пользователи из `ADMIN_USERS` (через запятую) автоматически получают роль админ при старте.
- Админ-панель: **http://host:5005/admin**
- Админ может: смотреть статистику, блокировать/удалять пользователей, назначать админов, открывать любой чат и видеть результаты пробивов.

## Что пробивает (~66 проверок)
- **DNS**: A, AAAA, NS, MX, TXT, SPF, DMARC, DKIM, CAA, HTTPS/SVCB, SOA, PTR, CNAME, wildcard, поиск поддоменов
- **WHOIS**: регистрант, регистратор, даты, статусы, nameservers, сырой блок, владелец IP-диапазонов
- **ASN / гео**: Team Cymru, RDAP, геолокация по IP
- **HTTP**: status, методы, заголовки, security-заголовки, cookies/флаги, redirect-цепи, www, title/meta, generator, favicon, robots/sitemap/security.txt, WAF/CDN, ошибки verbose, открытые файлы, пути, кэш, сжатие, CMS
- **TLS**: сертификат, протоколы, OCSP, цепочка, HSTS
- **Порты**: топ-24 открытых TCP, баннеры

## Технологии
- Flask + SSE + потоки; SQLite (users/conversations/messages); python-whois, dnspython, ssl/socket, RDAP/ipinfo/ipapi.
- Таймаут на проверку 50с; отмена прогонов; waitress для продакшна.

## API
- Auth: `POST /api/register|login|logout`, `GET /api/me`
- Чаты: `POST /api/conversation/new`, `GET/DELETE /api/conversation/<id>[/messages]`
- Прогон: `POST /api/scan`, `POST /api/scan/<job>/cancel`, `GET /api/stream/<job>`
- Админ: `GET /api/admin/stats|users|conversations`, `PATCH/DELETE /api/admin/users/<id>`, `GET/DELETE /api/admin/conversations/<id>`

## Тесты
```bash
python test_app.py
```

## Структура
```
app.py              — Flask, SSE, REST, авторизация, SQLite, админка
recon/engine.py     — оркестратор, очередь этапов, таймауты, отмены
recon/checks.py     — ~66 проверок по источникам
recon/context.py    — разбор URL, IP, сетевые хелперы, маскирование ошибок
templates/          — index.html, auth.html, admin.html
static/             — app.js, auth.js, admin.js, style.css
siteinfo.db         — SQLite (создаётся автоматически)
.env.example        — шаблон конфигурации
run_prod.bat        — запуск в production на Windows
```