# microsubsproxy

HTTP-сервис на Go, который агрегирует VPN-подписки с нескольких панелей 3x-ui в одну сводную ссылку. Клиент (V2RayNG, Hiddify, v2rayN, Clash Verge Rev, Mihomo Party, FlClash и т.п.) подписывается на единый URL, а сервис отдаёт результат либо в V2Ray-формате (base64-список), либо в Clash/Mihomo YAML — в зависимости от `?type=` или `User-Agent`.

## Зачем это нужно

Если у вас несколько серверов на 3x-ui, каждый из них выдаёт свою подписку. Чтобы клиенту не приходилось добавлять их по одной и не терять серверы при ротации, microsubsproxy собирает всё в один эндпоинт. Добавление нового узла = одна строка в конфиге и `systemctl restart`.

## Как это работает

1. Клиент делает `GET /<route_prefix>/<subId>[?type=clash|v2ray]`.
2. Сервис валидирует `subId` (только `[A-Za-z0-9]`, длина ≤ `max_sub_id_len`).
3. Параллельно опрашивает все шаблоны из `upstreams`, подставляя `subId` в `%s`.
4. Каждый ответ при необходимости декодируется из base64, разбивается по строкам и фильтруется по `valid_prefixes` (`vless://`, `vmess://`, `trojan://`, `ss://`).
5. К результату дописываются записи из `static_inject` (если есть и подходят по `sub_ids`).
6. Формат выдачи выбирается по `?type=` (приоритет 1) или `User-Agent` (приоритет 2):
   - **v2ray** (по умолчанию): base64-список URI, `Content-Type: text/plain`. Совместимо с V2RayNG, v2rayN, Hiddify, NekoBox, и т.д.
   - **clash**: YAML с секциями `proxies`, `proxy-groups` (`select PROXY`), `rules` (`MATCH,PROXY`), `Content-Type: text/yaml`. Совместимо с Mihomo (Clash Meta), Clash Verge Rev, Mihomo Party, FlClash, Stash. Оригинальный Clash не поддерживается (он не понимает VLESS).
7. Если хотя бы один апстрим вернул валидные строки — ответ 200. Если все молчат — 502.

### Выбор формата

| Способ | Приоритет | Пример |
|--------|-----------|--------|
| `?type=clash` / `?type=v2ray` | 1 (явный) | `GET /sub/abc?type=clash` |
| `User-Agent` содержит `clash\|mihomo\|verge\|stash\|flclash\|clashx` | 2 (авто) | `curl -A "mihomo/1.18" ...` |
| Иначе | — | v2ray base64 |

URI, которые не парсятся в Proxy-модель, попадают в v2ray-выдачу как есть (pass-through), но **отбрасываются** в clash-выдаче.

Поддерживаются:

| Протокол | Префиксы | Особенности |
|----------|----------|-------------|
| VLESS | `vless://` | Reality, xtls-rprx-vision, tcp/ws/grpc/xhttp/httpupgrade |
| VMess | `vmess://` | base64(JSON), tcp/ws/grpc/h2, alias `scy`/`security` |
| Trojan | `trojan://` | tcp/ws/grpc, allowInsecure |
| Shadowsocks | `ss://` | SIP002 (base64 и plaintext userinfo) + legacy whole-body base64 |
| Hysteria2 | `hysteria2://`, `hy2://` | Salamander obfs, QUIC+TLS implicit |
| TUIC v5 | `tuic://` | uuid:password, congestion-control, udp-relay-mode |
| WireGuard | `wireguard://`, `wg://` | private/public keys, allowed-ips, Cloudflare WARP `reserved` |
| ShadowsocksR | `ssr://` | Legacy single-blob base64, protocol+obfs params |

Hysteria1 и UDP-only протоколы вне списка — не поддерживаются.

Для **SS-плагинов** (SIP003) парсится `?plugin=...` строка из SIP002 URI и попадает в clash YAML как `plugin:` + `plugin-opts:`. Поддерживаются:

| Плагин | Алиасы | YAML вывод |
|--------|--------|------------|
| `obfs` | `obfs-local`, `simple-obfs` | `plugin: obfs`, `plugin-opts: {mode, host}` |
| `v2ray-plugin` | — | `plugin: v2ray-plugin`, `plugin-opts: {mode, host, path, tls, mux, skip-cert-verify}` |
| `shadow-tls` | — | `plugin: shadow-tls`, `plugin-opts: {host, password, version}` |

## Расширение Clash-вывода (dns, tun, rule-providers, ...)

По умолчанию clash-выдача содержит только `proxies`, дефолтную `proxy-groups: [PROXY select]` и `rules: [MATCH,PROXY]`. Для production-сетапов этого мало.

Параметр `clash_extra` в [config.yaml.example](config.yaml.example) принимает путь к base-YAML, который мерджится в каждый clash-ответ. Семантика:

- `proxies` — **всегда** генерируется нами (если в base есть этот ключ, сервис откажется стартовать).
- Все остальные ключи (`dns`, `tun`, `rule-providers`, `rules`, `proxy-groups`, и т.д.) — из base, без изменений.
- Если base не содержит `proxy-groups`/`rules`, добавляются дефолты.

В пользовательской `proxy-group` для ссылки на наши прокси используй **`include-all-proxies: true`** — это фича Mihomo, имена прокси перечислять не нужно (они генерируются динамически).

Base-YAML читается **один раз при старте** — изменения требуют рестарта.

## Безопасность

- `subId` считается секретом и **не пишется в логи** - логируется только `RemoteAddr`.
- Сервис слушает на `127.0.0.1` - рассчитан на работу за реверс-прокси (nginx/caddy) с TLS.
- systemd-юнит запускается со строгим хардингом: `ProtectSystem=strict`, `MemoryDenyWriteExecute`, фильтр syscalls `@system-service` минус `@privileged @resources`.

## Конфигурация

Все настройки — в [config.yaml.example](config.yaml.example):

| Поле | Назначение |
| --- | --- |
| `listen` | Адрес и порт прослушивания (`host:port`) |
| `route_prefix` | Префикс маршрута без слешей; запрос идёт на `/<route_prefix>/<subId>` |
| `max_sub_id_len` | Максимальная длина `subId` (защита от мусорных запросов) |
| `upstream_timeout` | Таймаут на каждый апстрим в формате `time.ParseDuration` (`5s`, `500ms`, `1m`) |
| `valid_prefixes` | Список разрешённых схем подписочных строк |
| `upstreams` | Шаблоны URL панелей 3x-ui; должны содержать `%s` для подстановки `subId` |
| `static_inject` | Опционально. Список статичных конфигов (`{url, name, sub_ids}`), которые приклеиваются к ответу подписки. Полезно для inbound'ов вне 3x-ui (например, вручную поднятый xray на другой ноде). Если `sub_ids` пуст — попадает всем; иначе только перечисленным `subId`. |
| `clash_extra` | Опционально. Путь к base-YAML для clash-формата (dns, tun, rule-providers, custom proxy-groups). См. раздел «Расширение Clash-вывода». |

Переменные окружения:

- `CONFIG` - путь к конфигу (по умолчанию `./config.yaml`).
- `LISTEN` - оверрайд `listen` для разовых запусков.

Конфиг читается **один раз при старте** - изменения требуют рестарта процесса.

## Сборка и запуск

```bash
# Сборка
go build -o microsubsproxy .

# Локальный запуск с дефолтным конфигом
go run .

# Альтернативный конфиг и порт
CONFIG=/etc/microsubsproxy/config.yaml LISTEN=0.0.0.0:9000 go run .

# Проверка (v2ray по умолчанию)
curl http://127.0.0.1:8090/session/<subId>

# Clash/Mihomo через query param
curl 'http://127.0.0.1:8090/session/<subId>?type=clash'

# Clash через User-Agent (имитация Mihomo)
curl -A 'mihomo/1.18' http://127.0.0.1:8090/session/<subId>
```

Зависимости: Go 1.26+, `gopkg.in/yaml.v3`.

## Деплой

Юнит [microsubsproxy.service](microsubsproxy.service) ожидает бинарник по пути `/usr/local/bin/microsubsproxy` и конфиг по `/etc/microsubsproxy/config.yaml` (FHS-стиль: бинарник в `PATH`, конфиг отдельно от исполняемого файла).

```bash
sudo install -m 755 microsubsproxy /usr/local/bin/
sudo install -d /etc/microsubsproxy
sudo install -m 644 config.yaml.example /etc/microsubsproxy/config.yaml
sudo install -m 644 microsubsproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now microsubsproxy
```

Логи:

```bash
journalctl -u microsubsproxy -f
```

### nginx (HTTPS terminate + reverse proxy)

Сервис слушает на `127.0.0.1` и не имеет своего TLS - публично его не выставлять. Перед ним должен стоять реверс-прокси с TLS. Готовый пример - [nginx.conf.example](nginx.conf.example):

```bash
# 1) Получить сертификат (например, certbot)
sudo certbot certonly --webroot -w /var/www/html -d your.domain.example \
    -m admin@your.domain.example --agree-tos --non-interactive

# 2) Установить site config
sudo install -m 644 nginx.conf.example /etc/nginx/sites-available/microsubsproxy
sudo ln -s /etc/nginx/sites-available/microsubsproxy /etc/nginx/sites-enabled/
# Заменить your.domain.example и route_prefix `session` на свои значения
sudo nano /etc/nginx/sites-available/microsubsproxy
sudo nginx -t && sudo systemctl reload nginx
```

В пример встроены: HTTP→HTTPS redirect + ACME http-01 challenge на :80; HSTS / no-cache / no-server-tokens; regex-валидация subId на nginx-уровне (`[A-Za-z0-9]{1,64}`); опциональный cover-landing.

Caddy / Cloudflare-fronted деплой - поддерживается симметрично (TLS терминируется снаружи, прокси на `http://127.0.0.1:8090`); специального config'а в репо не нужно.

## Добавление нового сервера или протокола

- **Новая панель 3x-ui** → добавить шаблон URL в `upstreams:` (с `%s` вместо `subId`) и `systemctl restart microsubsproxy`.
- **Новый протокол** → добавить полный префикс (с `://`) в `valid_prefixes:` и рестарт.
- **Inbound вне 3x-ui (ручной xray, кастомный мост)** → добавить запись в `static_inject:` с готовым `vless://`/`vmess://`/etc URL и рестарт. По умолчанию инжектится всем; для адресной выдачи указать `sub_ids: [...]`.

## Структура репозитория

```text
microsubsproxy/
├── main.go                  — HTTP-слой, загрузка конфига, роутинг
├── internal/
│   ├── fetch/               — параллельный опрос апстримов и фильтрация по схемам
│   ├── proxy/               — общий тип Proxy и парсеры vless/vmess/trojan/ss
│   └── render/              — рендеринг в v2ray (base64) и Clash/Mihomo YAML
├── config.yaml.example      — пример конфига
├── microsubsproxy.service   — systemd unit
├── nginx.conf.example       — пример nginx site config (TLS terminate + reverse proxy)
├── scripts/                 — postinstall / preremove hooks для пакетов
├── go.mod / go.sum
└── README.md
```
