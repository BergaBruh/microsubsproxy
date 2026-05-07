# microsubsproxy

HTTP-сервис на Go, который агрегирует VPN-подписки с нескольких панелей 3x-ui в одну сводную ссылку. Клиент (V2RayNG, Hiddify, v2rayN и т.п.) подписывается на единый URL, а сервис под капотом параллельно опрашивает все апстримы, фильтрует строки по разрешённым схемам и отдаёт объединённый base64-список.

## Зачем это нужно

Если у вас несколько серверов на 3x-ui, каждый из них выдаёт свою подписку. Чтобы клиенту не приходилось добавлять их по одной и не терять серверы при ротации, microsubsproxy собирает всё в один эндпоинт. Добавление нового узла = одна строка в конфиге и `systemctl restart`.

## Как это работает

1. Клиент делает `GET /<route_prefix>/<subId>`.
2. Сервис валидирует `subId` (только `[A-Za-z0-9]`, длина ≤ `max_sub_id_len`).
3. Параллельно опрашивает все шаблоны из `upstreams`, подставляя `subId` в `%s`.
4. Каждый ответ при необходимости декодируется из base64, разбивается по строкам и фильтруется по `valid_prefixes` (`vless://`, `vmess://`, `trojan://`, `ss://`).
5. Строки склеиваются в порядке апстримов, кодируются в base64 и возвращаются клиенту с заголовками `Subscription-Userinfo` и `Profile-Update-Interval: 24`.

Если хотя бы один апстрим вернул валидные строки — ответ 200. Если все молчат — 502.

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

# Проверка
curl http://127.0.0.1:8090/session/<subId>
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
├── main.go                  — весь код сервиса в одном файле
├── config.yaml.example      — пример конфига
├── microsubsproxy.service   — systemd unit
├── nginx.conf.example       — пример nginx site config (TLS terminate + reverse proxy)
├── scripts/                 — postinstall / preremove hooks для пакетов
├── go.mod / go.sum
└── README.md
```
