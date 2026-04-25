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

## Добавление нового сервера или протокола

- **Новая панель 3x-ui** → добавить шаблон URL в `upstreams:` (с `%s` вместо `subId`) и `systemctl restart microsubsproxy`.
- **Новый протокол** → добавить полный префикс (с `://`) в `valid_prefixes:` и рестарт.

## Структура репозитория

```text
microsubsproxy/
├── main.go                  — весь код сервиса в одном файле
├── config.yaml              — конфиг по умолчанию
├── microsubsproxy.service   — systemd unit
├── go.mod / go.sum
└── README.md
```
