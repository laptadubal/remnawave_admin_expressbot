# Remnawave Admin — админка + eXpress-бот (два в одном)

Веб-админка для панели **Remnawave** с собственной авторизацией, ролями,
полным аудит-логом и встроенным ботом **eXpress Messenger (express.ms)**.
Бот — часть функционала админки: он читает ту же базу/подключение к панели,
управляется отдельной ролью `bot_admin` прямо из раздела «Бот».

Никаких изменений на серверах не требует — запускается отдельно через
`docker compose`.

## Возможности

- **Собственная авторизация**: session-куки (httpOnly, SameSite=Lax),
  пароли — Argon2id. Дефолтный админ `admin` создаётся при первом запуске
  (пароль из `ADMIN_PASSWORD`, либо сгенерированный — печатается в logs).
- **Роли**:
  | Роль | Права |
  |------|-------|
  | `admin` | всё, включая раздел «Доступ» (свои пользователи) и «Настройки» |
  | `operator` | пользователи и профили Remnawave, узлы, генерация ключей |
  | `bot_admin` | управление eXpress-ботом (раздел «Бот»), ничего из панели |
  | `viewer` | только просмотр |
- **Менеджмент Remnawave**: узлы (ноды), пользователи, профили
  (включая создание с выбором трафика/срока), генерация ключей VLESS/VMess,
  экспорт CSV, сброс паролей/лимитов, включение/отключение/удаление.
  Подключение — API-токеном панели или логин/паролем (панель сама
  залогинится и сессия кешируется).
- **Аудит-лог**: каждое действие (вход в систему, изменение пользователя,
  действия над панелью, сохранение конфига бота) пишется в SQLite:
  кто, что, с какого IP, исходный результат. Раздел «Журнал» с фильтрами
  и CSV-экспортом.
- **eXpress-бот** (pybotx): команды `/help`, `/status`, `/nodes`,
  `/traffic`, `/user <имя>`, `/users`; whitelist по huid (кто может
  пользоваться ботом). Конфигурация (CTS URL, bot_id, секрет, список
  huid) вводится в веб-интерфейсе ролью `bot_admin`/`admin`,
  секрет шифруется `Fernet` на `SECRET_KEY`.
- **Дизайн**: тёмная тема, sidebar, htmx-фрагменты без перезагрузки
  страницы, flash-сообщения.

## Быстрый старт (Docker)

```bash
cp .env.example .env
# заполнить .env: SECRET_KEY, ADMIN_PASSWORD, REMNAWAVE_BASE_URL + токен
docker compose up -d --build
# http://<host>:8090  (порт — ADMIN_PORT)
```

`Makefile`: `make build|up|down|restart|logs|shell|smoke`.

## Конфигурация (`.env`)

| Переменная | Что делает |
|---|---|
| `ADMIN_PORT` | Порт на хосте (по умолчанию 8090) |
| `SECRET_KEY` | Случайный hex; `openssl rand -hex 32`. На нём шифруются секреты бота |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Первый администратор (создаётся один раз) |
| `SESSION_HOURS` | Время жизни сессии |
| `REMNAWAVE_BASE_URL` | URL панели, например `https://panel.example.com` |
| `REMNAWAVE_API_TOKEN` | **Рекомендуется**: API-токен панели (Settings → API Tokens) |
| `REMNAWAVE_USERNAME` / `REMNAWAVE_PASSWORD` | Альтернатива: логин/пароль панели |
| `LOG_LEVEL` | Логирование |

> Токен приоритетнее логина. Логин/пароль — это **учётная запись самой
> панели**, не SSH-администратор сервера.

### Подключение eXpress-бота

1. Раздел **«Бот»** (роль `bot_admin` или `admin`).
2. Заполнить: CTS-адрес (обычно `https://cts.express.ms`), **Bot ID** и
   **Secret** из настроек бота в express, список **huid** пользователей,
   которым разрешён бот (whitelist; пустой = доступ только admin'у панели).
3. Включить. Бот регистрирует webhook у CTS (пути `/botx/...`
   пробрасываются тем же контейнером) и начинает отвечать.

Команды бота работают только для huid из whitelist. Все команды бота
также пишутся в общий аудит-лог.

## Подключение к панели Remnawave

Проект обращается к REST API панели (`/api/*`) напрямую из контейнера.
Ничего на серверах панели менять не нужно. Если панель за TLS-сертификатом
без CAA, укажите корректный `REMNAWAVE_BASE_URL` — контейнер использует
стандартный системный бандл сертификатов.

## Структура

```
app/
  main.py            # FastAPI-приложение, healthz
  config.py          # чтение .env
  security.py        # Argon2, сессии, роли
  audit.py           # запись/чтение audit-лога
  db.py              # SQLAlchemy (SQLite), схемы
  flash.py           # flash-сообщения (httpOnly cookie)
  remna/
    client.py        # клиент REST API Remnawave
  botx/
    commands.py      # команды eXpress-бота
    provider.py      # подаёт настройки бота в pybotx из БД
    crypto.py        # Fernet-шифрование секрета бота
  routers/
    auth_page.py     # /login /logout
    web.py           # страницы (htmx)
    api.py           # REST /api/* (фрагменты, действия, аудит)
  static/            # CSS/JS, htmx
  templates/         # Jinja2
```

## Разработка без Docker

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
ADMIN_PASSWORD=Test12345 SECRET_KEY=dev $(...)/uvicorn app.main:app --reload
```

## Безопасность

- Пароли в БД — Argon2id (не reverifiable).
- Секрет eXpress-бота хранится зашифрованным (Fernet) и не виден в логах.
- Каждая сессия и действие — в аудит-логе; журнал доступен только `admin`.
- Контейнер работает не-привилегированным пользователем (uid 10001).
- `data/` — единственный volume (SQLite + состояние); не коммитится в git.

## License

MIT.
