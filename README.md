# CPM Proxy Server

Прокси-сервер для объединения запросов к cpm-serv и cpm-exam-main.
Реализует единую точку авторизации и обеспечивает работу cookies между серверами.

## Установка

```bash
pip install -r requirements.txt
```

## Настройка

Создайте файл `.env` или установите переменные окружения:

```bash
# URL основного сервера (cpm-serv)
export MAIN_SERVER_URL="http://192.168.1.11:80"

# URL экзам сервера (cpm-exam-main)
export EXAM_SERVER_URL="http://192.168.1.11:81"

# Секретный ключ JWT (должен совпадать с ключами на обоих серверах!)
export JWT_SECRET_KEY="ваш-секретный-ключ"

# Домен для cookie (для поддоменов, необязательно)
export COOKIE_DOMAIN=".cpm-lms.ru"

# Порт прокси-сервера
export PROXY_PORT=82

# Окружение
export FLASK_ENV="development"  # или "production"
```

## Запуск

```bash
python main.py
```

Сервер запустится на порту 82 (или указанном в PROXY_PORT).

## Архитектура

```
Клиент (React)
    ↓
Прокси-сервер (порт 82)
    ├── /api/* → cpm-serv (порт 80)
    └── /directions, /test*, /get-* → cpm-exam-main (порт 81)
```

## Роутинг

### Основной сервер (cpm-serv):

- `/api/*` → перенаправляется на `MAIN_SERVER_URL/api/*`
- `/add-learned-question`, `/get-themes`, `/all-cards-by-theme/*` и т.д. → основной сервер

### Экзам сервер (cpm-exam-main):

- `/directions` → экзам сервер
- `/tests/*` → экзам сервер
- `/test/*` → экзам сервер
- `/create-test` → экзам сервер
- `/get-all-exams`, `/get-exam-session` и т.д. → экзам сервер

### Авторизация:

- `/api/auth` → обрабатывается прокси, устанавливает cookie
- `/api/logout` → обрабатывается прокси, удаляет cookie
- `/api/aun` → возвращает данные из токена прокси

## Преимущества

1. ✅ Единая точка авторизации
2. ✅ Cookies работают автоматически (один домен)
3. ✅ Не нужно настраивать CORS для поддоменов
4. ✅ Проще управление SSL сертификатами (один домен)
5. ✅ Логирование всех запросов в одном месте

## Тестирование

После запуска прокси-сервера:

```bash
# Авторизация
curl -X POST http://localhost:82/api/auth \
  -H "Content-Type: application/json" \
  -d '{"login":"nickly24","password":"77tanufe"}' \
  -c cookies.txt

# Запрос к основному серверу
curl http://localhost:82/api/get-students -b cookies.txt

# Запрос к экзам серверу
curl http://localhost:82/get-all-exams -b cookies.txt
```
# cpm-proxy
