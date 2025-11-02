"""
Конфигурация прокси-сервера
"""
import os

# URL основного сервера (cpm-serv)
MAIN_SERVER_URL = os.environ.get('MAIN_SERVER_URL', 'http://192.168.1.11:80')

# URL экзам сервера (cpm-exam-main)
EXAM_SERVER_URL = os.environ.get('EXAM_SERVER_URL', 'http://192.168.1.11:81')

# Секретный ключ для JWT (должен совпадать с ключами на обоих серверах)
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-cpm-lms-2025-change-in-production')

# CORS настройки
ALLOWED_ORIGINS = [
    'https://cpm-lms.ru',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
]

# Порт прокси-сервера
PROXY_PORT = int(os.environ.get('PROXY_PORT', 82))

