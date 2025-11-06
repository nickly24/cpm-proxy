"""
Модуль для работы с JWT токенами и авторизацией на прокси-сервере
Использует тот же секретный ключ, что и оба сервера
"""
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, make_response
from config import JWT_SECRET_KEY

JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

def generate_token(user_data):
    """
    Генерирует JWT токен для пользователя
    """
    payload = {
        'role': user_data.get('role'),
        'id': user_data.get('id'),
        'full_name': user_data.get('full_name'),
        'group_id': user_data.get('group_id'),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def verify_token(token):
    """
    Проверяет JWT токен и возвращает данные пользователя
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return {
            'role': payload.get('role'),
            'id': payload.get('id'),
            'full_name': payload.get('full_name'),
            'group_id': payload.get('group_id')
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_token_from_request():
    """
    Получает JWT токен из заголовка Authorization или из cookie (для обратной совместимости)
    """
    # Сначала пытаемся получить из заголовка Authorization
    auth_header = request.headers.get('Authorization', '')
    if auth_header:
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '', 1)
            if token:
                return token
        # Попробуем без префикса Bearer (на случай если токен уже без префикса)
        elif auth_header.strip():
            return auth_header.strip()
    
    # Fallback на cookie для обратной совместимости
    cookie_token = request.cookies.get('auth_token')
    if cookie_token:
        return cookie_token
    
    return None


def get_current_user():
    """
    Получает текущего авторизованного пользователя из токена
    """
    token = get_token_from_request()
    if not token:
        return None
    
    # Пробуем верифицировать токен
    user = verify_token(token)
    if not user:
        # Если токен не прошел верификацию, логируем для отладки
        print(f"[DEBUG] Token verification failed. Token length: {len(token) if token else 0}")
        if token:
            print(f"[DEBUG] Token preview: {token[:20]}...")
    
    return user


def set_auth_cookie(response, token):
    """
    Устанавливает JWT токен в HTTP-only cookie
    """
    cookie_domain = os.environ.get('COOKIE_DOMAIN', None)
    
    # Всегда используем secure=false для единообразия между локальной и продакшен средой
    cookie_params = {
        'httponly': True,
        'secure': False,
        'samesite': 'Lax',
        'max_age': JWT_EXPIRATION_HOURS * 3600
    }
    
    if cookie_domain:
        cookie_params['domain'] = cookie_domain
    
    response.set_cookie('auth_token', token, **cookie_params)
    return response


def clear_auth_cookie(response):
    """
    Удаляет JWT токен из cookie
    Пытается удалить cookie для всех возможных вариантов конфигурации
    """
    cookie_domain = os.environ.get('COOKIE_DOMAIN', None)
    
    # Всегда используем secure=false для единообразия между локальной и продакшен средой
    base_cookie_params = {
        'httponly': True,
        'secure': False,
        'samesite': 'Lax',
        'max_age': 0
    }
    
    # Удаляем cookie без domain (на случай, если она была установлена без domain)
    response.set_cookie('auth_token', '', **base_cookie_params)
    
    # Если есть COOKIE_DOMAIN, также удаляем cookie с domain
    if cookie_domain:
        cookie_params_with_domain = base_cookie_params.copy()
        cookie_params_with_domain['domain'] = cookie_domain
        response.set_cookie('auth_token', '', **cookie_params_with_domain)
    
    return response

