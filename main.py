"""
Прокси-сервер для объединения запросов к cpm-serv и cpm-exam-main
Реализует единую точку авторизации
"""
from flask import Flask, request, jsonify, make_response, Response
from flask_cors import CORS
import requests
from config import MAIN_SERVER_URL, EXAM_SERVER_URL, ALLOWED_ORIGINS
from jwt_auth import generate_token, set_auth_cookie, clear_auth_cookie, get_current_user, verify_token, get_token_from_request
import os

app = Flask(__name__)

# CORS настройки
CORS(app, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "expose_headers": ["Content-Type"]
    }
})

# Таймаут для запросов к серверам (в секундах)
REQUEST_TIMEOUT = 30


def forward_request(target_url, path, method='GET', data=None, cookies=None, headers=None):
    """
    Перенаправляет запрос на целевой сервер
    
    Args:
        target_url: Базовый URL целевого сервера
        path: Путь запроса (например, '/api/get-students')
        method: HTTP метод
        data: Тело запроса (для POST/PUT)
        cookies: Cookies для отправки
        headers: Дополнительные заголовки
    
    Returns:
        Response объект от целевого сервера
    """
    url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
    
    # Подготавливаем headers
    request_headers = {
        'Content-Type': 'application/json'
    }
    
    if headers:
        request_headers.update(headers)
    
    # Подготавливаем cookies
    request_cookies = {}
    if cookies:
        # Если передан auth_token из cookie, отправляем его на целевой сервер
        auth_token = cookies.get('auth_token')
        if auth_token:
            request_cookies['auth_token'] = auth_token
    
    try:
        # Делаем запрос
        if method == 'GET':
            response = requests.get(
                url,
                params=request.args,
                cookies=request_cookies,
                headers=request_headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
        elif method == 'POST':
            response = requests.post(
                url,
                json=data,
                params=request.args,
                cookies=request_cookies,
                headers=request_headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
        elif method == 'PUT':
            response = requests.put(
                url,
                json=data,
                params=request.args,
                cookies=request_cookies,
                headers=request_headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
        elif method == 'DELETE':
            response = requests.delete(
                url,
                params=request.args,
                cookies=request_cookies,
                headers=request_headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
        else:
            return None, 405
        
        return response
        
    except requests.exceptions.Timeout:
        return None, 504
    except requests.exceptions.ConnectionError:
        return None, 503
    except Exception as e:
        print(f"Ошибка при перенаправлении запроса: {str(e)}")
        return None, 500


def create_proxy_response(requests_response, preserve_cookies=False):
    """
    Создаёт Flask Response из requests Response
    
    Args:
        requests_response: Response объект из requests
        preserve_cookies: Сохранять ли cookies из ответа целевого сервера
    """
    if requests_response is None:
        return jsonify({"error": "Сервер недоступен"}), 503
    
    # Получаем данные ответа
    try:
        content = requests_response.content
        content_type = requests_response.headers.get('Content-Type', 'application/json')
    except:
        content = b''
        content_type = 'application/json'
    
    # Создаём Flask response
    flask_response = make_response(content)
    flask_response.status_code = requests_response.status_code
    
    # Копируем заголовки (кроме cookie, если не нужно сохранять)
    for header, value in requests_response.headers.items():
        if header.lower() not in ['set-cookie', 'content-encoding', 'content-length']:
            flask_response.headers[header] = value
    
    # Если нужно сохранить cookies из целевого сервера
    if preserve_cookies:
        for cookie in requests_response.cookies:
            flask_response.set_cookie(
                cookie.name,
                cookie.value,
                domain=cookie.domain,
                path=cookie.path,
                secure=cookie.secure,
                httponly=cookie.has_nonstandard_attr('HttpOnly'),
                samesite=cookie.get('SameSite', 'Lax')
            )
    
    return flask_response


@app.route("/")
def health_check():
    """
    Проверка работоспособности прокси-сервера
    """
    return jsonify({
        "status": "ok",
        "service": "CPM Proxy Server"
    })


@app.route("/api/auth", methods=['POST'])
def proxy_auth():
    """
    Авторизация через основной сервер
    Прокси перенаправляет запрос на cpm-serv и обрабатывает ответ
    """
    data = request.get_json()
    
    # Перенаправляем запрос на основной сервер
    response = forward_request(
        MAIN_SERVER_URL,
        '/api/auth',
        method='POST',
        data=data
    )
    
    if response is None:
        return jsonify({"status": False, "error": "Сервер авторизации недоступен"}), 503
    
    # Получаем ответ от основного сервера
    try:
        response_data = response.json()
    except:
        return jsonify({"status": False, "error": "Ошибка при авторизации"}), 500
    
    # Если авторизация успешна, токен уже должен быть в Set-Cookie от основного сервера
    # Но мы создаём свой ответ, чтобы контролировать domain cookie
    if response_data.get('status') and response_data.get('user'):
        # Создаём токен на прокси-сервере (используя те же данные)
        token = generate_token(response_data['user'])
        
        # Создаём ответ с cookie
        flask_response = make_response(jsonify(response_data))
        flask_response = set_auth_cookie(flask_response, token)
        
        return flask_response
    
    # Если авторизация неуспешна, просто возвращаем ответ как есть
    return create_proxy_response(response)


@app.route("/api/logout", methods=['POST'])
def proxy_logout():
    """
    Выход - удаляет cookie на прокси
    """
    response = make_response(jsonify({
        "status": True,
        "message": "Выход выполнен успешно"
    }))
    
    response = clear_auth_cookie(response)
    
    # Также делаем logout на основном сервере
    forward_request(MAIN_SERVER_URL, '/api/logout', method='POST')
    
    return response


@app.route("/api/aun", methods=['POST'])
def proxy_aun():
    """
    Получение данных текущего пользователя из токена прокси
    """
    user = get_current_user()
    
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    return jsonify({
        'status': True,
        'role': user.get('role'),
        'entity_id': user.get('id'),
        'full_name': user.get('full_name'),
        'group_id': user.get('group_id')
    })


# ============================================================================
# ПРОКСИРОВАНИЕ ЗАПРОСОВ К ОСНОВНОМУ СЕРВЕРУ (cpm-serv)
# ============================================================================

@app.route("/api/<path:path>", methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_main_server(path):
    """
    Перенаправляет все запросы /api/* на основной сервер (cpm-serv)
    """
    data = None
    if request.method in ['POST', 'PUT']:
        try:
            data = request.get_json()
        except:
            pass
    
    response = forward_request(
        MAIN_SERVER_URL,
        f'/api/{path}',
        method=request.method,
        data=data,
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


# Также обрабатываем роуты без /api префикса, которые идут на основной сервер
@app.route("/add-learned-question", methods=['POST'])
@app.route("/all-cards-by-theme/<path:rest>", methods=['GET'])
@app.route("/cadrs-by-theme/<path:rest>", methods=['GET'])
@app.route("/create-theme-with-questions", methods=['POST'])
@app.route("/get-themes", methods=['GET'])
@app.route("/learned-questions/<path:rest>", methods=['GET'])
@app.route("/remove-learned-question/<path:rest>", methods=['DELETE'])
def proxy_main_server_direct(path=None, rest=None):
    """
    Перенаправляет запросы к основному серверу без /api префикса
    """
    # Формируем путь
    request_path = request.path
    
    data = None
    if request.method in ['POST']:
        try:
            data = request.get_json()
        except:
            pass
    
    response = forward_request(
        MAIN_SERVER_URL,
        request_path,
        method=request.method,
        data=data,
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


# ============================================================================
# ПРОКСИРОВАНИЕ ЗАПРОСОВ К ЭКЗАМ СЕРВЕРУ (cpm-exam-main)
# ============================================================================

@app.route("/directions", methods=['GET'])
@app.route("/tests/<path:rest>", methods=['GET'])
@app.route("/test/<path:rest>", methods=['GET', 'PUT', 'DELETE'])
@app.route("/create-test", methods=['POST'])
@app.route("/create-test-session", methods=['POST'])
@app.route("/test-session/<path:rest>", methods=['GET'])
@app.route("/test-sessions/<path:rest>", methods=['GET'])
@app.route("/get-attendance", methods=['POST'])
@app.route("/get-all-exams", methods=['GET'])
@app.route("/get-exam-session", methods=['POST'])
@app.route("/get-student-exam-sessions/<path:rest>", methods=['GET'])
@app.route("/get-all-exam-sessions", methods=['GET'])
@app.route("/get-exam-sessions/<path:rest>", methods=['GET'])
def proxy_exam_server(rest=None):
    """
    Перенаправляет все запросы к экзам серверу (cpm-exam-main)
    """
    request_path = request.path
    
    data = None
    if request.method in ['POST', 'PUT']:
        try:
            data = request.get_json()
        except:
            pass
    
    response = forward_request(
        EXAM_SERVER_URL,
        request_path,
        method=request.method,
        data=data,
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


# ============================================================================
# ОБРАБОТКА ОШИБОК
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Маршрут не найден"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Внутренняя ошибка сервера"}), 500


if __name__ == '__main__':
    from config import PROXY_PORT
    app.run(host='0.0.0.0', port=PROXY_PORT, debug=True)

