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
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
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
    
    # Добавляем Authorization заголовок, если он есть в исходном запросе
    auth_header = request.headers.get('Authorization')
    if auth_header:
        request_headers['Authorization'] = auth_header
    
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
    
    # Копируем заголовки (кроме cookie, CORS заголовков, encoding и length)
    # Flask-CORS сам добавит нужные CORS заголовки
    excluded_headers = ['set-cookie', 'content-encoding', 'content-length',
                        'access-control-allow-origin', 'access-control-allow-methods',
                        'access-control-allow-headers', 'access-control-allow-credentials',
                        'access-control-expose-headers']
    for header, value in requests_response.headers.items():
        if header.lower() not in excluded_headers:
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
    
    # Если авторизация успешна, создаём токен и возвращаем его в JSON
    if response_data.get('status') and response_data.get('user'):
        # Создаём токен на прокси-сервере (используя те же данные)
        token = generate_token(response_data['user'])
        
        # Добавляем токен в ответ
        response_data['token'] = token
        
        return jsonify(response_data)
    
    # Если авторизация неуспешна, просто возвращаем ответ как есть
    return create_proxy_response(response)


@app.route("/api/logout", methods=['POST'])
def proxy_logout():
    """
    Выход - просто возвращаем успешный ответ
    """
    return jsonify({
        "status": True,
        "message": "Выход выполнен успешно"
    })


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

@app.route("/api/add-attendance", methods=['POST'])
def proxy_add_attendance():
    """
    Перенаправляет запрос на добавление посещаемости
    Требует права администратора
    """
    # Отладочная информация
    auth_header = request.headers.get('Authorization', '')
    cookie_token = request.cookies.get('auth_token')
    all_headers = dict(request.headers)
    
    # Проверяем авторизацию
    user = get_current_user()
    
    # Если пользователь не найден, логируем для отладки
    if not user:
        print(f"[DEBUG] add-attendance: No user found")
        print(f"[DEBUG] Auth header present: {bool(auth_header)}, Cookie present: {bool(cookie_token)}")
        print(f"[DEBUG] All headers: {list(all_headers.keys())}")
        if auth_header:
            print(f"[DEBUG] Auth header preview: {auth_header[:50]}...")
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Проверяем роль - только админ
    if user.get('role') != 'admin':
        print(f"[DEBUG] add-attendance: User role is {user.get('role')}, required: admin")
        return jsonify({
            'status': False,
            'error': 'Недостаточно прав доступа. Требуется роль администратора.'
        }), 403
    
    # Перенаправляем запрос на основной сервер
    data = None
    if request.method == 'POST':
        try:
            data = request.get_json()
        except:
            pass
    
    response = forward_request(
        MAIN_SERVER_URL,
        '/api/add-attendance',
        method='POST',
        data=data,
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


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
def proxy_directions():
    """
    Получение направлений - не требует авторизации
    """
    response = forward_request(
        EXAM_SERVER_URL,
        '/directions',
        method='GET',
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


@app.route("/tests/<path:rest>", methods=['GET'])
def proxy_tests(rest=None):
    """
    Получение тестов по направлению - требует авторизацию
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Перенаправляем запрос на экзам сервер
    response = forward_request(
        EXAM_SERVER_URL,
        request.path,
        method='GET',
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


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
# РОУТЫ ДЛЯ ВНЕШНИХ ТЕСТОВ (требуют авторизацию)
# ============================================================================

@app.route("/external-tests/direction/<direction_id>", methods=['GET'])
def proxy_external_tests_by_direction(direction_id):
    """
    Получает внешние тесты по ID направления
    Требует авторизацию
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Перенаправляем запрос на экзам сервер
    response = forward_request(
        EXAM_SERVER_URL,
        f'/external-tests/direction/{direction_id}',
        method='GET',
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


@app.route("/external-tests/student/<student_id>/direction/<direction_id>", methods=['GET'])
def proxy_external_tests_for_student(student_id, direction_id):
    """
    Получает внешние тесты направления с результатами конкретного студента
    Требует авторизацию и проверку прав (студент может видеть только свои результаты)
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Проверяем права доступа: студент может видеть только свои результаты
    user_id = user.get('id')
    user_role = user.get('role')
    
    if user_role != 'admin' and str(user_id) != str(student_id):
        return jsonify({
            'status': False,
            'error': 'Недостаточно прав доступа'
        }), 403
    
    # Перенаправляем запрос на экзам сервер
    response = forward_request(
        EXAM_SERVER_URL,
        f'/external-tests/student/{student_id}/direction/{direction_id}',
        method='GET',
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


# ============================================================================
# РОУТЫ ДЛЯ РАСЧЕТА РЕЙТИНГОВ (для админов и супервайзеров)
# ============================================================================

@app.route("/get-all-ratings", methods=['GET'])
def proxy_get_all_ratings():
    """
    Получает все рейтинги из таблицы Allratings
    Требует авторизацию и роль администратора или супервайзера
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Проверяем права доступа
    user_role = user.get('role')
    if user_role not in ['admin', 'supervisor']:
        return jsonify({
            'status': False,
            'error': 'Недостаточно прав доступа. Требуется роль администратора или супервайзера'
        }), 403
    
    # Перенаправляем запрос на экзам сервер
    response = forward_request(
        EXAM_SERVER_URL,
        '/get-all-ratings',
        method='GET',
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


@app.route("/get-rating-details", methods=['POST'])
def proxy_get_rating_details():
    """
    Получает детализацию рейтинга по ID записи из MongoDB
    Требует авторизацию и роль администратора или супервайзера
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Проверяем права доступа
    user_role = user.get('role')
    if user_role not in ['admin', 'supervisor']:
        return jsonify({
            'status': False,
            'error': 'Недостаточно прав доступа. Требуется роль администратора или супервайзера'
        }), 403
    
    # Перенаправляем запрос на экзам сервер
    data = None
    if request.method == 'POST':
        try:
            data = request.get_json()
        except:
            pass
    
    response = forward_request(
        EXAM_SERVER_URL,
        '/get-rating-details',
        method='POST',
        data=data,
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


@app.route("/calculate-all-ratings", methods=['POST'])
def proxy_calculate_all_ratings():
    """
    Рассчитывает и сохраняет рейтинги для всех студентов
    Требует авторизацию и роль администратора
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Проверяем права доступа: только админ
    if user.get('role') != 'admin':
        return jsonify({
            'status': False,
            'error': 'Недостаточно прав доступа. Требуется роль администратора'
        }), 403
    
    # Перенаправляем запрос на экзам сервер
    data = None
    if request.method == 'POST':
        try:
            data = request.get_json()
        except:
            pass
    
    response = forward_request(
        EXAM_SERVER_URL,
        '/calculate-all-ratings',
        method='POST',
        data=data,
        cookies=request.cookies
    )
    
    return create_proxy_response(response)


# ============================================================================
# РОУТЫ ДЛЯ ТАБЛИЦЫ ОВ (для админов и супервайзеров)
# ============================================================================

@app.route("/get-ov-homework-table", methods=['GET'])
def proxy_get_ov_homework_table():
    """
    Получает таблицу данных по домашним заданиям типа ОВ
    Требует авторизацию и роль администратора, супервайзера или проктора
    """
    # Проверяем авторизацию
    user = get_current_user()
    if not user:
        return jsonify({
            'status': False,
            'error': 'Требуется авторизация'
        }), 401
    
    # Проверяем права доступа
    user_role = user.get('role')
    if user_role not in ['admin', 'supervisor', 'proctor']:
        return jsonify({
            'status': False,
            'error': 'Недостаточно прав доступа. Требуется роль администратора, супервайзера или проктора'
        }), 403
    
    # Перенаправляем запрос на основной сервер
    response = forward_request(
        MAIN_SERVER_URL,
        '/api/get-ov-homework-table',
        method='GET',
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
    app.run(host='0.0.0.0', port=PROXY_PORT, debug=False, threaded=True)

