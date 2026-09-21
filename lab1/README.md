# Информационная безопасность
## Лабораторная работа №1

### Стек
- Python 3.10.12 / Flask
- SQLite
- JWT
- bcrypt

### Описание API

`POST /auth/login`: метод для аутентификации пользователя (принимает логин и пароль).
```json
{
    "username": "admin",
    "password": "ChangeMe123!"
}
```
Возвращает JWT-токен, который передаётся в защищённые запросы как `Authorization: Bearer <access_token>`.

`GET /api/data`: метод для получения списка пользователей. Доступ только у аутентифицированных пользователей.

`PUT /api/users/me/password`: метод для смены пароля текущего пользователя. Требует JWT.
```json
{
    "current_password": "ChangeMe123!",
    "new_password": "NewStrongPassword123!"
}
```

### Описание реализованных мер защиты

- От **SQLi** код защищён параметризованными SQL-запросами SQLite:
```python
row = get_db().execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,)
).fetchone()
```
- От **XSS** пользовательские данные экранируются функцией `escape` перед возвратом в API:
```python
"display_name": str(escape(row["display_name"]))
```
- От **Broken Authentication** используется JWT и middleware `token_required`, проверяющий Bearer-токен, подпись и срок действия:
```python
@app.get("/api/data")
@token_required
def users():
    ...
```
- Пароли не хранятся в открытом виде: используется bcrypt:
```python
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```