# auth-service

## Используемые технологии
- Go (Gin)
- JWT
- PostgreSQL
- Docker

## Запуск сервиса

Я специально загрузил в репозиторий `.env` и `postgres.env`, чтобы не нужно было тратить время на заполнение конфигов. Переменные отвечающие за длительность действия токенов находятся в `.env` файле. Запуск в терминале с помощью `docker compose`:

```bash
docker compose up --build
```

Также самую последнюю версию проекта я развернул на своём сервере, поэтому можно даже не развертывать проект локально, а просто посылать запросы на ip адрес 84.237.53.137

## Маршруты

 - GET /auth/tokens?user_id=(guid)

> выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса. Устанавливает в cookie access и refresh токены. По умолчанию access токен на 5 минут, а refresh на 15.

 - GET /auth/refresh

> выполняет Refresh операцию на пару Access, Refresh токенов. Требует refresh токен в cookie. Данные об ip пользователя я храню в базе данных refresh токенов.

### Примеры запросов

- `http://localhost:8080/auth/tokens?user_id=123` вернет сообщение о некорректном user_id
- `http://localhost:8080/auth/tokens?user_id=40471626-f79d-49fe-8491-79377f1468c5`

- `http://localhost:8080/auth/refresh`

Для cookie параметр Secure установлен в `false`, чтобы не тратить время на сертификаты.

## Структура токенов

Полезная нагрузка access токенов представляет собой:
- "user_id"
- "access_id" идентификатор пары refresh и access токена. Я решил сохранять этот идентификатор у пары при обновлении токенов.
- "client_ip" по требованию задания сохраняем ip пользователя
- "exp"

## Структура базы данных

Мой запрос на инициализацию таблицы refresh токенов:

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    access_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    issued_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
);
```

Поля `user_id`, `access_id`, `client_ip` хранятся в таблице для генерации нового access токена (так как я не извлекаю данные из старой версии токена). Поле `issued_at` используется для проверки срока его действия. `revoked` обозначает был ли переисползован токен. В будущем это поле можно исопльзовать для бана ip адресов, с которых приходят частые запросы на переиспользование refresh токенов.