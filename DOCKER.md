# Docker: развёртывание Attack–Defense лаборатории

## Проверка Docker

Нужен Docker Desktop с Compose v2:

```powershell
docker version
docker compose version
```

Если команда `docker` не найдена, установите Docker Desktop, запустите его и откройте новый PowerShell. В текущей среде Docker CLI не установлен, поэтому фактический запуск Compose здесь невозможен.

## 1. Первый запуск

Откройте PowerShell в папке `Attack_on_defense`:

```powershell
Copy-Item .env.example .env
notepad .env
```

В `.env` задайте собственный локальный токен, например длинную случайную строку:

```env
TEAM_ID=blue
CHECKER_TOKEN=replace-with-a-long-random-local-token
PATCHED=0
NOTES_PORT=18081
WORKFLOW_PORT=18082
SEARCH_PORT=18083
```

Файл `.env` не публикуйте в GitHub. Запустите сборку и контейнеры:

```powershell
docker compose up --build -d
```

Проверьте состояние:

```powershell
docker compose ps
docker compose logs --tail=50
```

Проверка health endpoints:

```powershell
Invoke-RestMethod http://127.0.0.1:18081/health
Invoke-RestMethod http://127.0.0.1:18082/health
Invoke-RestMethod http://127.0.0.1:18083/health
```

В ответе должны быть `status: ok`, соответствующий `service` и `patched: false`.

## 2. Checker

Токен берётся из `.env`. Для команды `blue`:

```powershell
python checker.py --token 'replace-with-a-long-random-local-token' --team-user blue
```

Ожидаемый результат — три строки `UP`. Checker создаёт свежие случайные флаги на каждом запуске и проверяет их штатным путём. Он не предназначен для публикации в Интернет.

## 3. Демонстрация атак

```powershell
python attack.py notes --base http://127.0.0.1:18081 --id 1
python attack.py workflow --base http://127.0.0.1:18082
python attack.py search --base http://127.0.0.1:18083
```

- `notes` демонстрирует чтение чужого объекта через изменяемый ID.
- `workflow` демонстрирует отгрузку до оплаты.
- `search` демонстрирует SQL injection в собственном SQLite-сервисе.

Атакуйте только эти локальные targets. Не используйте примеры против сторонних сайтов или открытых IP.

## 4. Проверка исправленного режима

Перезапустите контейнеры с защитными ветками:

```powershell
$env:PATCHED='1'
docker compose up --build -d
```

Проверьте:

```powershell
Invoke-RestMethod http://127.0.0.1:18081/health
python checker.py --token 'replace-with-a-long-random-local-token' --team-user blue
python attack.py workflow --base http://127.0.0.1:18082
python test_lab.py
```

В `health` должно быть `patched: true`. Checker должен пройти, а демонстрационные атаки должны перестать получать защищённые данные/переходы.

Вернуться в уязвимый режим:

```powershell
$env:PATCHED='0'
docker compose up --build -d
```

Изменение `.env` предпочтительнее переменной текущей PowerShell-сессии. После редактирования `.env` снова выполните `docker compose up --build -d`.

## 5. Остановка и сброс

Остановить контейнеры, сохранив базы и volumes:

```powershell
docker compose down
```

Удалить контейнеры и базы этой лаборатории:

```powershell
docker compose down -v
```

Команда `down -v` необратимо сбрасывает локальные флаги и состояние. Не запускайте её в другой Compose-папке.

## 6. Несколько команд на одном компьютере

Для каждого Compose project используйте отдельное имя, порты, `TEAM_ID` и token:

```powershell
$env:TEAM_ID='blue'; $env:CHECKER_TOKEN='blue-token'; $env:NOTES_PORT='18081'; $env:WORKFLOW_PORT='18082'; $env:SEARCH_PORT='18083'; docker compose -p team-blue up --build -d
$env:TEAM_ID='red'; $env:CHECKER_TOKEN='red-token'; $env:NOTES_PORT='18181'; $env:WORKFLOW_PORT='18182'; $env:SEARCH_PORT='18183'; docker compose -p team-red up --build -d
$env:TEAM_ID='green'; $env:CHECKER_TOKEN='green-token'; $env:NOTES_PORT='18281'; $env:WORKFLOW_PORT='18282'; $env:SEARCH_PORT='18283'; docker compose -p team-green up --build -d
```

Важно: значения переменных остаются в текущей PowerShell-сессии. Перед каждой командой задавайте все нужные значения явно. Checker для red:

```powershell
python checker.py --notes http://127.0.0.1:18181 --workflow http://127.0.0.1:18182 --search http://127.0.0.1:18183 --token 'red-token' --team-user red
```

Остановить только red:

```powershell
docker compose -p team-red down
```

## 7. Подключение через private VPN

По умолчанию host-порты привязаны к `127.0.0.1`, поэтому другой компьютер их не видит. Для команды без белого IP используйте Tailscale или WireGuard:

1. Подключите участников к одной private VPN-сети.
2. В `docker-compose.yml` замените, например, `127.0.0.1:18081:8081` на VPN-адрес хоста: `100.x.y.z:18081:8081`.
3. Разрешите в firewall порты только через VPN-интерфейс и только участникам команды.
4. Проверяйте доступ по VPN-IP, например `http://100.x.y.z:18081/health`.
5. Не используйте `0.0.0.0`, port forwarding на роутере или публичный reverse proxy для намеренно уязвимого стенда.

Сервис внутри контейнера слушает `0.0.0.0`, но внешний bind в Compose остаётся ограниченным loopback до тех пор, пока вы явно его не измените.

## 8. Диагностика

### `docker` не найден

Установите Docker Desktop, запустите его и перезапустите PowerShell. Проверьте:

```powershell
Get-Command docker
docker info
```

### Контейнер сразу завершился

```powershell
docker compose ps -a
docker compose logs notes
docker compose logs workflow
docker compose logs search
```

### Порт занят

Поменяйте `NOTES_PORT`, `WORKFLOW_PORT` или `SEARCH_PORT` в `.env`. Внутренние порты `8081–8083` менять не нужно.

### Checker получает `403`

Токен в аргументе `--token` не совпадает с `CHECKER_TOKEN` контейнера. Проверьте эффективную конфигурацию:

```powershell
docker compose config
```

### Состояние не сбросилось

Обычный `docker compose down` сохраняет named volumes. Для полного сброса используйте `docker compose down -v` только для нужного project.

## 9. Безопасность

Это учебная среда с намеренно уязвимым кодом. Не храните реальные секреты и реальные данные в контейнерах. Не добавляйте `.env`, базы и логи в репозиторий. Не публикуйте checker endpoints. После тренировки остановите контейнеры и при необходимости удалите volumes.
