# Патч без потери SLA

## Порядок действий

1. **Снять копию файла.** `cp app.py app.py.bak` — до правки, не после.
2. **Одна дыра за раз.** Пять правок сразу не откатываются по одной.
3. **Синтаксис.** `python -m py_compile app.py` (или `go build`, `cargo check`).
4. **Локальный прогон.** Поднять сервис на своём ноутбуке, дёрнуть ручку,
   которая проверяется чекером.
5. **Деплой в окно между проверками.** Если чекер ходит каждые 30 секунд —
   правка и рестарт занимают секунды, но лучше попасть сразу после проверки.
6. **Проверить через раунд.** Смотреть логи: чекер вернулся, ответ `UP`.

## Типовые патчи

### SQL-инъекция

```python
# было
query = f"SELECT id, title FROM notes WHERE title LIKE '%{term}%'"
db.execute(query)

# стало
db.execute("SELECT id, title FROM notes WHERE title LIKE ?", (f"%{term}%",))
```

### IDOR

```python
# было
row = db.execute("SELECT title, body FROM notes WHERE id = ?", (note_id,)).fetchone()

# стало: владелец — часть условия, а не украшение
row = db.execute(
    "SELECT title, body FROM notes WHERE id = ? AND owner = ?",
    (note_id, current_user_id),
).fetchone()
```

### Path traversal

```python
import os

root = os.path.realpath(UPLOAD_ROOT)
target = os.path.realpath(os.path.join(root, name))
if not target.startswith(root + os.sep):
    abort(403)
```

### Command injection

```python
# было
os.system(f"convert {name} out.png")

# стало: без shell, аргументы списком
subprocess.run(["convert", name, "out.png"], shell=False, check=False)
```

### Mass assignment

```python
# было
profile = {"role": payload.get("role", "user"), **payload}

# стало: allowlist полей
profile = {"name": payload.get("name", ""), "bio": payload.get("bio", "")}
profile["role"] = "user"
```

## Чего не делать

- Не менять формат ответа, который проверяет чекер. Лишний `print`, лишний
  `\n`, обёртка в JSON — и сервис `CORRUPT` при живом коде.
- Не рестартовать «на всякий случай» перед проверкой.
- Не трогать `/_checker/*`: это не ваш код и не ваша зона.
- Не логировать флаги в открытый файл: их читают соседи.
