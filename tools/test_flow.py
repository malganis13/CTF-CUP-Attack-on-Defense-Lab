"""Поток значений и порядок веток: детекторы и их пределы.

Проверяется три вещи:
  1. находка находится там, где шаблон её пропускает (значение прошло через
     присваивания, подпись проверяется после ранней ветки);
  2. ложных срабатываний нет на нормальном коде (int(), параметризованный
     запрос, проверка до ветки);
  3. на реальных корпусах детектор срабатывает по делу — starpost и cubic.

Корпусные проверки пропускаются, если каталога нет: тест должен работать и на
машине без скачанных репозиториев.
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import confidence, flow

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


TAINT = '''import os
from flask import request


def download():
    raw = request.args.get("name")
    name = raw.strip()
    base = "/srv/files"

    target = os.path.join(base, name)
    with open(target, "rb") as handle:
        return handle.read()
'''

TAINT_SANITIZED = '''import os
from flask import request


def download():
    name = int(request.args.get("id"))
    return open(os.path.join("/srv/files", name)).read()
'''

PARAMETERIZED = '''from flask import request


def find(cur):
    uid = request.args.get("id")
    cur.execute("SELECT * FROM notes WHERE id = %s", (uid,))
    cur.execute("SELECT * FROM notes WHERE id = %s" % uid)
'''

GUARD = '''import hmac
from flask import request


def reviews():
    cursor = request.args.get("cursor")

    def parse(token, limit_raw):
        limit = int(limit_raw) if limit_raw is not None else None
        if limit is not None and limit <= 3:
            return json.loads(base64.urlsafe_b64decode(token.split(".")[0]))
        if "." not in token:
            raise ValueError("missing signature")
        payload, signature = token.rsplit(".", 1)
        if not hmac.compare_digest(sign(payload), signature):
            raise ValueError("bad signature")
        return json.loads(base64.urlsafe_b64decode(payload))

    return parse(cursor, request.args.get("limit"))
'''

GUARD_SAFE = '''import hmac
from flask import request


def reviews():
    token = request.args.get("cursor")
    if not hmac.compare_digest(sign(token), token):
        return None
    limit = int(request.args.get("limit"))
    if limit <= 3:
        return []
    return load(token)
'''

VALUE_AUTH = '''from cube.cube import Cube


class AuthManager:
    def login(self):
        login = input("> ")
        pub_cube, priv_key, info = self.db.get_user_data(login)
        priv_cube = Cube.from_str(input("> ").strip())
        if priv_cube.multiply(self.base_cube.pow(priv_key)) != pub_cube:
            print("Wrong cube!")
            return
        return login
'''

VALUE_AUTH_SAFE = '''class Renderer:
    def render(self):
        value = input("> ")
        if value.multiply(scale) != target:
            return None
        return value
'''


def rules(findings: list[dict]) -> set[str]:
    return {item["rule"] for item in findings}


def main() -> int:
    taint = flow.taint("/srv/notes/app.py", TAINT, "python")
    check("поток нашёл path traversal через присваивания", "flow-taint-path" in rules(taint),
          str(rules(taint)))
    if taint:
        item = taint[0]
        check("у находки указана исходная строка", item.get("source_line", 0) > 0,
              str(item.get("source_line")))
        check("в объяснении видна цепочка", "строка" in item["why"], item["why"][:60])
        check("поток помечен как flow", item.get("flow") is True)

    sanitized = flow.taint("/srv/notes/app.py", TAINT_SANITIZED, "python")
    check("int() снимает поток", not sanitized, str(rules(sanitized)))

    parameterized = flow.taint("/srv/notes/app.py", PARAMETERIZED, "python")
    flagged = {item["line"] for item in parameterized if item["rule"] == "flow-taint-sql"}
    check("параметризованный запрос не считается дырой", 6 not in flagged, str(flagged))
    check("склейка через % остаётся находкой", 7 in flagged, str(flagged))

    guard = flow.guard("/srv/reviews.py", GUARD, "python")
    check("ветка до проверки подписи найдена", "flow-guard-bypass" in rules(guard),
          str(rules(guard)))
    if guard:
        check("указана строка проверки", guard[0].get("verify_line", 0) > guard[0]["line"],
              f"{guard[0]['line']} -> {guard[0].get('verify_line')}")
        check("ветка названа функцией", guard[0].get("function") == "parse",
              str(guard[0].get("function")))

    safe = flow.guard("/srv/reviews.py", GUARD_SAFE, "python")
    check("проверка до ветки — не находка", not safe, str(rules(safe)))

    auth = flow.value_auth("/srv/auth.py", VALUE_AUTH, "python")
    check("авторизация сравнением структуры найдена",
          "flow-auth-by-value" in rules(auth), str(rules(auth)))
    ordinary = flow.value_auth("/srv/render.py", VALUE_AUTH_SAFE, "python")
    check("обычное сравнение не в auth-функции не шумит", not ordinary, str(rules(ordinary)))

    for item in taint + guard + auth:
        item["confidence"] = confidence.assess(item)
    if taint:
        level = taint[0]["confidence"]["level"]
        check("уверенность потока — не «уверен»", level in {"likely", "unsure"}, level)
        check("у потока есть план", bool(taint[0]["confidence"]["plan"]))
    if guard:
        check("у обхода есть план", bool(guard[0]["confidence"]["plan"]))

    empty = flow.analyze("/srv/empty.py", "", "python")
    check("пустой файл не падает", empty == [], str(empty))

    starpost = Path(r"D:\aciso\GoCTF-2026-AD\services\starpost\api\app.py")
    if starpost.is_file():
        items = flow.analyze(str(starpost), starpost.read_text(encoding="utf-8", errors="replace"),
                             "python")
        found = rules(items)
        check("starpost: обход подписи найден", "flow-guard-bypass" in found, str(found))
        check("starpost: LFI тоже виден", "flow-taint-path" in found, str(found))
    else:
        print("skip starpost: корпуса нет")

    cubic = Path(r"D:\aciso\ctfcup-2020-ad\services\cubic\service\managers\auth_manager.py")
    if cubic.is_file():
        items = flow.analyze(str(cubic), cubic.read_text(encoding="utf-8", errors="replace"),
                             "python")
        check("cubic: авторизация по структуре найдена",
              "flow-auth-by-value" in rules(items), str(rules(items)))
    else:
        print("skip cubic: корпуса нет")

    total = 20
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
