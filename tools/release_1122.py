"""Публикация релиза 1.12.2: GitHub Release + AD-Audit.exe в ассетах.

    $env:GH_TOKEN = "..."; python tools/release_1122.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

REPO = "malganis13/CTF-CUP-Attack-on-Defense-Lab"
TAG = "v1.12.2"
BRANCH = "ad-audit-1.1"
EXE = Path(r"D:\ad-audit-dist\AD-Audit.exe")

NOTES = """Инструмент для финала X Кубка CTF России (Attack-Defense).

Новое в 1.12.2
- аудит исходников по SSH: путь, начинающийся с «/», читается на SSH-хосте —
  приложение подключается и сканирует каталог там, копировать файлы не нужно;
- на стенде 2025 AD `/ctfcup/services` даёт 237 файлов и 86 находок
  (31 high, 55 medium) за один прогон;
- ошибка входа объясняется по-человечески: «неверный пароль или ключ. Введите
  пароль заново на вкладке „Подключение“» вместо AuthenticationException;
- подсказка в поле пути описывает три режима: пусто — хост по SSH, `D:\\...` —
  оффлайн, `/...` — каталог на хосте;
- README: раздел про три входа в движок.

Проверено
- `/ctfcup/services` по SSH: 237 файлов, 86 находок;
- `D:\\aciso\\ctfcup2025-ad\\services\\veladora` оффлайн: 39 файлов, 48 находок;
- py_compile чистый; сборка 16 148 084 байт,
  SHA-256 `141CD6030778C155E0EAC44961382127F80292B7EAD7C3E3E8495184D4197FEF`.

Запуск
- Windows: `AD-Audit.exe` из ассетов;
- Linux: `git clone -b ad-audit-1.1`, затем `packaging/linux/install.sh`.
"""


def call(method: str, url: str, data: bytes | None = None, content_type: str = "application/json"):
    token = os.environ.get("GH_TOKEN") or ""
    if not token:
        raise SystemExit("GH_TOKEN не задан")
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "ad-audit-release",
        "Content-Type": content_type,
    })
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    payload = json.dumps({
        "tag_name": TAG,
        "target_commitish": BRANCH,
        "name": "AD Audit 1.12.2 — аудит исходников по SSH",
        "body": NOTES,
        "draft": False,
        "prerelease": False,
    }, ensure_ascii=False).encode("utf-8")
    release = call("POST", f"https://api.github.com/repos/{REPO}/releases", payload,
                   "application/json; charset=utf-8")
    print(f"release: {release['html_url']}")

    if not EXE.exists():
        print(f"exe не найден: {EXE}")
        return 1
    url = (f"https://uploads.github.com/repos/{REPO}/releases/{release['id']}"
           f"/assets?name={EXE.name}")
    asset = call("POST", url, EXE.read_bytes(), "application/vnd.microsoft.portable-executable")
    print(f"asset: {asset['browser_download_url']} ({asset['size']} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
