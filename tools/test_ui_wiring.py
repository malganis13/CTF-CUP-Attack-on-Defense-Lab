"""Связность интерфейса: каждый id, который ищет JS, существует в HTML.

Ошибка в имени идентификатора не падает в консоли сервера — она проявляется
пустым блоком на экране. Поэтому проверка статическая: разобрать `$("#...")`
из app.js, собрать `id="..."` из index.html и сверить.

Плюс проверяется, что у каждой вкладки есть панель, а у каждой панели — запись
в TITLES/ORDER: новая вкладка без панели выглядит как мёртвая кнопка.
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


def main() -> int:
    ids = set(re.findall(r'id="([A-Za-z0-9_.-]+)"', HTML))
    used = set(re.findall(r'\$\("#([A-Za-z0-9_.-]+)"', JS))
    missing = sorted(used - ids)
    check("все id из JS есть в HTML", not missing, ", ".join(missing))

    tabs = set(re.findall(r'data-tab="([a-z]+)"', HTML))
    panels = set(re.findall(r'id="panel-([a-z]+)"', HTML))
    titles = set(re.findall(r"^\s{2}([a-z]+): \[", JS, re.M))
    order_line = re.search(r"const ORDER = \[(.*?)\];", JS, re.S)
    order = set(re.findall(r'"([a-z]+)"', order_line.group(1))) if order_line else set()

    check("у каждой вкладки есть панель", tabs <= panels, ", ".join(sorted(tabs - panels)))
    check("у каждой панели есть вкладка", panels <= tabs, ", ".join(sorted(panels - tabs)))
    check("вкладки описаны в TITLES", tabs <= titles, ", ".join(sorted(tabs - titles)))
    check("вкладки есть в ORDER", tabs <= order, ", ".join(sorted(tabs - order)))

    check("карта использует /api/map", 'api("/api/map")' in JS)
    check("стенд использует /api/topology", 'api("/api/topology")' in JS)
    check("стенд сохраняется кнопкой", 'btn-stand-save' in JS and "saveStand" in JS)
    check("журнал использует /api/journal", 'api("/api/journal")' in JS)
    check("статус отправляется на /api/status", 'api("/api/status"' in JS)
    check("поиск использует /api/search", 'api("/api/search' in JS or '"/api/search"' in JS)
    check("сортировка таблиц подключена", "makeSortable" in JS and "makeAllSortable" in JS)
    check("сортировка находок подключена", 'state.sort' in JS and "$(\"#f-sort\")" in JS)
    check("в правилах есть сброс фильтра",
          "btn-rules-reset" in JS and "resetRulesFilters" in JS)
    check("сброс возвращает сортировку", "resetSort" in JS and "#rules-sev .sev-chip" in JS)
    check("есть пометка «проверить»", 'pill review' in JS and 'btn-review' in JS)
    check("фильтр «проверить» подключён", "state.filter.review" in JS and "toggleReview" in JS)

    unsure = "не уверен" in JS and "certain" in JS
    check("уверенность отображается", unsure)

    total = 18
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
