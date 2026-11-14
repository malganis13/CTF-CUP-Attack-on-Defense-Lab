"""Живой прогон тренажёра: восемь эксплойтов по полигону и предполётная проверка."""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8765"


def call(path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=data, method="POST" if data else "GET")
    if data:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        return {"http_error": error.code, "body": body}


def wsl(cmd):
    out = subprocess.run(["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", cmd],
                         capture_output=True, text=True, timeout=120)
    return (out.stdout or "").strip()


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ip = subprocess.run(["wsl", "-d", "kali-linux", "--", "hostname", "-I"],
                        capture_output=True, text=True, timeout=60).stdout.strip().split()[0]
    call("/api/config", {"target": {"host": ip, "port": 2222, "user": "root", "auth": "key",
                                    "key_path": r"C:\Users\RYZEN_USER\Downloads\III_Exploit\ad-audit\sim\keys\ad_lab"}})
    print("host:", ip)

    patterns = call("/api/patterns")
    print(f"rules: {len(patterns['rules'])} untranslated={patterns['untranslated']}")
    sample = next(item for item in patterns["rules"] if item["id"] == "sql-fstring")
    print("  sql-fstring ru:", sample["kind_ru"], "|", sample["patch_ru"][:60], "| fix:",
          (sample.get("fix") or {}).get("title"), (sample.get("fix") or {}).get("risk"))

    rulefix = call("/api/rulefix?rule=sql-fstring")
    print("  rulefix:", rulefix["fix"]["available"], rulefix["fix"]["title"], "lines:",
          len(rulefix["fix"]["before"]), "->", len(rulefix["fix"]["after"]))

    drill = call("/api/drill")
    print(f"drills: {len(drill['drills'])} bases={drill['bases']}")
    for item in drill["drills"]:
        answer = call("/api/drill/run", {"id": item["id"]})
        if "hit" not in answer:
            print(f"  {item['id']:<14} ERROR {answer}")
            continue
        print(f"  {item['id']:<14} {answer['status']} {answer['bytes']:>5}B "
              f"{'HIT ' if answer['hit'] else 'miss'} {answer['evidence'][:52]}")

    pre = call("/api/preflight", {})
    print(f"preflight: {pre['verdict']} {pre['summary']} {pre['duration_ms']}ms")
    for row in pre["rows"]:
        print(f"  {row['status']:<5} {row['title']:<22} {row['value'][:70]}")

    print("logs:", end=" ")
    log = call("/api/logs?unit=ad-notes&lines=6")
    print("exit", log.get("exit"), "lines", len((log.get("text") or "").splitlines()))
    print("traffic:", call("/api/traffic")["summary"]["total"], "requests,",
          "labels", sorted({e.get("label") for e in call("/api/traffic")["events"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
