use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn env_value(name: &str, fallback: &str) -> String {
    env::var(name).unwrap_or_else(|_| fallback.to_string())
}

fn patched() -> bool {
    matches!(
        env::var("PATCHED")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn response(status: &str, body: &Value) -> Vec<u8> {
    let payload = body.to_string();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{}",
        payload.as_bytes().len(), payload
    ).into_bytes()
}

fn send(stream: &mut TcpStream, status: &str, body: Value) {
    let _ = stream.write_all(&response(status, &body));
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > 32768 {
            return None;
        }
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .next()
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
    String::from_utf8(request).ok()
}

fn request_parts(request: &str) -> (&str, &str, &str) {
    let first = request.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    (method, target, body)
}

fn header(request: &str, name: &str) -> String {
    request
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.eq_ignore_ascii_case(name) {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn profile_path(data_root: &str, team: &str) -> PathBuf {
    PathBuf::from(data_root)
        .join("profiles")
        .join(format!("{team}.json"))
}

fn flag_path(data_root: &str, team: &str) -> PathBuf {
    PathBuf::from(data_root)
        .join("flags")
        .join(format!("{team}.json"))
}

fn load_profile(path: &PathBuf) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| json!({"user":"alice", "role":"member"}))
}

fn handle(mut stream: TcpStream, data_root: &str, team: &str, token: &str, is_patched: bool) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let (method, target, body) = request_parts(&request);
    let path = target.split('?').next().unwrap_or(target);

    if method == "GET" && path == "/health" {
        send(
            &mut stream,
            "200 OK",
            json!({"status":"ok", "service":"rust-profile", "team":team, "patched":is_patched}),
        );
        return;
    }

    if path.starts_with("/_checker/") {
        if header(&request, "X-Checker-Token") != token {
            send(
                &mut stream,
                "403 Forbidden",
                json!({"error":"checker authentication required"}),
            );
            return;
        }
        if method == "POST" && path == "/_checker/putflag" {
            let payload: Value = match serde_json::from_str(body) {
                Ok(value) => value,
                Err(_) => {
                    send(
                        &mut stream,
                        "400 Bad Request",
                        json!({"error":"invalid JSON"}),
                    );
                    return;
                }
            };
            let flag_id = payload.get("flag_id").and_then(Value::as_str).unwrap_or("");
            let flag = payload.get("flag").and_then(Value::as_str).unwrap_or("");
            if flag_id.is_empty() || flag.is_empty() {
                send(
                    &mut stream,
                    "400 Bad Request",
                    json!({"error":"flag_id and flag required"}),
                );
                return;
            }
            let profile = profile_path(data_root, team);
            let flag_file = flag_path(data_root, team);
            let stored_flag = json!({"flag_id":flag_id, "flag":flag});
            if fs::create_dir_all(profile.parent().unwrap()).is_err()
                || fs::create_dir_all(flag_file.parent().unwrap()).is_err()
                || fs::write(&flag_file, stored_flag.to_string()).is_err()
                || (!profile.exists()
                    && fs::write(
                        &profile,
                        json!({"user":"alice", "role":"member"}).to_string(),
                    )
                    .is_err())
            {
                send(
                    &mut stream,
                    "500 Internal Server Error",
                    json!({"error":"checker storage failed"}),
                );
            } else {
                send(&mut stream, "200 OK", json!({"status":"stored"}));
            }
            return;
        }
        if method == "GET" && path == "/_checker/checkflag" {
            match fs::read_to_string(flag_path(data_root, team)) {
                Ok(content) => match serde_json::from_str::<Value>(&content) {
                    Ok(stored) => send(&mut stream, "200 OK", json!({"stored":stored})),
                    Err(_) => send(&mut stream, "409 Conflict", json!({"error":"flag corrupt"})),
                },
                Err(_) => send(&mut stream, "409 Conflict", json!({"error":"flag missing"})),
            }
            return;
        }
        send(
            &mut stream,
            "404 Not Found",
            json!({"error":"checker route not found"}),
        );
        return;
    }

    let profile_file = profile_path(data_root, team);
    if method == "GET" && path == "/api/profile" {
        let profile = load_profile(&profile_file);
        send(
            &mut stream,
            "200 OK",
            json!({"user":"alice", "role":profile.get("role").and_then(Value::as_str).unwrap_or("member")}),
        );
        return;
    }

    if method == "PUT" && path == "/api/profile" {
        let payload: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(_) => {
                send(
                    &mut stream,
                    "400 Bad Request",
                    json!({"error":"invalid JSON"}),
                );
                return;
            }
        };
        let requested_role = payload
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("member");
        let role = if is_patched { "member" } else { requested_role };
        // INTENTIONAL MASS ASSIGNMENT: unpatched handler trusts a client-supplied role.
        let profile = json!({"user":"alice", "role":role});
        if fs::create_dir_all(profile_file.parent().unwrap()).is_err()
            || fs::write(&profile_file, profile.to_string()).is_err()
        {
            send(
                &mut stream,
                "500 Internal Server Error",
                json!({"error":"profile update failed"}),
            );
        } else {
            send(&mut stream, "200 OK", profile);
        }
        return;
    }

    if method == "GET" && path == "/api/admin/secret" {
        let profile = load_profile(&profile_file);
        if is_patched || profile.get("role").and_then(Value::as_str) != Some("admin") {
            send(
                &mut stream,
                "403 Forbidden",
                json!({"error":"admin role required"}),
            );
            return;
        }
        match fs::read_to_string(flag_path(data_root, team)) {
            Ok(content) => match serde_json::from_str::<Value>(&content) {
                Ok(flag) => send(
                    &mut stream,
                    "200 OK",
                    json!({"flag_id":flag.get("flag_id"), "flag":flag.get("flag")}),
                ),
                Err(_) => send(
                    &mut stream,
                    "409 Conflict",
                    json!({"error":"secret data corrupt"}),
                ),
            },
            Err(_) => send(
                &mut stream,
                "404 Not Found",
                json!({"error":"secret not found"}),
            ),
        }
        return;
    }

    send(&mut stream, "404 Not Found", json!({"error":"not found"}));
}

fn main() {
    let port = env_value("PORT", "8085");
    let team = env_value("TEAM_ID", "blue");
    let token = env_value("CHECKER_TOKEN", "CHANGE-ME-LOCAL-ONLY");
    let data_root = env_value("DATA_ROOT", "/data");
    let is_patched = patched();
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).expect("bind failed");
    eprintln!("starting rust-profile on :{port} team={team} patched={is_patched}");
    for stream in listener.incoming().flatten() {
        let root = data_root.clone();
        let team_id = team.clone();
        let secret = token.clone();
        thread::spawn(move || handle(stream, &root, &team_id, &secret, is_patched));
    }
}
