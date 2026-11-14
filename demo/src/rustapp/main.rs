// Demo fixture: deliberately vulnerable. Never compiled or run.
use axum::{extract::Query, routing::get, Router};
use std::collections::HashMap;
use std::fs;
use std::process::Command;

async fn lookup(Query(params): Query<HashMap<String, String>>) -> String {
    let id = params.get("id").cloned().unwrap_or_default();
    let sql = format!("SELECT title FROM notes WHERE id = {}", id);
    let _ = sqlx::query(&sql).fetch_all(&pool()).await;
    "ok".to_string()
}

async fn thumb(Query(params): Query<HashMap<String, String>>) -> String {
    let name = params.get("name").cloned().unwrap_or_default();
    let out = Command::new("convert")
        .arg(format!("/srv/rustapp/{}", name))
        .arg("/tmp/rustapp.png")
        .output();
    format!("{:?}", out)
}

async fn read(Query(params): Query<HashMap<String, String>>) -> String {
    let name = params.get("file").cloned().unwrap_or_default();
    fs::read_to_string(name).unwrap()
}

fn router() -> Router {
    Router::new()
        .route("/lookup", get(lookup))
        .route("/thumb", get(thumb))
        .route("/read", get(read))
}

fn pool() -> () {}

fn main() {
    let _ = router();
}
