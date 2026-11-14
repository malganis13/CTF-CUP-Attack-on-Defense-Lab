<?php
/* warehouse — сервис полигона A/D. PHP 8.4, встроенный сервер.

Намеренно уязвим:

  LFI           /?page=              include по параметру
  SQLi          /item?id=            запрос склеен из $_GET
  Cmd injection /thumb?src=          system со строкой из запроса
  Eval          /calc?code=&t=lab    eval по параметру (в полигоне)
  Deser         /cart                unserialize cookie

Слушает 0.0.0.0:8083. Данные — /srv/warehouse/warehouse.db.
*/
declare(strict_types=1);

$DB_PATH = "/srv/warehouse/warehouse.db";
$UPLOADS = "/srv/warehouse/uploads";
@mkdir($UPLOADS, 0777, true);

function db(): SQLite3 {
    global $DB_PATH;
    $db = new SQLite3($DB_PATH, SQLITE3_OPEN_READWRITE | SQLITE3_OPEN_CREATE);
    $db->busyTimeout(3000);
    $db->exec("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, price INTEGER)");
    $count = (int) $db->querySingle("SELECT COUNT(*) FROM items");
    if ($count === 0) {
        $db->exec("INSERT INTO items (name, price) VALUES ('cable',120),('adapter',340),('crate',900)");
    }
    return $db;
}

function out(int $status, string $body, string $type = "text/plain; charset=utf-8"): void {
    http_response_code($status);
    header("Content-Type: " . $type);
    header("Content-Length: " . strlen($body));
    echo $body;
}

$route = parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH) ?: "/";

if ($route === "/view") {
    include($_GET["page"]);
    return;
}

if ($route === "/health" || $route === "/") {
    $db = db();
    out(200, json_encode(["service" => "warehouse", "ok" => true, "items" => (int) $db->querySingle("SELECT COUNT(*) FROM items")]), "application/json");
    return;
}

if ($route === "/routes") {
    out(200, json_encode(["routes" => ["/", "/item", "/thumb", "/calc", "/cart", "/api/item"]]), "application/json");
    return;
}

if ($route === "/api/item") {
    $db = db();
    $stmt = $db->prepare("SELECT id, name, price FROM items WHERE id = :id");
    $stmt->bindValue(":id", (int) ($_GET["id"] ?? 1), SQLITE3_INTEGER);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($row === false) { out(404, json_encode(["error" => "not found"]), "application/json"); return; }
    out(200, json_encode($row), "application/json");
    return;
}

if ($route === "/item") {
    $db = db();
    $result = @$db->query("SELECT id, name, price FROM items WHERE id = " . ($_GET["id"] ?? "1"));
    if ($result === false) {
        out(500, "SQLite3::query(): Unable to prepare statement: " . $db->lastErrorMsg());
        return;
    }
    $rows = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) { $rows[] = $row; }
    out(200, json_encode(["count" => count($rows), "items" => $rows]), "application/json");
    return;
}

if ($route === "/thumb") {
    $src = $_GET["src"] ?? "/srv/warehouse";
    $output = [];
    $status = 0;
    system("ls -la " . $src . " 2>&1", $output, $status);
    out(200, implode("\n", $output) . "\nexit=" . $status);
    return;
}

if ($route === "/calc") {
    if (($_GET["t"] ?? "") === "lab" && isset($_GET["code"])) {
        ob_start();
        eval($_GET["code"]);
        out(200, (string) ob_get_clean());
        return;
    }
    out(403, "token required");
    return;
}

if ($route === "/cart") {
    if (!isset($_COOKIE["cart"])) { out(200, "empty cart"); return; }
    $cart = unserialize($_COOKIE["cart"]);
    out(200, "cart: " . print_r($cart, true));
    return;
}

/* Страница-заглушка: страница берётся из параметра и попадает в include
   через /view. Ниже — та же логика для запросов без роутинга. */
$page = $_GET["page"] ?? null;
if ($page !== null) {
    include($_GET["page"]);
    return;
}

out(404, "not found");
