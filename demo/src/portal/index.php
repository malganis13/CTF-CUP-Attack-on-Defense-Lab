<?php
// Demo fixture: deliberately vulnerable. Never served or executed.

$pdo = new PDO('sqlite:/srv/portal/portal.sqlite3');

$sql = "SELECT id, title FROM notes WHERE id = " . $_GET['id'];
$rows = $pdo->query($sql)->fetchAll();

if (isset($_GET['thumb'])) {
    system("convert " . $_GET['thumb'] . " /tmp/thumb.png");
}

if (isset($_GET['page'])) {
    include($_GET['page'] . '.php');
}

if (isset($_POST['code'])) {
    eval($_POST['code']);
}

if (isset($_FILES['avatar'])) {
    move_uploaded_file($_FILES['avatar']['tmp_name'], '/srv/portal/uploads/' . $_FILES['avatar']['name']);
}

$state = unserialize($_COOKIE['state']);

header('Content-Type: application/json');
echo json_encode(['rows' => $rows, 'state' => $state]);
