<?php
$pdo = new PDO('sqlite:app.db');

function list_users_sorted($pdo) {
    $sort = $_GET['sort'] ?? 'id';
    return $pdo->query("SELECT id, name FROM users ORDER BY " . $sort)->fetchAll();
}

function list_users_safe($pdo) {
    $cols = ['id' => 'id', 'name' => 'name', 'created' => 'created_at'];
    $sort = $cols[$_GET['sort'] ?? 'id'] ?? 'id';
    return $pdo->query("SELECT id, name FROM users ORDER BY " . $sort)->fetchAll();
}

function find_user($pdo) {
    $stmt = $pdo->prepare("SELECT id, name FROM users WHERE email = ?");
    $stmt->execute([$_GET['email'] ?? '']);
    return $stmt->fetch();
}
