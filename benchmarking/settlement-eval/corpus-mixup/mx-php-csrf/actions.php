<?php
session_start();

function check_csrf($t) {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$t);
}

function verify_csrf($t) {
    if (!check_csrf($t)) {
        http_response_code(403);
        exit;
    }
}

function transfer_funds($pdo) {
    check_csrf($_POST['token'] ?? '');
    $pdo->prepare("UPDATE acct SET bal = bal - ? WHERE id = ?")->execute([$_POST['amt'], $_SESSION['uid']]);
    $pdo->prepare("UPDATE acct SET bal = bal + ? WHERE id = ?")->execute([$_POST['amt'], $_POST['to']]);
}

function update_profile($pdo) {
    verify_csrf($_POST['token'] ?? '');
    $pdo->prepare("UPDATE users SET bio = ? WHERE id = ?")->execute([$_POST['bio'], $_SESSION['uid']]);
}
