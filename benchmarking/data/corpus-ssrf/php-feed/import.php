<?php
session_start();

function require_admin() {
    if (empty($_SESSION['is_admin'])) {
        http_response_code(403);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['feed'])) {
    $xml = file_get_contents($_POST['feed']);
    echo strlen($xml);
    exit;
}

if (isset($_POST['set_webhook'])) {
    require_admin();
    $hook = $_POST['set_webhook'];
    $ch = curl_init($hook);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    echo "ok";
    exit;
}

$tpl = __DIR__ . '/templates/' . basename($_GET['page'] ?? 'home') . '.html';
echo file_get_contents($tpl);
