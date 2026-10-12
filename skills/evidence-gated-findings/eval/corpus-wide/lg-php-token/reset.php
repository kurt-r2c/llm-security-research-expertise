<?php
function reset_password_loose($db, $email, $token, $new) {
    $row = $db->query("SELECT token FROM resets WHERE email = " . $db->quote($email))->fetch();
    if ($row && $row['token'] == $token) {
        $db->exec("UPDATE users SET pw = " . $db->quote(password_hash($new, PASSWORD_DEFAULT)) .
                  " WHERE email = " . $db->quote($email));
        return true;
    }
    return false;
}

function reset_password($db, $email, $token, $new) {
    $row = $db->query("SELECT token FROM resets WHERE email = " . $db->quote($email))->fetch();
    if ($row && hash_equals($row['token'], (string)$token)) {
        $db->exec("UPDATE users SET pw = " . $db->quote(password_hash($new, PASSWORD_DEFAULT)) .
                  " WHERE email = " . $db->quote($email));
        return true;
    }
    return false;
}
