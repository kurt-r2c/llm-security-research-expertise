# Client-supplied amount not range checked

Language: PHP

## Vulnerable
```php
$qty = (int)$_POST['qty'];
$total = $qty * $item->price;
$account->balance -= $total;   // qty = -5 credits the account
$cart->add($item, $qty);
```

## Fixed
```php
$qty = filter_var($_POST['qty'], FILTER_VALIDATE_INT,
    ['options' => ['min_range' => 1, 'max_range' => 100]]);
if ($qty === false) { http_response_code(422); exit; }
$total = $qty * $item->price;
```

Invariant: Numeric inputs that feed money, stock or limits need explicit sign and range bounds on the server.

Look for: Arithmetic on request numbers (qty, amount, price, discount, page size) with no min/max and a sign-sensitive effect.
