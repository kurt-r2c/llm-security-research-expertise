# Sanitizer runs before decoding

Language: PHP

## Vulnerable
```php
$name = str_replace('../', '', $_GET['f']);
$name = urldecode($name);
echo file_get_contents('/srv/files/' . $name);
// input "..%2f..%2fetc/passwd" survives the filter
```

## Fixed
```php
$name = urldecode($_GET['f']);
$path = realpath('/srv/files/' . $name);
if ($path === false || strpos($path, '/srv/files/') !== 0) { http_response_code(400); exit; }
echo file_get_contents($path);
```

Invariant: Validation must run on the final canonical form, after every decode, normalisation and join that precedes the sink.

Look for: A filter/escape/strip call whose output is later passed through urldecode, base64, unicode normalisation, or a framework's own decoder.
