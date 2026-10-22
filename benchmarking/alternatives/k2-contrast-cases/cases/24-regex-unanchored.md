# Validation regex without anchors

Language: PHP

## Vulnerable
```php
if (preg_match('/[a-z0-9_]+\.png/', $_POST['img'])) {
    include_image($_POST['img']);   // "x.png/../../etc/passwd" matches
}
```

## Fixed
```php
if (preg_match('/\A[a-z0-9_]+\.png\z/', $_POST['img'])) {
    include_image($_POST['img']);
}
```

Invariant: A validation pattern must match the whole value; a partial match proves nothing about the rest.

Look for: match/test/preg_match/re.search used as a gate with no ^...$ (or \A..\z); also `$` allowing a trailing newline.
