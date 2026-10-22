# URL validated then re-parsed differently

Language: Python

## Vulnerable
```python
def fetch(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise Forbidden()
    return requests.get(url, timeout=5)  # different parser, follows redirects
```

## Fixed
```python
def fetch(url):
    p = urlparse(url)
    if p.scheme != 'https' or p.hostname not in ALLOWED_HOSTS:
        raise Forbidden()
    return requests.get(p.geturl(), timeout=5, allow_redirects=False)
```

Invariant: The component that is validated must be the same parsed value the sender uses, and redirects must not escape the check.

Look for: Two different URL libraries (or a string check plus a client) touching one value; allow-lists using startswith/contains/regex on the raw URL.
