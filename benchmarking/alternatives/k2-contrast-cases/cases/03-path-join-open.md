# Path joined from user input then opened

Language: Python

## Vulnerable
```python
@app.get('/download')
def download():
    name = request.args['file']
    path = os.path.join(UPLOAD_DIR, name)
    return send_file(path)
```

## Fixed
```python
@app.get('/download')
def download():
    name = request.args['file']
    path = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if os.path.commonpath([path, UPLOAD_ROOT]) != UPLOAD_ROOT:
        abort(400)
    return send_file(path)  # UPLOAD_ROOT = realpath(UPLOAD_DIR)
```

Invariant: The final resolved path, not the user string, must be proven to lie under the intended root.

Look for: join/Join/resolve with a request-derived segment feeding open/read/send_file; note join discards the base if the segment is absolute.
