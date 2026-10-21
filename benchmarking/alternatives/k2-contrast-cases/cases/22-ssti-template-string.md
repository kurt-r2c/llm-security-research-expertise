# User text compiled as a template

Language: Python

## Vulnerable
```python
@app.get('/hello')
def hello():
    greeting = "Hello " + request.args['name']
    return render_template_string(greeting)  # {{ config }} is evaluated
```

## Fixed
```python
@app.get('/hello')
def hello():
    return render_template_string("Hello {{ name }}", name=request.args['name'])
```

Invariant: User data is a template variable, never part of the template source.

Look for: render_template_string, Template(x).render, ERB.new, eval-like template compile whose source includes request or stored user text.
