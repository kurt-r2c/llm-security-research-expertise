# Untrusted data into a general-purpose deserializer

Language: Python

## Vulnerable
```python
def load_config(blob):
    return yaml.load(blob, Loader=yaml.Loader)  # can build arbitrary objects
```

## Fixed
```python
def load_config(blob):
    return yaml.safe_load(blob)
```

Invariant: Untrusted bytes may only be parsed by a data-only format reader that cannot instantiate arbitrary types.

Look for: pickle/yaml.load/Marshal.load/unserialize/ObjectInputStream/node-serialize reading request, queue, cache or uploaded content.
