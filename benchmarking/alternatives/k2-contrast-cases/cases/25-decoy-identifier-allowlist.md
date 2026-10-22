# DECOY: concatenated SQL with allow-listed identifier

Language: Python

## Looks vulnerable
```python
SORTABLE = {'name': 'name', 'created': 'created_at'}
def list_users(sort):
    col = SORTABLE.get(sort, 'name')
    return db.execute(f"SELECT id, name FROM users ORDER BY {col}")
```

The shape looks like injection, but the value is mapped through a dict with a constant default. It would become vulnerable if `sort` were used directly, or if the map were built from input.

Invariant: Interpolated text comes only from a closed constant map, so the attacker chooses among fixed literals, not SQL.

Look for: f-string SQL: trace the interpolated value; if it can only be a server-side literal key, it is not injectable.
