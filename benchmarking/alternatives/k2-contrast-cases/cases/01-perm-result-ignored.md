# Permission check result discarded

Language: JavaScript

## Vulnerable
```js
app.delete('/doc/:id', async (req, res) => {
  checkAccess(req.user, 'delete', req.params.id); // returns bool
  await db.docs.remove(req.params.id);
  res.sendStatus(204);
});
```

## Fixed
```js
app.delete('/doc/:id', async (req, res) => {
  if (!checkAccess(req.user, 'delete', req.params.id))
    return res.sendStatus(403);
  await db.docs.remove(req.params.id);
  res.sendStatus(204);
});
```

Invariant: A security predicate only protects if its return value (or exception) gates the action.

Look for: A call named check/can/authorize/validate used as a bare statement, or assigned to a variable never read.
