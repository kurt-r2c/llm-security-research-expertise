# Async authorization check not awaited

Language: TypeScript

## Vulnerable
```ts
async function canEdit(u: User, id: string): Promise<boolean> {
  return (await repo.owner(id)) === u.id;
}
router.put('/item/:id', async (req, res) => {
  if (!canEdit(req.user, req.params.id)) return res.sendStatus(403);
  await repo.update(req.params.id, req.body);
  res.sendStatus(200);
});
```

## Fixed
```ts
router.put('/item/:id', async (req, res) => {
  if (!(await canEdit(req.user, req.params.id)))
    return res.sendStatus(403);
  await repo.update(req.params.id, req.body);
  res.sendStatus(200);
});
```

Invariant: A Promise is always truthy, so `!promise` is always false and the guard never fires.

Look for: An async function's result used in an if/ternary/&& without await (also Python coroutines, Java CompletableFuture).
