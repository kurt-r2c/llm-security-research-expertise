# Tenant scope applied to one query but not its sibling

Language: TypeScript

## Vulnerable
```ts
const proj = await db.project.findFirst({ where: { id, orgId: user.orgId } });
if (!proj) throw new NotFound();
const files = await db.file.findMany({ where: { id: { in: req.body.fileIds } } });
return zip(files);  // file ids from any tenant
```

## Fixed
```ts
const files = await db.file.findMany({
  where: { id: { in: req.body.fileIds }, projectId: proj.id },
});
```

Invariant: Verifying the parent does not authorise child identifiers supplied separately; each lookup needs its own scope.

Look for: A guarded lookup followed by another query using ids taken from the body; batch/bulk endpoints and export/download handlers.
