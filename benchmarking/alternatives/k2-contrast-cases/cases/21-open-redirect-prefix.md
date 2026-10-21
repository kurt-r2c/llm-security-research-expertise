# Redirect target checked by prefix or substring

Language: TypeScript

## Vulnerable
```ts
const next = String(req.query.next);
if (next.startsWith('/') || next.includes('example.com')) {
  return res.redirect(next); // '//evil.test' and 'evil.test/example.com'
}
```

## Fixed
```ts
const u = new URL(String(req.query.next), 'https://example.com');
if (u.origin === 'https://example.com') return res.redirect(u.pathname + u.search);
return res.redirect('/');
```

Invariant: A redirect target must be parsed once and compared on a structured component such as the origin, not by string shape.

Look for: startsWith, includes, endsWith, indexOf or regex on a URL-like string that decides where a redirect, fetch or CORS origin goes.
