# Key id from header used as a file or query

Language: JavaScript

## Vulnerable
```js
function keyFor(header) {
  return fs.readFileSync('/etc/keys/' + header.kid);
}
const claims = jwt.verify(tok, keyFor(jwt.decode(tok, {complete: true}).header),
                          {algorithms: ['HS256']});
```

## Fixed
```js
const KEYS = { k1: process.env.KEY_1, k2: process.env.KEY_2 };
function keyFor(header) {
  const k = KEYS[header.kid];
  if (!k) throw new Error('unknown kid');
  return k;
}
```

Invariant: A key identifier selects from a closed server-side set and is never interpolated into a path, query or URL.

Look for: header.kid, jku, x5u or issuer fields concatenated into fs, SQL or HTTP calls before the signature is verified.
