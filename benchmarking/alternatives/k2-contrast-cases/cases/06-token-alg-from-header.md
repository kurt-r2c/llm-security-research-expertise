# Algorithm taken from the token itself

Language: JavaScript

## Vulnerable
```js
function verify(token, key) {
  const [h, p, s] = token.split('.');
  const alg = JSON.parse(b64d(h)).alg;
  if (alg === 'none') return JSON.parse(b64d(p));
  return hmacVerify(alg, key, h + '.' + p, s) && JSON.parse(b64d(p));
}
```

## Fixed
```js
function verify(token, key) {
  const [h, p, s] = token.split('.');
  if (JSON.parse(b64d(h)).alg !== 'HS256') throw new Error('alg');
  if (!hmacVerify('HS256', key, h + '.' + p, s)) throw new Error('sig');
  return JSON.parse(b64d(p));
}
```

Invariant: The verifier, not the token, decides the algorithm and key type; attacker-supplied header fields are untrusted input.

Look for: Reads of alg/kid/jku/x5u/typ from the token header that choose verification behaviour; a public key reused as an HMAC secret.
