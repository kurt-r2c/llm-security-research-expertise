# Recursive merge with attacker-chosen keys

Language: JavaScript

## Vulnerable
```js
function merge(dst, src) {
  for (const k in src) {
    if (typeof src[k] === 'object' && src[k] !== null) {
      dst[k] = merge(dst[k] || {}, src[k]);
    } else dst[k] = src[k];
  }
  return dst;
}
merge(config, JSON.parse(req.body)); // {"__proto__":{"isAdmin":true}}
```

## Fixed
```js
const BAD = new Set(['__proto__', 'constructor', 'prototype']);
function merge(dst, src) {
  for (const k of Object.keys(src)) {
    if (BAD.has(k)) continue;
    if (isPlainObject(src[k])) dst[k] = merge(Object.hasOwn(dst, k) ? dst[k] : {}, src[k]);
    else dst[k] = src[k];
  }
  return dst;
}
```

Invariant: Keys from untrusted objects must never be allowed to address the prototype chain during recursive copy or path-set.

Look for: Hand-rolled merge/clone/extend/set(obj, path, v) walking keys of parsed JSON or query strings; for-in without own-property checks.
