# DECOY: user path joined but confined by canonical check

Language: Go

## Looks vulnerable
```go
base, _ := filepath.EvalSymlinks(root)
p, err := filepath.EvalSymlinks(filepath.Join(base, name))
rel, err2 := filepath.Rel(base, p)
if err != nil || err2 != nil || strings.HasPrefix(rel, "..") {
	http.Error(w, "bad", 400); return
}
http.ServeFile(w, r, p)
```

Looks like path traversal because of Join(name), but containment is tested on the resolved path. Weaker variants (prefix test without separator, check on the unresolved string) would still be bugs.

Invariant: The path is resolved first and then proven to be inside the root, so `..` and symlinks cannot escape.

Look for: A join with user input is fine when a canonicalise-then-contain check sits between it and the sink; verify the check uses the resolved value.
