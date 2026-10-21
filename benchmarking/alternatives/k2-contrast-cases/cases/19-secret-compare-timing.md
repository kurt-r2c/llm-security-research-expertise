# Secret compared with early-exit equality

Language: Go

## Vulnerable
```go
func ok(given, want string) bool {
	return given == want // returns at first differing byte
}
```

## Fixed
```go
func ok(given, want string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}
```

Invariant: Comparison of MACs, API keys and tokens must take time independent of where they first differ.

Look for: ==, equals, strcmp on signatures, HMACs, reset tokens or keys; also a missing length or empty-value check that lets '' match.
