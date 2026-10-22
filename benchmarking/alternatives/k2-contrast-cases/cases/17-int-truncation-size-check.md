# Size checked in one integer width, used in another

Language: Go

## Vulnerable
```go
func Alloc(n int64) []byte {
	if int32(n) > MaxChunk { // wraps: 1<<32 + 5 becomes 5
		return nil
	}
	return make([]byte, n)
}
```

## Fixed
```go
func Alloc(n int64) []byte {
	if n < 0 || n > MaxChunk {
		return nil
	}
	return make([]byte, n)
}
```

Invariant: A bound must be tested in the widest type of the value and in the same type used for the allocation or index.

Look for: Casts, int/uint/long conversions, or multiplications between a length check and the buffer operation; len*size without overflow guard.
