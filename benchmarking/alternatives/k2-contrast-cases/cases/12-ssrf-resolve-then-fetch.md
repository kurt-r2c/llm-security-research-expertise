# Hostname resolved for checking, resolved again for fetching

Language: Go

## Vulnerable
```go
func fetch(raw string) (*http.Response, error) {
	u, _ := url.Parse(raw)
	ips, _ := net.LookupIP(u.Hostname())
	if isPrivate(ips[0]) { return nil, errBlocked }
	return http.Get(raw) // resolves again; DNS may now answer 127.0.0.1
}
```

## Fixed
```go
	dialer := &net.Dialer{Control: func(_, addr string, _ syscall.RawConn) error {
		h, _, _ := net.SplitHostPort(addr)
		if isPrivate([]net.IP{net.ParseIP(h)}) { return errBlocked }
		return nil
	}}
	client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	return client.Get(raw)
```

Invariant: The address that is checked must be the address that is connected to, enforced at connect time.

Look for: An IP/hostname check function called before a separate HTTP client call; check-then-use on DNS with no pinning.
