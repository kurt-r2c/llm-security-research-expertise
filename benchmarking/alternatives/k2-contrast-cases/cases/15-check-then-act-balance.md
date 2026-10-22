# Balance check separate from the debit

Language: Go

## Vulnerable
```go
func Withdraw(id int, amt int64) error {
	var bal int64
	db.QueryRow("SELECT balance FROM acct WHERE id=?", id).Scan(&bal)
	if bal < amt { return ErrFunds }
	_, err := db.Exec("UPDATE acct SET balance=balance-? WHERE id=?", amt, id)
	return err
}
```

## Fixed
```go
func Withdraw(id int, amt int64) error {
	res, err := db.Exec(
		"UPDATE acct SET balance=balance-? WHERE id=? AND balance>=?", amt, id, amt)
	if err != nil { return err }
	if n, _ := res.RowsAffected(); n == 0 { return ErrFunds }
	return nil
}
```

Invariant: A limit check and the state change it protects must be one atomic step, or concurrent requests all pass the check.

Look for: SELECT then UPDATE, read-then-write on counters, coupons, invites, one-time tokens, without a lock, unique constraint or conditional update.
