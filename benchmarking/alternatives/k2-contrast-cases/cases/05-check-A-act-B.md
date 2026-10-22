# Check applied to object A, action applied to object B

Language: Go

## Vulnerable
```go
func Move(w http.ResponseWriter, r *http.Request) {
	var in struct{ DocID, FolderID string }
	json.NewDecoder(r.Body).Decode(&in)
	if !canWrite(user(r), in.DocID) { http.Error(w, "no", 403); return }
	db.Exec("UPDATE docs SET folder=? WHERE id=?", in.FolderID, in.DocID)
}
```

## Fixed
```go
	if !canWrite(user(r), in.DocID) || !canWrite(user(r), in.FolderID) {
		http.Error(w, "no", 403)
		return
	}
	db.Exec("UPDATE docs SET folder=? WHERE id=?", in.FolderID, in.DocID)
```

Invariant: Every object reference the action touches (source and destination, parent and child) must be authorised, not only the first one.

Look for: A handler taking two or more IDs from the body/URL with an ownership check on just one.
