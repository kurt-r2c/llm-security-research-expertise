package main

import (
	"net/http"
)

type User struct {
	Name  string
	Perms map[string]bool
}

func checkPerm(u *User, perm string) bool {
	return u.Perms[perm]
}

func mustPerm(w http.ResponseWriter, u *User, perm string) bool {
	if !u.Perms[perm] {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func purge(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	checkPerm(u, "admin")
	purgeAll()
	w.Write([]byte("purged"))
}

func rotateKeys(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !mustPerm(w, u, "admin") {
		return
	}
	rotateAll()
	w.Write([]byte("rotated"))
}

func userFrom(r *http.Request) *User { return r.Context().Value(userKey{}).(*User) }

type userKey struct{}

func purgeAll()                      {}
func rotateAll()                     {}
