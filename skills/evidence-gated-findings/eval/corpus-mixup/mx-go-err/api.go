package main

import (
	"errors"
	"net/http"
)

type User struct {
	ID    string
	Roles []string
}

func Authorize(u *User, role string) error {
	for _, r := range u.Roles {
		if r == role {
			return nil
		}
	}
	return errors.New("forbidden")
}

func userFrom(r *http.Request) *User { return r.Context().Value("user").(*User) }

func dropTable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	Authorize(u, "dba")
	runSQL("DROP TABLE " + r.FormValue("t"))
	w.WriteHeader(http.StatusNoContent)
}

func vacuum(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if err := Authorize(u, "dba"); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	runSQL("VACUUM")
	w.WriteHeader(http.StatusNoContent)
}

func runSQL(string) {}

func main() {
	http.HandleFunc("/admin/drop", dropTable)
	http.HandleFunc("/admin/vacuum", vacuum)
	http.ListenAndServe(":8083", nil)
}
