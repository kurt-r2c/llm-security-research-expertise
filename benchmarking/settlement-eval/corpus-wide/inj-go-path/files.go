package main

import (
	"net/http"
	"os"
	"path/filepath"
)

const root = "/srv/files"

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func avatar(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("u"))
	data, err := os.ReadFile(filepath.Join(root, "avatars", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func main() {
	http.HandleFunc("/dl", download)
	http.HandleFunc("/avatar", avatar)
	http.ListenAndServe(":8082", nil)
}
