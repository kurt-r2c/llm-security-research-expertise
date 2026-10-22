package main

import (
	"io"
	"net/http"
	"net/url"
)

var allowed = map[string]bool{
	"images.example.org": true,
	"docs.example.org":   true,
}

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func safeFetch(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("target"))
	if err != nil || !allowed[u.Hostname()] {
		http.Error(w, "forbidden", 403)
		return
	}
	resp, err := http.Get(u.String())
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/fetch", fetch)
	http.HandleFunc("/safe", safeFetch)
	http.ListenAndServe(":8080", nil)
}
