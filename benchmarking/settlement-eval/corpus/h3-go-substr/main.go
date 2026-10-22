package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

var trusted = map[string]struct{}{"cdn.example.io": {}}

func noRedirect(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

func cdn(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.FormValue("u"))
	if err != nil {
		http.Error(w, "bad", 400)
		return
	}
	if _, ok := trusted[u.Hostname()]; !ok {
		http.Error(w, "no", 403)
		return
	}
	c := &http.Client{CheckRedirect: noRedirect}
	resp, _ := c.Get(u.String())
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func logo(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("logo")
	if !strings.Contains(raw, "example.io") {
		http.Error(w, "no", 403)
		return
	}
	resp, _ := http.Get(raw)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/cdn", cdn)
	http.HandleFunc("/logo", logo)
	http.ListenAndServe(":8081", nil)
}
