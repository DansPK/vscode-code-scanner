package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
		exec.Command("sh", "-c", "ping "+r.URL.Query().Get("host")).Run()
	}
}
