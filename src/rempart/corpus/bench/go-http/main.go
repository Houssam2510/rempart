package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

func user(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// rempart-expect: CODE-SQL-INJECTION
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
	defer rows.Close()
	// rempart-safe: CODE-SQL-INJECTION
	safe, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
	defer safe.Close()
}

func run(w http.ResponseWriter, r *http.Request) {
	// rempart-expect: CODE-CMD-INJECTION
	out, _ := exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Output()
	w.Write(out)
	// rempart-safe: CODE-CMD-INJECTION
	ver, _ := exec.Command("git", "--version").Output()
	w.Write(ver)
}

func main() {
	http.HandleFunc("/user", user)
	http.HandleFunc("/run", run)
	http.ListenAndServe(":8080", nil)
}
