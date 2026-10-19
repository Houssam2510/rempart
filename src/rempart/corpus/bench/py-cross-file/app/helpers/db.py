import sqlite3


def run(query):
    conn = sqlite3.connect("app.db")
    return conn.execute(query).fetchall()


def run_params(query, params):
    conn = sqlite3.connect("app.db")
    return conn.execute(query, params).fetchall()
