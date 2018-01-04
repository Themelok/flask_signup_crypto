import sqlite3


def get_db_connect(app) -> sqlite3.connect:
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def get_password_by_username(username, db_connection) -> str:
    db_resp = db_connection.execute("SELECT password FROM users WHERE username is ?", [username])
    passw = db_resp.fetchall()[0]['password']
    return passw


def get_users_props(username, db_connection) -> dict:
    db_resp = db_connection.execute("SELECT * FROM users WHERE username is ?", [username])
    return dict(db_resp.fetchall()[0])


def is_user(username, db_connections) -> bool:
    db_resp = db_connections.execute("SELECT username from users WHERE username is ?",
                                     [username])
    users = db_resp.fetchall()
    return bool(users)