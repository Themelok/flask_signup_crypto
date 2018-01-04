import os
from flask import Flask, g, session, flash, redirect, url_for, abort, request, render_template, get_flashed_messages

from utils import get_password_by_username, get_db_connect, get_users_props, is_user


app = Flask(__name__)
app.config["DATABASE"] = os.path.join(app.root_path, "signup.db")
app.config["SECRET_KEY"] = "DEVELOPMENT KEY"


@app.before_first_request
def init_db():
    db = get_db_connect(app)
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db_connect'):
        g.db_connect.close()


# ------------------ VIEW FUNCTIONS ------------------


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    flash("You were logged out")
    return redirect(url_for('index'))


@app.route("/login", methods=["POST", "GET"])
def login():
    error=None
    if session.get("logget_in"):
        abort(401)
    if request.method == "POST":
        db = get_db_connect(app)
        users = db.execute("SELECT username FROM users")
        if not any(request.form['username'] in user for user in users.fetchall()):
            error = "Invalid username"

        elif not request.form['password'] == get_password_by_username(request.form['username'], db):
            error = 'Invalid password'
        else:
            session["logged_in"] = True
            session["username"] = request.form['username']
            flash("You were logged in")
            return redirect(url_for("index"))
    return render_template('login.html', error=error)


@app.route("/signup", methods=["POST"])
def signup():
    if session.get("logged_in"):
        abort(401)
    db = get_db_connect(app)
    # session['error'] = "ERRORR"
    if not is_user(request.form['username'],db):
        db.execute("INSERT INTO users (username, password, age, email) values (?, ?, ?, ?)",
                             [request.form['username'],
                              request.form['password'],
                              request.form['age'],
                              request.form['email']])

        db.commit()
        # g.username = request.form['username']
        session['logged_in'] = True
        session['username'] = request.form['username']
        flash("You have successfully registered!")
    else:
        flash("User {} already exists!!!".format(request.form['username']), category='error')
    for mes in get_flashed_messages():
        print(mes)
    return redirect(url_for("index"))


@app.route('/')
def index():
    creds = None

    # error = session.pop('error', None)
    if session.get('logged_in'):
        creds = get_users_props(session["username"], get_db_connect(app))
    return render_template("index.html", creds=creds)


if __name__ == '__main__':
    app.run()