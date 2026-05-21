from flask import Flask, request, redirect, session, render_template_string
import sqlite3
import bcrypt

app = Flask(__name__)

app.secret_key = "super_secret_key_change_this"

DATABASE = "users.db"

def init_db():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    """)

    conn.commit()

    conn.close()

init_db()

REGISTER_HTML = """
<h2>Register</h2>

<form method="POST">

<input type="text" name="username" placeholder="Username" required><br><br>

<input type="password" name="password" placeholder="Password" required><br><br>

<button type="submit">Register</button>

</form>

<p>{{ message }}</p>

<a href="/login">Login</a>
"""

LOGIN_HTML = """
<h2>Login</h2>

<form method="POST">

<input type="text" name="username" placeholder="Username" required><br><br>

<input type="password" name="password" placeholder="Password" required><br><br>

<button type="submit">Login</button>

</form>

<p>{{ message }}</p>

<a href="/register">Register</a>
"""

DASHBOARD_HTML = """
<h2>Dashboard</h2>

<p>Welcome {{ username }}</p>

<a href="/logout">Logout</a>
"""

@app.route("/")

def home():

    if "user" in session:

        return redirect("/dashboard")

    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])

def register():

    message = ""

    if request.method == "POST":

        username = request.form["username"].strip()

        password = request.form["password"]

        if len(username) < 3:

            message = "Username too short"

            return render_template_string(REGISTER_HTML, message=message)

        if len(password) < 6:

            message = "Password must be at least 6 characters"

            return render_template_string(REGISTER_HTML, message=message)

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:

            conn = sqlite3.connect(DATABASE)

            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()

            conn.close()

            return redirect("/login")

        except:

            message = "Username already exists"

    return render_template_string(REGISTER_HTML, message=message)

@app.route("/login", methods=["GET", "POST"])

def login():

    message = ""

    if request.method == "POST":

        username = request.form["username"].strip()

        password = request.form["password"]

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user:

            stored_password = user[0]

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password
            ):

                session["user"] = username

                return redirect("/dashboard")

        message = "Invalid username or password"

    return render_template_string(LOGIN_HTML, message=message)

@app.route("/dashboard")

def dashboard():

    if "user" not in session:

        return redirect("/login")

    return render_template_string(
        DASHBOARD_HTML,
        username=session["user"]
    )

@app.route("/logout")

def logout():

    session.clear()

    return redirect("/login")

if __name__ == "__main__":

    app.run(debug=True)