from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-me-to-a-long-random-string"

DB_CONFIG = {
    "host": "185.114.247.43",
    "port": 3306,
    "database": "sch688_vvedenie",
    "user": "sch688_vvedenie",
    "password": "Qwerty123",
}


# ---------- Страницы ----------

@app.route("/")
def registration():
    return render_template("registration.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/welcome")
def welcome():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("welcome.html", name=session.get("user_name"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- API ----------

@app.route("/user_register", methods=["POST"])
def user_register():
    req = request.get_json(silent=True) or {}
    name = (req.get("name") or "").strip()
    email = (req.get("email") or "").strip().lower()
    password = req.get("password") or ""

    if not name or not email or not password:
        return jsonify({"result": False, "error": "Заполните все поля"}), 400

    if len(password) < 6:
        return jsonify({"result": False, "error": "Пароль короче 6 символов"}), 400

    cnx = None
    cur = None
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cur = cnx.cursor()

        cur.execute("SELECT id FROM `users` WHERE `email` = %s", (email,))
        if cur.fetchone():
            return jsonify({"result": False, "error": "Email уже зарегистрирован"}), 409

        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO `users` (`username`, `email`, `password_hash`) VALUES (%s, %s, %s)",
            (name, email, password_hash),
        )
        cnx.commit()
    except mysql.connector.Error as e:
        if cnx:
            cnx.rollback()
        return jsonify({"result": False, "error": f"Ошибка БД: {e}"}), 500
    finally:
        if cur:
            cur.close()
        if cnx and cnx.is_connected():
            cnx.close()

    return jsonify({"result": True, "redirect": "/login"})


@app.route("/user_login", methods=["POST"])
def user_login():
    req = request.get_json(silent=True) or {}
    email = (req.get("email") or "").strip().lower()
    password = req.get("password") or ""

    if not email or not password:
        return jsonify({"result": False, "error": "Заполните все поля"}), 400

    cnx = None
    cur = None
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cur = cnx.cursor()
        cur.execute(
            "SELECT `id`, `username`, `password_hash` FROM `users` WHERE `email` = %s",
            (email,),
        )
        row = cur.fetchone()

        try:
            ok = bool(row) and check_password_hash(row[2], password)
        except (ValueError, TypeError):
            ok = False

        if not ok:
            return jsonify({"result": False, "error": "Неверный email или пароль"}), 401

        # Сохраняем пользователя в сессии
        session["user_id"] = row[0]
        session["user_name"] = row[1]

        return jsonify({"result": True, "redirect": "/welcome"})
    except mysql.connector.Error as e:
        return jsonify({"result": False, "error": f"Ошибка БД: {e}"}), 500
    finally:
        if cur:
            cur.close()
        if cnx and cnx.is_connected():
            cnx.close()

@app.route("/api/balance")
def api_balance():
    if "user_id" not in session:
        return jsonify({"result": False, "error": "Не авторизован"}), 401

    cnx = None
    cur = None
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cur = cnx.cursor()
        cur.execute("SELECT `balance` FROM `users` WHERE `id` = %s", (session["user_id"],))
        row = cur.fetchone()
        return jsonify({"result": True, "balance": row[0] if row else 0})
    except mysql.connector.Error as e:
        return jsonify({"result": False, "error": str(e)}), 500
    finally:
        if cur:
            cur.close()
        if cnx and cnx.is_connected():
            cnx.close()


if __name__ == "__main__":
    app.run(debug=True)