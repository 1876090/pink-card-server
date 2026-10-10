
Enter file contents here
import os, json, time, random, string
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, redirect, session

app = Flask(__name__)
app.secret_key = "pink_card_2026"
ADMIN_PASSWORD = "123456789"
CARD_FILE = "cards.json"

def load_cards():
    if os.path.exists(CARD_FILE):
        with open(CARD_FILE, "r") as f:
            return json.load(f)
    return {"cards": {}, "announce": "Welcome", "logs": []}

def save_cards(data):
    with open(CARD_FILE, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

@app.route("/")
def index():
    return jsonify({"status": "ok", "service": "PINK Card System"})

@app.route("/api/verify", methods=["POST"])
def verify():
    data = load_cards()
    body = request.get_json(silent=True) or request.form.to_dict()
    card = body.get("card", "")
    uid = body.get("uid", "")
    if not card:
        return jsonify({"code": 400, "msg": "no card"})
    info = data.get("cards", {}).get(card)
    if not info:
        return jsonify({"code": 404, "msg": "card not found"})
    if uid and info.get("status") == "inactive":
        days = info.get("days", 30)
        info["expire"] = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        info["status"] = "active"
    expire = info.get("expire", "")
    if expire and expire != "permanent":
        try:
            if datetime.now() > datetime.strptime(expire, "%Y-%m-%d %H:%M:%S"):
                return jsonify({"code": 403, "msg": "expired"})
        except:
            pass
    save_cards(data)
    return jsonify({"code": 200, "msg": "ok", "announce": data.get("announce", ""), "expire": expire})

@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect("/admin/login")
    data = load_cards()
    cards = data.get("cards", {})
    html = "<h1>Card Admin</h1><p>Total: " + str(len(cards)) + "</p>"
    html += "<p>Announce: " + data.get("announce", "") + "</p>"
    html += '<form method="POST" action="/admin/add">'
    html += '<input name="card" placeholder="card (auto if empty)">'
    html += '<input name="days" type="number" value="30">'
    html += "<button>Add</button></form><ul>"
    for name, info in cards.items():
        html += "<li>" + name + " - " + str(info.get("days",30)) + "d - " + (info.get("expire") or "inactive") + "</li>"
    html += "</ul>"
    return html

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")
        return "wrong password"
    return '<form method="POST"><input type="password" name="password"><button>Login</button></form>'

@app.route("/admin/add", methods=["POST"])
def add_card():
    if not session.get("admin"):
        return redirect("/admin/login")
    data = load_cards()
    card = request.form.get("card", "").strip()
    days = int(request.form.get("days", 30))
    if not card:
        card = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    data.setdefault("cards", {})[card] = {"days": days, "expire": "", "status": "inactive"}
    save_cards(data)
    return redirect("/admin")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
