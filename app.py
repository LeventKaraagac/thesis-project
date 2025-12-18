from flask import Flask, render_template, request

app = Flask(__name__)  # Flask constructor
ALERT_LOG_PATH = "data/alerts.log"

def load_alerts(n=100):
    rows = []
    try:
        with open(ALERT_LOG_PATH, "r") as f:
            lines = f.readlines()[-n:]
    except FileNotFoundError:
        return rows

    for line in lines:
        parts = [p.strip() for p in line.strip().split("|")]
        if len(parts) != 5:
            continue
        ts, rule, src, dst, details = parts
        rows.append({
            "timestamp": ts,
            "rule": rule,
            "src": src,
            "dst": dst if dst != "-" else "",
            "details": details,
        })
    return rows

# A decorator used to tell the application
# which URL is associated function
@app.route('/')
def index():
    alerts = load_alerts(100)
    return render_template("index.html", alerts=alerts)

if __name__ == '__main__':
    app.run(debug=True)