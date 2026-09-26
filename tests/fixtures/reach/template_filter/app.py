from flask import Flask, render_template

app = Flask(__name__)

@app.route("/label")
def label():
    return render_template("label.html", attrs={"class": "x"})
