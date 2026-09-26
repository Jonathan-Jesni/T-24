from io import BytesIO

import requests
from flask import Flask, request, render_template, jsonify
from PIL import Image

import config

app = Flask(__name__)


@app.route("/upload-config", methods=["POST"])
def upload_config():
    settings = config.load_settings(request.data)
    return jsonify(settings)


@app.route("/thumbnail", methods=["POST"])
def thumbnail():
    file = request.files.get("image")
    img = Image.open(file)
    img.thumbnail((128, 128))
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read(), 200, {"Content-Type": "image/png"}


@app.route("/label/<label_id>", methods=["GET"])
def label(label_id):
    return render_template("label.html", label_id=label_id, title="Label", fields={})


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_json()
    url = payload.get("url")
    response = requests.post(url, json=payload)
    return jsonify({"status": response.status_code})


if __name__ == "__main__":
    app.run(debug=True)
