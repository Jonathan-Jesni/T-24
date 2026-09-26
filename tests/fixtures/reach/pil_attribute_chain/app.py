from PIL import ImageMath
from flask import Flask

app = Flask(__name__)

@app.route("/calc")
def calc():
    result = ImageMath.eval("a+b", a=1, b=2)
    return str(result)
