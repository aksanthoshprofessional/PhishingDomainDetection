from flask import Flask, request, render_template
import joblib
from scripts.link_extractor import *

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    color = "red"  
    if request.method == 'POST':
        user_input = request.form['text']
        result = pred(user_input) 
        if result == 0:
            result = 'a Legitimate'
            color = 'rgb(124,252,0)'
        elif result == 1:
            result = 'possibly a Phishing'
            color = "red"
        else:
            result = "Unknown"
            color = "gray"  
    return render_template('index.html', result=result, g_color=color)

if __name__ == '__main__':
    app.run(debug=False)