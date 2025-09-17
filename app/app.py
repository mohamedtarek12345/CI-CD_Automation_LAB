from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>🚀 CI/CD Automation Lab - Deployed via Flux + Jenkins!</h1><p>Zero-downtime updates enabled.</p>"

@app.route('/health')
def health():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
