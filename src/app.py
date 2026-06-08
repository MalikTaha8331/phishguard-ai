from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os

app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static'
)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url  = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'Please enter a URL!'}), 400

        # Add http if missing
        if not url.startswith('http'):
            url = 'http://' + url

        print(f"Checking URL: {url}")

        # Extract features
        from extractor import extract_features
        features = extract_features(url)

        # Predict
        from predictor import predict_url
        result = predict_url(url, features)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/batch', methods=['POST'])
def check_batch():
    """Check multiple URLs at once"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])

        if not urls:
            return jsonify({'error': 'No URLs provided!'}), 400

        results = []
        from extractor import extract_features
        from predictor import predict_url

        for url in urls[:10]:  # Max 10 at once
            url = url.strip()
            if not url:
                continue
            if not url.startswith('http'):
                url = 'http://' + url
            features = extract_features(url)
            result   = predict_url(url, features)
            results.append(result)

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("PhishGuard AI Starting...")
    print("Dashboard: http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)