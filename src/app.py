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

@app.route('/deepscan', methods=['POST'])
def deep_scan():
    try:
        data = request.get_json()
        url  = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'Please enter a URL!'}), 400

        if not url.startswith('http'):
            url = 'http://' + url

        print(f"Deep scanning: {url}")

        # Step 1 — ML prediction
        from extractor import extract_features
        from predictor import predict_url
        features = extract_features(url)
        ml_result = predict_url(url, features)

        # Step 2 — Page content analysis
        from analyzer import analyze_page, get_content_verdict
        print("Analyzing page content...")
        analysis = analyze_page(url)
        content_verdict, content_confidence = get_content_verdict(analysis)

        # Step 3 — Combine results
        ml_score      = ml_result['confidence'] / 100
        content_score = content_confidence

        # Weighted combination
        # ML model: 60% weight
        # Content analysis: 40% weight
        if ml_result['safe']:
            ml_phish_score = 1 - ml_score
        else:
            ml_phish_score = ml_score

        if content_verdict == 'PHISHING':
            content_phish_score = content_score
        elif content_verdict == 'SUSPICIOUS':
            content_phish_score = content_score * 0.7
        else:
            content_phish_score = 1 - content_score

        combined_score = (ml_phish_score * 0.6) + (content_phish_score * 0.4)
        combined_conf  = round(combined_score * 100, 2)

        # Final verdict
        if combined_score >= 0.65:
            final_verdict  = 'PHISHING'
            final_risk     = 'PHISHING'
            final_color    = 'red'
            final_icon     = '🎣'
            final_safe     = False
        elif combined_score >= 0.40:
            final_verdict  = 'SUSPICIOUS'
            final_risk     = 'SUSPICIOUS'
            final_color    = 'yellow'
            final_icon     = '⚠️'
            final_safe     = False
        else:
            final_verdict  = 'LEGITIMATE'
            final_risk     = 'SAFE'
            final_color    = 'green'
            final_icon     = '✅'
            final_safe     = True

        # Combine all indicators
        all_indicators = ml_result.get('indicators', []) + analysis.get('indicators', [])

        return jsonify({
            'url':              url,
            'prediction':       final_verdict,
            'risk':             final_risk,
            'confidence':       combined_conf,
            'color':            final_color,
            'icon':             final_icon,
            'safe':             final_safe,
            'indicators':       all_indicators,
            'ml_result':        {
                'prediction': ml_result['prediction'],
                'confidence': ml_result['confidence']
            },
            'content_analysis': {
                'accessible':     analysis['accessible'],
                'title':          analysis['title'],
                'has_login_form': analysis['has_login_form'],
                'brand_impersonation': analysis['brand_impersonation'],
                'impersonated_brand':  analysis['impersonated_brand'],
                'redirect_count': analysis['redirect_count'],
                'score':          analysis['score'],
                'verdict':        content_verdict,
                'error':          analysis['error']
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("PhishGuard AI Starting...")
    print("Dashboard: http://127.0.0.1:5000")
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)