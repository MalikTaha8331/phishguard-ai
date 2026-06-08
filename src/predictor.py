import joblib
import numpy as np
import os

# Load model, scaler and features
BASE     = os.path.dirname(os.path.abspath(__file__))
MODELS   = os.path.join(BASE, '..', 'models')
MODEL    = joblib.load(os.path.join(MODELS, 'phish_model.pkl'))
SCALER   = joblib.load(os.path.join(MODELS, 'scaler.pkl'))
FEATURES = joblib.load(os.path.join(MODELS, 'features.pkl'))

def predict_url(url, features_dict):
    """Predict if URL is phishing or legitimate"""
    try:
        # Check reputation databases first
        from extractor import check_reputation
        if check_reputation(url):
            return {
                'url':        url,
                'prediction': 'PHISHING',
                'risk':       'PHISHING',
                'confidence': 99.9,
                'color':      'red',
                'icon':       '🎣',
                'indicators': ['URL found in known phishing database!'],
                'safe':       False,
                'features':   features_dict
            }
        # Build feature vector in correct order
        vector = np.array([[features_dict.get(f, 0) for f in FEATURES]])

        # Scale
        vector_scaled = SCALER.transform(vector)

        # Predict
        prediction   = MODEL.predict(vector_scaled)[0]
        probability  = MODEL.predict_proba(vector_scaled)[0]
        confidence   = round(float(max(probability)) * 100, 2)

        # 1 = Legitimate, -1 = Phishing
        is_phishing  = prediction == 0  # we mapped -1 to 0

        # Risk level
        if not is_phishing:
            risk  = 'SAFE'
            color = 'green'
            icon  = '✅'
        elif confidence < 70:
            risk  = 'SUSPICIOUS'
            color = 'yellow'
            icon  = '⚠️'
        elif confidence < 85:
            risk  = 'LIKELY PHISHING'
            color = 'orange'
            icon  = '🚨'
        else:
            risk  = 'PHISHING'
            color = 'red'
            icon  = '🎣'

        # Suspicious indicators
        indicators = []
        if features_dict.get('having_ip_address') == -1:
            indicators.append('Uses IP address instead of domain name')
        if features_dict.get('having_at_symbol') == -1:
            indicators.append('Contains @ symbol in URL')
        if features_dict.get('prefix_suffix') == -1:
            indicators.append('Domain contains dash (-) character')
        if features_dict.get('sslfinal_state') == -1:
            indicators.append('No HTTPS encryption')
        if features_dict.get('shortining_service') == -1:
            indicators.append('Uses URL shortening service')
        if features_dict.get('double_slash_redirecting') == -1:
            indicators.append('Contains double slash redirecting')
        if features_dict.get('having_sub_domain') == -1:
            indicators.append('Too many subdomains')
        if features_dict.get('domain_registration_length') == -1:
            indicators.append('Domain registered for less than 1 year')
        if features_dict.get('age_of_domain') == -1:
            indicators.append('Domain is less than 6 months old')
        if features_dict.get('dnsrecord') == -1:
            indicators.append('No DNS record found')
        if features_dict.get('statistical_report') == -1:
            indicators.append('Suspicious top-level domain')

        return {
            'url':          url,
            'prediction':   'PHISHING' if is_phishing else 'LEGITIMATE',
            'risk':         risk,
            'confidence':   confidence,
            'color':        color,
            'icon':         icon,
            'indicators':   indicators,
            'safe':         not is_phishing,
            'features':     features_dict
        }

    except Exception as e:
        return {
            'url':        url,
            'prediction': 'ERROR',
            'risk':       'ERROR',
            'confidence': 0,
            'color':      'gray',
            'icon':       '❓',
            'indicators': [str(e)],
            'safe':       False,
            'features':   {}
        }