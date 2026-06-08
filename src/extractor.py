import re
import socket
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse

def extract_features(url):
    """Extract 30 features from a URL matching UCI dataset"""
    features = {}

    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        path   = parsed.path

        # 1 — Having IP address
        try:
            socket.inet_aton(domain)
            features['having_ip_address'] = -1
        except:
            features['having_ip_address'] = 1

        # 2 — URL Length
        length = len(url)
        features['url_length'] = 1 if length < 54 else (0 if length <= 75 else -1)

        # 3 — Shortening service
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly',
                     'is.gd', 'buff.ly', 'adf.ly', 'bit.do']
        features['shortining_service'] = -1 if any(s in domain for s in shorteners) else 1

        # 4 — Having @ symbol
        features['having_at_symbol'] = -1 if '@' in url else 1

        # 5 — Double slash redirecting
        features['double_slash_redirecting'] = -1 if '//' in path else 1

        # 6 — Prefix/Suffix with dash
        features['prefix_suffix'] = -1 if '-' in domain else 1

        # 7 — Having sub domain
        dots = domain.count('.')
        features['having_sub_domain'] = 1 if dots == 1 else (0 if dots == 2 else -1)

        # 8 — SSL final state
        features['sslfinal_state'] = 1 if url.startswith('https') else -1

        # 9 — Domain registration length
        try:
            w = whois.whois(domain)
            if w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                days = (exp - datetime.now()).days
                features['domain_registration_length'] = 1 if days > 365 else -1
            else:
                features['domain_registration_length'] = -1
        except:
            features['domain_registration_length'] = -1

        # 10 — Favicon (simplified)
        features['favicon'] = 1

        # 11 — Port
        features['port'] = -1 if parsed.port and parsed.port not in [80, 443] else 1

        # 12 — HTTPS token in domain
        features['https_token'] = -1 if 'https' in domain else 1

        # 13 — Request URL (simplified)
        features['request_url'] = 1

        # 14 — URL of anchor (simplified)
        features['url_of_anchor'] = 0

        # 15 — Links in tags (simplified)
        features['links_in_tags'] = 0

        # 16 — SFH (simplified)
        features['sfh'] = 1

        # 17 — Submitting to email
        features['submitting_to_email'] = -1 if 'mailto:' in url else 1

        # 18 — Abnormal URL
        try:
            w = whois.whois(domain)
            features['abnormal_url'] = 1 if domain in str(w) else -1
        except:
            features['abnormal_url'] = -1

        # 19 — Redirect
        features['redirect'] = 1

        # 20 — On mouseover (simplified)
        features['on_mouseover'] = 1

        # 21 — Right click (simplified)
        features['rightclick'] = 1

        # 22 — Popup window (simplified)
        features['popupwindow'] = 1

        # 23 — iFrame (simplified)
        features['iframe'] = 1

        # 24 — Age of domain
        try:
            w = whois.whois(domain)
            if w.creation_date:
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                age = (datetime.now() - created).days
                features['age_of_domain'] = 1 if age > 180 else -1
            else:
                features['age_of_domain'] = -1
        except:
            features['age_of_domain'] = -1

        # 25 — DNS record
        try:
            socket.gethostbyname(domain)
            features['dnsrecord'] = 1
        except:
            features['dnsrecord'] = -1

        # 26 — Web traffic (simplified)
        features['web_traffic'] = 0

        # 27 — Page rank (simplified)
        features['page_rank'] = -1

        # 28 — Google index
        try:
            r = requests.get(
                f'https://www.google.com/search?q=site:{domain}',
                timeout=3,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            features['google_index'] = 1 if 'did not match any documents' not in r.text else -1
        except:
            features['google_index'] = 0

        # 29 — Links pointing to page (simplified)
        features['links_pointing_to_page'] = 0

        # 30 — Statistical report (simplified)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        features['statistical_report'] = -1 if any(domain.endswith(t) for t in suspicious_tlds) else 1

    except Exception as e:
        print(f"Feature extraction error: {e}")
        # Return default features
        for key in ['having_ip_address', 'url_length', 'shortining_service',
                   'having_at_symbol', 'double_slash_redirecting', 'prefix_suffix',
                   'having_sub_domain', 'sslfinal_state', 'domain_registration_length',
                   'favicon', 'port', 'https_token', 'request_url', 'url_of_anchor',
                   'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
                   'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe',
                   'age_of_domain', 'dnsrecord', 'web_traffic', 'page_rank',
                   'google_index', 'links_pointing_to_page', 'statistical_report']:
            if key not in features:
                features[key] = 0

    return features

# Known phishing databases to check
PHISH_DATABASES = [
    'https://openphish.com/feed.txt',
]

phish_cache = set()
phish_loaded = False

def load_phish_list():
    global phish_cache, phish_loaded
    if phish_loaded:
        return
    try:
        import requests
        r = requests.get(
            'https://openphish.com/feed.txt',
            timeout=5
        )
        phish_cache = set(r.text.strip().split('\n'))
        phish_loaded = True
        print(f"Loaded {len(phish_cache)} known phishing URLs")
    except:
        pass

def check_reputation(url):
    """Check URL against known phishing databases"""
    load_phish_list()
    # Check exact match
    if url in phish_cache:
        return True
    # Check domain match
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        for phish_url in phish_cache:
            if domain in phish_url:
                return True
    except:
        pass
    return False