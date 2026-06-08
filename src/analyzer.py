import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import time

# Headers to mimic real browser
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
}

# Known legitimate brands that phishers impersonate
BRANDS = [
    'paypal', 'amazon', 'google', 'facebook', 'apple',
    'microsoft', 'netflix', 'bank', 'ebay', 'instagram',
    'whatsapp', 'twitter', 'linkedin', 'dropbox', 'chase',
    'wellsfargo', 'citibank', 'barclays', 'hsbc', 'visa',
    'mastercard', 'dhl', 'fedex', 'ups', 'usps'
]

# Suspicious keywords in page content
SUSPICIOUS_KEYWORDS = [
    'verify your account', 'confirm your identity',
    'your account will be suspended', 'unusual activity',
    'click here to verify', 'update your payment',
    'your account has been limited', 'security alert',
    'enter your password', 'sign in to continue',
    'validate your account', 'account verification required',
    'suspended', 'unauthorized access', 'unusual sign-in'
]

def analyze_page(url):
    """
    Visit the URL and analyze page content for phishing indicators
    Returns dict with analysis results
    """
    results = {
        'accessible':        False,
        'final_url':         url,
        'redirected':        False,
        'redirect_count':    0,
        'has_login_form':    False,
        'has_password_field': False,
        'has_suspicious_keywords': False,
        'suspicious_keywords_found': [],
        'brand_impersonation': False,
        'impersonated_brand': None,
        'external_form_action': False,
        'has_iframe':        False,
        'has_popup':         False,
        'title':             '',
        'favicon_mismatch':  False,
        'score':             0,
        'indicators':        [],
        'error':             None
    }

    try:
        # Fetch the page
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10,
            allow_redirects=True,
            verify=False
        )

        results['accessible']     = True
        results['final_url']      = response.url
        results['redirected']     = response.url != url
        results['redirect_count'] = len(response.history)

        # Check redirect
        if results['redirected']:
            results['indicators'].append(
                f'Redirected to: {response.url}'
            )
            results['score'] += 1

        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')

        # Get title
        title = soup.find('title')
        results['title'] = title.text.strip() if title else ''

        # Check for login forms
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                inp_type = inp.get('type', '').lower()
                inp_name = inp.get('name', '').lower()

                if inp_type == 'password' or 'password' in inp_name:
                    results['has_password_field'] = True
                    results['has_login_form']     = True
                    results['score']             += 2
                    results['indicators'].append(
                        'Page contains password input field'
                    )
                    break

            # Check form action — does it submit to external domain?
            action = form.get('action', '')
            if action and action.startswith('http'):
                form_domain = urlparse(action).netloc
                page_domain = urlparse(url).netloc
                if form_domain and form_domain != page_domain:
                    results['external_form_action'] = True
                    results['score'] += 3
                    results['indicators'].append(
                        f'Form submits to external domain: {form_domain}'
                    )

        # Check for iframes
        iframes = soup.find_all('iframe')
        if iframes:
            results['has_iframe'] = True
            results['score']     += 1
            results['indicators'].append(
                f'Page contains {len(iframes)} iframe(s)'
            )

        # Check for suspicious keywords
        page_text = soup.get_text().lower()
        found_keywords = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in page_text:
                found_keywords.append(keyword)

        if found_keywords:
            results['has_suspicious_keywords']    = True
            results['suspicious_keywords_found']  = found_keywords[:5]
            results['score']                     += len(found_keywords)
            results['indicators'].append(
                f'Suspicious keywords: {", ".join(found_keywords[:3])}'
            )

        # Check brand impersonation
        page_lower = page_text + ' ' + results['title'].lower()
        domain     = urlparse(url).netloc.lower()

        for brand in BRANDS:
            # Brand mentioned in page but not in domain = impersonation
            if brand in page_lower and brand not in domain:
                results['brand_impersonation'] = True
                results['impersonated_brand']  = brand
                results['score']              += 4
                results['indicators'].append(
                    f'Possible {brand.upper()} impersonation detected!'
                )
                break

        # Check for popup scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'window.open' in str(script.string):
                results['has_popup'] = True
                results['score']    += 1
                results['indicators'].append('Page contains popup scripts')
                break

        # Check right-click disable
        for script in scripts:
            if script.string and (
                'contextmenu' in str(script.string) or
                'event.button==2' in str(script.string)
            ):
                results['score'] += 1
                results['indicators'].append('Right-click is disabled on page')
                break

    except requests.exceptions.SSLError:
        results['score']      += 2
        results['indicators'].append('SSL certificate error')
        results['error']       = 'SSL Error'

    except requests.exceptions.ConnectionError:
        results['error'] = 'Could not connect to URL'

    except requests.exceptions.Timeout:
        results['error'] = 'Connection timed out'

    except Exception as e:
        results['error'] = str(e)

    return results


def get_content_verdict(analysis):
    """
    Convert analysis score to verdict
    Score 0-2: Low risk
    Score 3-5: Medium risk
    Score 6+:  High risk
    """
    score = analysis['score']

    if not analysis['accessible']:
        return 'UNKNOWN', 0.5

    if score >= 6:
        return 'PHISHING', min(0.95, 0.6 + score * 0.03)
    elif score >= 3:
        return 'SUSPICIOUS', min(0.75, 0.45 + score * 0.05)
    else:
        return 'LIKELY_SAFE', max(0.3, 0.6 - score * 0.1)