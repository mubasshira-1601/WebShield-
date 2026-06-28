from flask import Flask, render_template, request
import requests

app = Flask(__name__)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']

    # Add https:// if user doesn't enter it
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    results = {}
    score = 0

    try:
        response = requests.get(url, timeout=5)

        # Check HTTPS
        if url.startswith('https://'):
            results['HTTPS'] = "Present ✅"
            score += 20
        else:
            results['HTTPS'] = "Missing ❌"

        # Check security headers
        for header in SECURITY_HEADERS:
            if header in response.headers:
                results[header] = "Present ✅"
                score += 15
            else:
                results[header] = "Missing ❌"

        # Get server information
        server = response.headers.get('Server', 'Not Disclosed')
        results['Server'] = server

        # Determine risk level
        if score >= 80:
            risk = "Low Risk"
            color = "green"
        elif score >= 50:
            risk = "Medium Risk"
            color = "orange"
        else:
            risk = "High Risk"
            color = "red"

        return render_template(
            'result.html',
            url=url,
            results=results,
            score=score,
            risk=risk,
            color=color
        )

    except Exception as e:
        return render_template(
            'result.html',
            error="Unable to scan the website. Please enter a valid URL."
        )


if __name__ == '__main__':
    app.run(debug=True)