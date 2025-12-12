from app import create_app
from flask_talisman import Talisman


app = create_app()

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", 'https://cdn.jsdelivr.net','https://cdnjs.cloudflare.com'],
    'style-src': ["'self'", 'https://fonts.googleapis.com'],
    'img-src': ["'self'", 'data:', 'https://images.unsplash.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com']
}

Talisman(app, content_security_policy=csp,strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    referrer_policy="strict-origin-when-cross-origin",
    frame_options="SAMEORIGIN")

if __name__ == '__main__':
    app.run(debug=True)