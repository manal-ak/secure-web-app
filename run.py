#main entry point, It starts the Flask server and tells Python to run the app in debug mode 
"""from app import app

if __name__ == '__main__':
    app.run(debug=True)
"""
from app import app

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))

