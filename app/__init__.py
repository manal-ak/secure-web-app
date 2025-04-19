#Initializes the Flask app and all its tools (database, bcrypt, login).
#This file connects everything together.
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database.db'

# Flask extensions
db = SQLAlchemy(app) # Database
bcrypt = Bcrypt(app)  # Password hashing
login_manager = LoginManager(app) # Login management
login_manager.login_view = 'login'

#import models BEFORE user_loader
from app.models import User # Load User model

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# import routes LAST
from app import routes   # Load routes
