#Defines the User model (what a user looks like in the database).
#This creates a table called user with columns: id, username, password, and role
from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')  # for access control
    comment = db.Column(db.Text, default='')
