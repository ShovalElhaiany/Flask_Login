from flask_login import UserMixin
from app import db



class User(UserMixin ,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200),unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email =  db.Column(db.String(200),unique=True, nullable=False)

    def __repr__(self) -> str:
        return '<user %r>' % self.username