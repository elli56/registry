from flask_login import UserMixin
from datetime import datetime

from sweater import db, login_manager


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.LargeBinary(), nullable=False)
    name = db.Column(db.String(50), nullable=True)
    soname = db.Column(db.String(50), nullable=True)
    nick = db.Column(db.String(50), nullable=True)
    entries = db.relationship("Entry", backref="owner")

    def __repr__(self):
        return f"USER_ID:{self.id}, Username:{self.username}"


class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    private = db.Column(db.Boolean)
    author_nick = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f"ID:{self.id}, title:{self.title}"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
