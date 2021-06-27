from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, login_required, LoginManager, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt

from datetime import datetime


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ildar:1234@localhost/attempt2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'some secret salt'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.LargeBinary(), nullable=False)
    entries = db.relationship("Entrie", backref="owner")

class Entrie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f"ID:{self.id}, title:{self.title}"


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def main():
    return render_template('main.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = request.form.get('user')
    password = request.form.get('pass')
    user = User.query.filter_by(username=user).first()
    if user:
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard', id = current_user.id))
        else:
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['pass']
        password2 = request.form['pass2']

        if not (user and password and password2):
            flash("Please fill all fields")
        elif password != password2:
            flash('Passwords are not equal! Try again')
        else:
            hashed_pass = bcrypt.generate_password_hash(request.form['pass'])
            new_user = User(username=user, password=hashed_pass)

            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/dashboard/<int:id>')
@login_required
def dashboard():
    user = current_user

    return render_template('dashboard.html', user=user)



@app.route('/create-entrie', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        content = request.form['content']

        new_entrie = Entrie(title=title, description=description, content=content, user_id=current_user.id)
        db.session.add(new_entrie)
        db.session.commit()
        return redirect('/dashboard')

    return render_template('create.html')



@app.after_request
def redirect_to_signin(response):  #если пользователь будет ломиться на страничку куда нельзя без авторизации 
    # мы будем сразу его перенапрвлять на старничку с логином после чего будем перенаправлять туда куда он хотел попасть
    #response это тот ответ который даеют любой метод куда нельзя например код 401
    if response.status_code == 404:
        return redirect(url_for('login'))

    return response 












