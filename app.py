from flask import Flask, render_template, url_for, redirect, request, flash, session
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
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def main():
    return render_template('main.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = request.form.get('user') #запрашиваем через метод get что бы в случае чего не сломалось ничего
    password = request.form.get('pass')
    if user and password:
        user = User.query.filter_by(username=user).first()
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id # сохраняем в сессию user_id что бы иметь доступ к нему из всех методов
            next_page = request.args.get('next') # Сохраняем тот адрес куда пользователь хотел попасть до перенаправления на авторизацию
            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Login or password isn't correct")
    else:
        flash('Please fill login and password')
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


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user

    return render_template('dashboard.html', user=user)

@app.route('/dashboard/<int:id>/all-entries')
@login_required
def all_entries(id):
    entries = Entrie.query.filter_by(user_id=id).all()
    print(entries)
    return render_template('all_entries.html', entries=entries)


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
        return redirect(url_for('dashboard'))

    return render_template('create.html')


@app.route('/all-entries/<int:id>/post-detail')
@login_required
def post_detail(id):
    post = Entrie.query.filter_by(id=id).first()
    return render_template('post_detail.html', post=post)


@app.route('/change/<int:id>', methods=['GET', 'POST'])
@login_required
def change(id):
    changing_entrie = Entrie.query.filter_by(id=id).first()
    if request.method == 'POST':
        changing_entrie.title = request.form['title']
        changing_entrie.description = request.form['description']
        changing_entrie.content = request.form['content']
        db.session.commit()
        return redirect(url_for('all_entries', id=changing_entrie.user_id))
    
    return render_template('change.html', entrie=changing_entrie)


@app.route('/remove/<int:id>')
@login_required
def remove(id):
    removing_entrie = Entrie.query.filter_by(id=id).first()
    db.session.delete(removing_entrie)
    db.session.commit()
    user_id = session['user_id']
    return redirect(url_for('all_entries', id=user_id))


@app.after_request
def redirect_to_signin(response):  #если пользователь будет ломиться на страничку куда нельзя без авторизации 
    # мы будем сразу его перенапрвлять на старничку с логином после чего будем перенаправлять туда куда он хотел попасть
    #response это тот ответ который даеют любой метод куда нельзя например код 401
    print("CODE:", response.status_code)
    if response.status_code == 401:
        return redirect(url_for('login') + '?next=' + request.url)

    return response 












