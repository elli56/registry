from flask import render_template, url_for, redirect, request, flash, session
from flask_login import login_user, login_required, logout_user, current_user

from sweater import app, db, bcrypt
from sweater.models import User, Entry


@app.route('/')
def main():
    all_not_private_entries = Entry.query.filter_by(private=False)
    return render_template('main.html', entries=all_not_private_entries)


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = request.form.get('user') #запрашиваем через метод get что бы в случае чего не сломалось ничего
    password = request.form.get('pass')
    db_user = User.query.filter_by(username=user).first()
    if db_user and password:
        if bcrypt.check_password_hash(db_user.password, password):
            login_user(db_user)
            session['user_id'] = db_user.id # сохраняем в сессию user_id что бы иметь доступ к нему из всех методов
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
        nick = request.form['nick']
        password = request.form['pass']
        password2 = request.form['pass2']

        if not (user and password and password2):
            flash("Please fill all fields")
        elif password != password2:
            flash('Passwords are not equal! Try again')
        else:
            hashed_pass = bcrypt.generate_password_hash(request.form['pass'])
            new_user = User(username=user, password=hashed_pass, nick=nick)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    return render_template('dashboard.html', user=user)


@app.route('/dashboard-update/<int:user_id>', methods=['GET','POST'])
@login_required
def dashboard_update(user_id):
    user = User.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        user.name = request.form['name']
        user.soname = request.form['soname']
        user.nick = request.form['nick']
        db.session.commit()
        session['nick'] = user.nick
        return redirect(url_for('dashboard'))
    return render_template('update_dashboard_info.html', user=user)


@app.route('//dashboard-change-pass/<int:user_id>', methods=['GET', 'POST'])
@login_required
def dashboard_change_pass(user_id):
    user = User.query.filter_by(id=user_id).first()
    if request.method =='POST':
        if bcrypt.check_password_hash(user.password, request.form['password_current']):
            if request.form['password1'] == request.form['password2']:
                user.password = bcrypt.generate_password_hash(request.form['password1'])
                db.session.commit()
                return redirect(url_for('dashboard'))
            else:
                flash('passwords are not equal')
        else:
            flash('Your current password is not correct!')
    return render_template('dashboard_change_pass.html', user=user)



@app.route('/dashboard/<int:id>/all-entries')
@login_required
def all_entries(id):
    entries = Entry.query.filter_by(user_id=id).all()
    print(entries)
    return render_template('all_entries.html', entries=entries)


@app.route('/create-entrie', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        content = request.form['content']
        private = bool(request.form.get('private_entrie'))
        new_entrie = Entry(title=title, description=description, content=content, user_id=current_user.id, private=private, author_nick=current_user.nick)
        db.session.add(new_entrie)
        db.session.commit()
        return redirect(url_for('all_entries', id=session['user_id']))

    return render_template('create.html')


@app.route('/all-entries/<int:id>/post-detail')
@login_required
def post_detail(id):
    post = Entry.query.filter_by(id=id).first()
    return render_template('post_detail.html', post=post)


@app.route('/completely-entrie/<int:entry_id>/')
def completely_entrie(entry_id):
    post = Entry.query.filter_by(id=entry_id).first()
    return render_template('completely_entrie.html', post=post)



@app.route('/change/<int:id>', methods=['GET', 'POST'])
@login_required
def change(id):
    changing_entrie = Entry.query.filter_by(id=id).first()
    if request.method == 'POST':
        changing_entrie.title = request.form['title']
        changing_entrie.description = request.form['description']
        changing_entrie.content = request.form['content']
        changing_entrie.private = bool(request.form.get('private_entrie'))
        db.session.commit()
        return redirect(url_for('all_entries', id=changing_entrie.user_id))
    
    return render_template('change.html', entrie=changing_entrie)


@app.route('/remove/<int:id>')
@login_required
def remove(id):
    removing_entrie = Entry.query.filter_by(id=id).first()
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
