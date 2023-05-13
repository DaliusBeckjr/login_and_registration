from flask_app import app
from flask import render_template, redirect, request, session, flash
from flask_app.models import user
from flask_bcrypt import Bcrypt     
bcrypt = Bcrypt(app)

@app.route('/')
def root():
    return render_template('home.html')

# note: redirecting from root was making it load twice giving the table 
# two colums of the same person

# new user
@app.route('/users/show/<int:id>')
def new_user(id):
    if 'logged_in_user_id' not in session:
        return redirect('/') # can enalbe this function everywhere ex user dashboard, login to other user
    data = {
        'id' : id 
    }
    return render_template('show_user.html', user_login = user.User.get_one_user(data))


# create user/ register save_user
@app.route('/users/register', methods=['POST'])
def create_user():
    if not user.User.validate_user(request.form):
        print('USER WAS FILLED OUT WRONG')
        return redirect('/')
    hashed_pw = bcrypt.generate_password_hash(request.form['password'])
    print(hashed_pw)
    data = {
        'first_name' : request.form['first_name'],
        'last_name' : request.form['last_name'],
        'email' : request.form['email'],
        'password' : hashed_pw,
    }
    user_id = user.User.save_user(data) # create method
    session['logged_in_user_id'] = user_id
    return redirect('/')

@app.route('/users/login', methods=['POST'])
def login_user():
    user_login = user.User.get_user_by_email(request.form)
    if not user_login:
        flash('Invalid Credentials', 'login')
        return redirect('/')
    if not bcrypt.check_password_hash(user_login.password, request.form['password']):
        flash('Invalid Credentials', 'login')
        return redirect('/')
    session['logged_in_user_id'] = user_login.id
    return redirect(f"/users/show/{user_login.id}")

@app.route('/users/sign_out')
def sign_out():
    session.clear()
    return redirect('/')