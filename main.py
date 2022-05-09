""" Crypto web app.
    Home page which has User dashbpard. Will show top crypto news for crytpo user is subscribed to
    Trends page: shows crypto performance 1 day, 1 Month, 6 Month, 1 Year, all time
    Subscribe Page: User can subscribe to Cryptos they are interested in"""


from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
Bootstrap(app)

## AUTHENTIFICATION STUFF
SECRET_KEY = 'e76926225e7143245c274fe155a211705e6f4868740a1a849c33c9d325784ccf'
app.secret_key = SECRET_KEY
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(250))


class RegistartionForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')


class LoginForm(FlaskForm):
    email = StringField(label='Name', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def root():
    return render_template('index.html')


@app.route('/logout')
def logout():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():

    registration_form = RegistartionForm()
    if request.method == 'POST' and registration_form.validate_on_submit():

        # handle email unique constraint error
        if User.query.filter_by(email=registration_form.email.data).first():
            # user already exists
            flash("An account already exists with this email")
            return redirect(url_for('login'))
        # process the new user

        hashed_password = generate_password_hash(
            registration_form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            email=registration_form.email.data,
            password=hashed_password,
            name=registration_form.name.data
        )

        # commit data to DB

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for('home_page'))

    return render_template('register.html', form=registration_form)


@app.route('/login', methods=['GET', 'POST'])
def login():

    login_form = LoginForm()
    if request.method == 'POST':
        # query the database for matching email
        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist, please try again")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Incorrect password")
            return redirect(url_for('login'))
        else:
            login_user(user)
            flash("Welcome back!")
            return redirect(url_for('home_page'))

    return render_template('login.html', form=login_form)


@app.route('/home', methods=['GET', 'POST'])
def home_page():
    return render_template('home.html')


@app.route('/trends')
def trends():
    return render_template('trends.html')


@app.route('/subscribe')
def subscribe():
    return render_template('subscribe.html')


if __name__ == '__main__':
    app.run(debug=True)
