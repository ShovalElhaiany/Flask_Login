from flask import Flask, redirect, render_template, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
# from forms import LoginForm, RegisterForm
from flask_login import UserMixin, login_manager, logout_user, login_required, LoginManager, login_user
from flask_bcrypt import check_password_hash, generate_password_hash

db = SQLAlchemy()
app = Flask(__name__)
app.secret_key = 'flaskey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)

login_manager= LoginManager()
login_manager.init_app(app)
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField
)
from wtforms.validators import (
    InputRequired,
    Email,
    Length,
    ValidationError,
    Optional,
    EqualTo,
    Regexp
)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(),
        Length(3,20, message="please provide a valid name"),
        Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0, "user name must have only letters, numbers, dots or underscores")
    ])
    email = StringField(validators=[
        InputRequired(), Length(5,64), Email("Email not valid")
        ])
    pwd = PasswordField(validators=[
        InputRequired(), Length(4,64)
        ])
    cpwd = PasswordField(validators=[])

    def validate_email(self, email):
        if User.query.filter_by(email = email.data).first():
            raise ValidationError("Email already exists")
        
    def validate_uname(self, uname):
        if User.query.filter_by(username = uname.data).first():
            raise ValidationError("user name already taken")


class LoginForm(FlaskForm):
    pwd = PasswordField(validators=[InputRequired(), Length(4,64)])
    email = StringField(validators=[InputRequired(), Length(5,64)])



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin ,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200),unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email =  db.Column(db.String(200),unique=True, nullable=False)

    def __repr__(self) -> str:
        return '<user %r>' % self.username
    
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login/', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        form=LoginForm()
        if form.validate_on_submit():
            try:
                user = User.query.filter_by(email=form.email.data).first()
                if check_password_hash(user.password, form.pwd.data):
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    flash(f'Invalid user name or password', 'danger')
            except Exception as e:
                flash(e, 'danger')
        return redirect(url_for('login'))
    else:
        form = LoginForm()
        return render_template("auth.html", form=form)
    

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
    

@app.route('/register/', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        form = RegisterForm()
        if form.validate_on_submit():
            email = form.email.data
            username = form.username.data
            pwd = form.pwd.data

            newUser = User(
                username=username, 
                email=email,
                password=generate_password_hash(pwd)
                )
            db.session.add(newUser)
            db.session.commit()
            flash("Account created succesfully")
            return redirect(url_for('login'))

    else:
        form = RegisterForm()
        return render_template("auth.html", form=form)
    
app.app_context().push()
db.create_all()
if __name__ == "__main__":
    app.run(debug=True)
    
