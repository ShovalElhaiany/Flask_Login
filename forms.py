from models import User
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

