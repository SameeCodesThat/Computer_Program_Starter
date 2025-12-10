from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError, Email, EqualTo, Optional
import re

#---------------------------------- semantic validators -----------------------------------------------------------------

def validate_password(form, field):
    password = field.data.lower()
    username = form.username.data
    blacklist = ['Password123$', 'Qwerty123!', 'Adminadmin1@', 'weLcome123!']
    if password in blacklist:
        raise ValidationError("This password isn't allowed, please try again. ")
    if len(password) < 12:
        raise ValidationError("")
    if not re.search(r'[a-z]', password):                          #checks to ensure input is alphanumeric
        raise ValidationError("Password must contain at least a letter")
    if not re.search(r'[A-Z]', field.data):
        raise ValidationError("Password must contain a capital letter")
    if not re.search(r'[0-9]', password):
        raise ValidationError("Password must contain a numeric value")
    if not re.search(r'[^a-zA-Z0-9]', password):                      #checks to ensure input has a special character
        raise ValidationError("Must contain at-least one special character")
    if re.search(r'\s', password):                                    #checks for spaces in input
        raise ValidationError("Password must not contain any spaces")
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one number.")
    if re.search(r"(.)\1{2,}", password):
        raise ValidationError("password cannot have repeated characters like 'aaa' or '1111'")
    if username.split('@')[0] in password:
        raise ValidationError("Password mus not contain the username/email")

def validate_users_age(form, field):
    if field.data is not None and field.data <= 0:
        raise ValidationError("Age must be greater than zero")

#------------------------------------------ syntactic validators -------------------------------------------------------------

class RegisterForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired(), Length(min=5, max=120),
                                                   Regexp(r'[a-zA-Z_]'), Email()])

    password = PasswordField("Password", validators=[DataRequired(), Length(min=12), Regexp('[a-zA-Z1-9]'),
                                                     validate_password])

    role = SelectField("Role", choices=[("user","User"),("moderator","Moderator"),("admin","Admin")], default="user")

    bio = TextAreaField("Bio", validators=[Length(max=200)])

    age = IntegerField("Age", validators=[Optional(), validate_users_age])

    consent = BooleanField("Accept Terms & Conditions", validators=[DataRequired(message="You must accept terms and conditions")])

    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField(
        "Email", validators=[DataRequired(message="Username is required"),Email(message="Enter a valid email address"),
            Length(min=5, max=50, message="Username must be 5-50 characters long")])

    password = PasswordField("Password",validators=[DataRequired(message="Password is required"),
            Length(min=10, message="Password must be at least 12 characters long")])

    submit = SubmitField("Log In")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("current password", validators=[DataRequired()])

    new_password = PasswordField("new password", validators=[DataRequired(), Length(min=12), Regexp('[a-zA-Z1-9]')])

    submit = SubmitField("Change Password")