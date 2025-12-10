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
