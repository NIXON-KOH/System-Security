import re
from wtforms import StringField, validators, PasswordField, SubmitField, BooleanField, DecimalField, FileField
from flask_wtf import FlaskForm, RecaptchaField


class LoginForm(FlaskForm):
    username = StringField("username",[validators.Length(min=2,max=25)],render_kw={"placeholder":"Username"})
    password = PasswordField("password", [validators.length(min=2)],render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")
    recaptcha = RecaptchaField()

class Totpform(FlaskForm):
    totp = StringField("totp")
    submit = SubmitField("submit")

class addroom(FlaskForm):
    name = StringField("name")
    cost = DecimalField("cost")
    description = StringField("description")
    availability = BooleanField("availability")
    max_occupancy = DecimalField('max_occupancy')
    smoking = BooleanField("smoking")
    submit = SubmitField("submit")
