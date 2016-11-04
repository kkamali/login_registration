from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'ThisIsSecret'
mysql = MySQLConnector(app,'sample_users')
bcrypt = Bcrypt(app)


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    canGoOn = True
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirmation = request.form['confirm']
    if (len(first_name) < 2):
        flash("First Name cannot be empty!")
        canGoOn = False
    if (not first_name.isalpha()):
        flash("First Name cannot contain numbers!")
        canGoOn = False
    if (not last_name.isalpha()):
        flash("Last Name cannot contain numbers!")
        canGoOn = False
    if (len(last_name) < 2):
        flash("Last Name cannot be empty!")
        canGoOn = False
    if (not EMAIL_REGEX.match(request.form['email'])):
        flash("Not valid email address!")
        canGoOn = False
    if (len(password) < 8):
        flash("Password cannot be less than 8 characters!")
        canGoOn = False
    if (confirmation != password):
        flash("Passwords don't match!")
        canGoOn = False
    if (canGoOn == False):
        return redirect("/")
    else:
        pw_hash = bcrypt.generate_password_hash(password)
        query = "INSERT INTO sample_users.users (email, password, first_name, last_name) VALUES (:email, :password, :first_name, :last_name)"
        data = {
            'email' : request.form["email"],
            'password' : pw_hash,
            'first_name' : request.form["first_name"],
            'last_name' : request.form["last_name"]
            }
        mysql.query_db(query, data)
        return render_template("success.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data)
    if bcrypt.check_password_hash(user[0]['password'], password):
        return render_template("success.html")
    else:
        flash("Login incorrect!")
        return redirect("/")

app.run(debug=True)
