import re
import os
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
from flask import Flask, render_template, request, redirect, session, flash
app = Flask(__name__)
# import the function that will return an instance of a connection
bcrypt = Bcrypt(app)

app.secret_key = os.urandom(16)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route("/")
def index():
    if 'tracker' in session:
        session['tracker'] = False
        session['first_name'] = ""
    return render_template("index.html")


@app.route('/create_user', methods=["GET", "POST"])
def add_user_to_db():
    is_valid = True

    if len(request.form['f_name']) < 1:
        is_valid = False
        flash("Please enter a first name.", "f_name")
    if len(request.form['l_name']) < 1:
        is_valid = False
        flash("Please enter a last name.", "l_name")
    if len(request.form['email_add']) < 1:
        is_valid = False
        flash("Please enter an email address.", "email")
    if not EMAIL_REGEX.match(request.form['email_add']):
        is_valid = False
        flash("Invalid email.", "email_format")
    if len(request.form['pword']) < 1 and len(request.form['pword2']) < 1:
        is_valid = False
        flash("Please enter a password and confirm it.", "p_word")
    if request.form['pword'] != request.form['pword2']:
        is_valid = False
        flash("Passwords do not match.", "p_word_match")

    if not is_valid:
        return redirect("/")
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['pword'])
        print(pw_hash)

        mysql = connectToMySQL("trip_buddy")
        query = "INSERT INTO users (first_name, last_name, email, pword) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s);"
        data = {
            'fn': request.form["f_name"],
            'ln': request.form["l_name"],
            'em': request.form["email_add"],
            'pw': pw_hash
        }
        mysql.query_db(query, data)
        session['tracker'] = True
        session['first_name'] = request.form["f_name"]
        return redirect("/home")


@app.route('/login', methods=['GET', 'POST'])
def login():
    # see if the username provided exists in the database
    mysql = connectToMySQL("trip_buddy")
    login_query = "SELECT * FROM trip_buddy.users WHERE email = '%(email)s';"
    data = {
        'email': request.form['l_email_add']
    }
    result = mysql.query_db(login_query, data)
    if len(result) > 0:
        session['userid'] = result[0]['user_id']
        session['first_name'] = result[0]['first_name']
        # assuming we only have one user with this username, the user would be first in the list we get back
        # of course, we should have some logic to prevent duplicates of usernames when we create users
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['l_password']):
            session['tracker'] = True
            # if we get True after checking the password, we may put the user id in session

            # never render on a post, always redirect!
            return redirect('/home')
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash("You could not be logged in")
    return redirect("/")


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['tracker'] = False
    flash("You have logged out.")
    return redirect('/')


@app.route('/home', methods=["GET"])
def home():
    if not session['tracker']:
        flash("You are not logged in.  Please login or register.")
        return redirect('/')
    else:
        return render_template('dashboard.html')


if __name__ == "__main__":
    app.run(debug=True)
