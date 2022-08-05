from flask import Flask, make_response
from markupsafe import escape
from flask import render_template
from flask import request

app = Flask(__name__)

@app.route("/")
def index():
    return "<span> Hello World </span>"

@app.route("/profile/<username>")
def username(username):
    cookie = make_response("<span><b>Created Cookie!</b></span>")
    cookie.set_cookie('username', username)
    return cookie

@app.route("/profile/details/")
@app.route("/profile/details")
def userProfile(): 
    return render_template('profile.html', username=request.cookies.get('username'))