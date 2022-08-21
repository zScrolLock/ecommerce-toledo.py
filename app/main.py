from operator import or_
from flask import Flask, make_response, abort, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from dotenv import load_dotenv
from pathlib import Path
import jwt
import os
import bcrypt

app = Flask(__name__)
env_path = Path('.')/'.env'
load_dotenv(dotenv_path=env_path)
app.debug = True
app.config['SECRET_JWT_KEY'] = os.getenv("SECRET_JWT_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{os.getenv("DATABASE_USER")}:{os.getenv("DATABASE_PASS")}@localhost:3306/{os.getenv("DATABASE_DB")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

user_adverts = db.Table('user_has_adverts', 
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('adverts_id', db.Integer, db.ForeignKey('adverts.id'), primary_key=True)
)

shops_adverts = db.Table('shops_has_adverts', 
    db.Column('shop_id', db.Integer, db.ForeignKey('shops.id'), primary_key=True),
    db.Column('adverts_id', db.Integer, db.ForeignKey('adverts.id'), primary_key=True)
)
class Users(db.Model): 
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256), nullable = False)
    email = db.Column('email', db.String(256), nullable = False)
    username = db.Column('username', db.String(256), nullable = False)
    password = db.Column('password', db.String(256), nullable = False)
    role = db.Column('role', db.String(256), default = "User", nullable = False)
    favs = db.relationship('Adverts', secondary = user_adverts, lazy = 'subquery', backref = db.backref('users', lazy = True))
    shops_id = db.Column('shops_id', db.Integer, db.ForeignKey('shops.id'), nullable = True)

    # Constructor
    def __init__(this, name, email, username, password, shops_id):
        this.name = name
        this.email = email
        this.username = username
        this.password = password
        this.shops_id = shops_id

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Shops(db.Model): 
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256), nullable = False)
    owner = db.relationship('Owner', backref = 'shops', lazy = True)
    report = db.relationship('Report', backref = 'reports', lazy = True)
    products = db.relationship('Adverts', secondary = shops_adverts, lazy = 'subquery', backref = db.backref('shops', lazy = True))

    # Constructor
    def __init__(this, name):
        this.name = name

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Adverts(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256), nullable = False)
    price = db.Column('price', db.Numeric(10, 2), nullable = False)
    category = db.Column('category', db.String(256), nullable = False)

    # Constructor
    def __init__(this, name, price, category):
        this.name = name
        this.price = price
        this.category = category

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Reports(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    type = db.Column('type', db.String(256))
    shops_id = db.Column('shops_id', db.Integer, db.ForeignKey('shops.id'))

    # Constructor
    def __init__(this, name, type, shops_id):
        this.name = name
        this.type = type
        this.shops_id = shops_id

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# Validate user With JWT Token
def checkUser(token):
    if not token:
        return False

    credentials = jwt.decode(token, app.config['SECRET_JWT_KEY'])
    result = Users.query.filter(Users.username == credentials['username'], Users.id == credentials['id']).one()

    if result == None:
        return False
    else:
        return True

@app.errorhandler(404)
def notFoundPage(err):
    return render_template('notFound.html', error = err)

@app.errorhandler(401)
def notFoundPage(err):
    return render_template('unauthorized.html', error = err)

def jokerAction(action, error):
    return render_template('jokerMessage.html', action = action, title = error['title'], message = error['message'])

@app.route("/")
def index():
    return render_template('home.html', username = request.cookies.get('username'), users = Users.query.all(), token = request.cookies.get('token'))

@app.route("/login")
def loginPage():
    return render_template('login.html')

@app.route("/user-login", methods=['POST'])
def login():
    parseResult = Users.query.filter(Users.username == request.form.get('username')).one_or_none()

    if(parseResult == None):
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    if not bcrypt.checkpw(request.form.get('password'), parseResult.password): 
        return jokerAction('Invalid Password', {'title': 'Invalid Password', 'message': 'User password is invalid'})

    token = jwt.encode({'username': parseResult.username, 'id': parseResult.id, 'role': parseResult.role}, app.config['SECRET_JWT_KEY'])
    
    del parseResult.password

    cookie = make_response(render_template('profile.html', user = parseResult))
    cookie.set_cookie('username', parseResult.name)
    cookie.set_cookie('token', token)
    
    return cookie

@app.route("/register")
def registerPage(): 
    return render_template('register.html')

@app.route("/register-user", methods=['POST'])
def registerUser():
    userValidate = Users.query.filter(or_(Users.email == request.form.get('email'), Users.username == request.form.get('username'))).one_or_none()

    if not userValidate:
        newUser = Users(request.form.get('name'), request.form.get('email'), request.form.get('username'), bcrypt.hashpw(request.form.get('password'), bcrypt.gensalt()), None)
        db.session.add(newUser)
        db.session.commit()

        return redirect(url_for('index'))
    else:
        return jokerAction('Already Exists', {'title': 'Already Exists', 'message': 'E-mail or Username is already being used'})

    

@app.route("/profile/details/")
@app.route("/profile/details")
def userProfilePage(): 
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    user = Users.query.get(jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])['id'])

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    return render_template('profile.html', user = user)


@app.route("/profile/details/update", methods=['POST'])
def updateUser():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])

    user = Users.query.get(decodedInfos['id'])

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    user.name = request.form.get('name') or user.name
    
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('userProfilePage'))

@app.route("/profile/details/delete", methods=['POST'])
def deleteUser():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    user = Users.query.get(jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])['id'])

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    db.session.delete(user)
    db.session.commit()

    cookie = make_response(redirect("/"))
    cookie.delete_cookie('token')
    cookie.delete_cookie('username')

    return cookie

@app.route("/logout-user", methods=['POST'])
def logoutUser(): 
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    cookie = make_response(redirect("/"))
    cookie.delete_cookie('token')
    cookie.delete_cookie('username')

    return cookie

@app.route("/shop/")
@app.route("/shop")
def shopPage():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    return render_template('shops.html')

@app.route("/shop/register")
def registerShopPage(): 
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    return render_template('registerShop.html')

@app.route("/shop/edit")
def updateShopPage():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    return render_template('editShop.html')

@app.route("/shop/report")
def reportsSalesShopPage():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    return render_template('reportSales.html')

if __name__ == 'main':
    db.create_all()