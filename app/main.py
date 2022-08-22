from base64 import decode
from operator import or_
from flask import Flask, make_response, abort, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from sqlalchemy import select
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
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{os.getenv("DATABASE_USER")}:{os.getenv("DATABASE_PASS")}@{os.getenv("DATABASE_HOST")}/{os.getenv("DATABASE_DB")}'
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

    # Constructor
    def __init__(this, name, email, username, password):
        this.name = name
        this.email = email
        this.username = username
        this.password = password

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Shops(db.Model): 
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256), nullable = False)
    report = db.relationship('Reports', backref = 'reports', lazy = True)
    products = db.relationship('Adverts', secondary = shops_adverts, lazy = 'subquery', backref = db.backref('shops', lazy = True))
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable = False)

    # Constructor
    def __init__(this, name, user_id):
        this.name = name
        this.user_id = user_id

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
    return render_template('home.html', username = request.cookies.get('username'), token = request.cookies.get('token'))

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

@app.route("/shop/register-shops", methods=['POST'])
def registerShops():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    shopValidate = Shops.query.filter(Shops.name == request.form.get('name')).one_or_none()
    user = Users.query.get(jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])['id'])

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    if not shopValidate:
        newShop = Shops(request.form.get('name'), user.id)
        db.session.add(newShop)
        db.session.commit()

        user.shops_id = newShop.id
        user.role = "Shop Owner"
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('index'))
    else:
        return jokerAction('Already Exists', {'title': 'Already Exists', 'message': 'Name is already being used'})

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

    shops = Shops.query.filter(Shops.user_id == jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])['id']).one_or_none()
    
    if not shops:
        return abort(404)

    return render_template('shopsPage.html', shop = shops)

@app.route("/shop/register")
def registerShopPage(): 
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    return render_template('registerShop.html')

@app.route("/shop/edit", methods=['POST'])
def updateShopPage():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])

    shops = Shops.query.filter(Shops.user_id == decodedInfos['id']).one_or_none()

    if not shops:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'Shops not found in database'})

    shops.name = request.form.get('name') or shops.name
    
    db.session.add(shops)
    db.session.commit()

    return redirect(url_for('shopPage'))

@app.route("/shop/delete", methods=['POST'])
def deleteShop():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    shops = Shops.query.filter(Shops.user_id == decodedInfos['id']).one_or_none()

    if not shops:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'Shops not found in database'})

    user = Users.query.get(decodedInfos['id'])
    user.role = "User"

    db.session.delete(shops)
    db.session.commit()

    return redirect(url_for('index'))


@app.route("/shop/create-product", methods=['POST'])
def createProduct():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    shops = Shops.query.filter(Shops.user_id == decodedInfos['id']).one_or_none()

    product = Adverts(request.form.get('name'), request.form.get('price'), request.form.get('category'))

    shops.products.append(product)
    db.session.add(shops)
    db.session.commit()

    return redirect(url_for('index'))


@app.route("/shop/report")
def reportsSalesShopPage():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    return render_template('reportSales.html')

if __name__ == 'main':
    db.create_all()
    app.run()