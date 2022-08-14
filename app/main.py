from flask import Flask, make_response, abort, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from pathlib import Path
import jwt
import os

app = Flask(__name__)
env_path = Path('.')/'.env'
load_dotenv(dotenv_path=env_path)
app.debug = True
app.config['SECRET_JWT_KEY'] = os.getenv("SECRET_JWT_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{os.getenv("DATABASE_USER")}:{os.getenv("DATABASE_PASS")}@localhost:3306/{os.getenv("DATABASE_DB")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Users(db.Model): 
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256))
    email = db.Column('email', db.String(256))
    username = db.Column('username', db.String(256))
    password = db.Column('password', db.String(256))
    salt = db.Column('salt', db.String(256))
    role = db.Column('role', db.String(256), default = "User")
    shops_id = db.Column('shops_id', db.Integer)

    # Constructor
    def __init__(this, name, email, username, password, salt, shops_id):
        this.name = name
        this.email = email
        this.username = username
        this.password = password
        this.salt = salt
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

@app.route("/")
def index():
    return render_template('home.html', username=request.cookies.get('username'), users = Users.query.all(), token = request.cookies.get('token'))

@app.route("/login")
def loginPage():
    return render_template('login.html')

@app.route("/user-login", methods=['POST'])
def login():
    result = Users.query.filter(Users.username == request.form.get('username'), Users.password == request.form.get('password')).one()

    if(result == None):
        return jsonify(
            ok = False,
            code = 404,
            message = "User not Found"
        )
    token = jwt.encode({'username': result.username, 'id': result.id, 'role': result.role}, app.config['SECRET_JWT_KEY'])
    
    cookie = make_response(render_template('profile.html', user = result))
    cookie.set_cookie('username', result.name)
    cookie.set_cookie('token', token)
    
    return cookie

@app.route("/register")
def registerPage(): 
    return render_template('register.html')

@app.route("/register-user", methods=['POST'])
def registerUser():
    newUser = Users(request.form.get('name'), request.form.get('email'), request.form.get('username'), request.form.get('password'), '', None)
    db.session.add(newUser)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/profile/details/")
@app.route("/profile/details")
def userProfilePage(): 
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    user = Users.query.get(jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])['id'])

    if not user:
        return jsonify({'message': 'user not found'})

    return render_template('profile.html', user = user)


@app.route("/profile/details/update", methods=['POST'])
def updateUser():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])

    user = Users.query.get(decodedInfos['id'])
    user.name = request.form.get('name') or user.name
    
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('userProfilePage'))

@app.route("/profile/details/delete", methods=['POST'])
def deleteUser():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

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