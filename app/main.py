from crypt import methods
from operator import or_
from flask import Flask, make_response, abort, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime
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
    address = db.Column('address', db.String(256), nullable = False)
    shopcode = db.Column('shop_code', db.String(256), nullable = False)
    cellphone = db.Column('cellphone', db.String(256), nullable = False)
    products = db.relationship('Adverts', secondary = shops_adverts, lazy = 'subquery', backref = db.backref('shops', lazy = True))
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable = False)

    # Constructor
    def __init__(this, name, user_id, address, shopcode, cellphone):
        this.name = name
        this.user_id = user_id
        this.address = address
        this.shopcode = shopcode
        this.cellphone = cellphone

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Adverts(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256), nullable = False)
    price = db.Column('price', db.Numeric(10, 2), nullable = False)
    category = db.Column('category', db.String(256), nullable = False)
    quantity = db.Column('quantity', db.Integer, nullable = False)
    owner = db.Column('owner', db.Integer, nullable = False)

    # Constructor
    def __init__(this, name, price, quantity, category, owner):
        this.name = name
        this.price = price
        this.quantity = quantity
        this.category = category
        this.owner = owner

    # ToString Method
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Sales(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    product_id = db.Column('product_id', db.Integer, nullable = False)
    owner_id = db.Column('shop_id', db.Integer, nullable = False)
    buyer_id = db.Column('buyer_id', db.Integer, nullable = False)
    created_at = db.Column('created_at', db.DateTime, nullable = False, default = datetime.now())

    # Constructor
    def __init__(this, product_id, owner_id, buyer_id):
        this.product_id = product_id
        this.owner_id = owner_id
        this.buyer_id = buyer_id

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
    adverts_arr = Adverts.query.join(Shops, Shops.id==Adverts.owner).all()

    for x in adverts_arr:
        x.shop_name = db.session.query(Shops.name).filter(Shops.id == x.owner).one_or_none()['name']

    if request.cookies.get('token'):
        user = Users.query.get(jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])['id'])
        return render_template('home.html', role = user.role, username = user.username, token = request.cookies.get('token'), products=adverts_arr)
    else:
        return render_template('home.html', role = None, username = None, token = None, products=adverts_arr)
    

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
    cookie.set_cookie('token', token)
    
    return cookie

@app.route("/register")
def registerPage(): 
    return render_template('register.html')

@app.route("/register-user", methods=['POST'])
def registerUser():
    userValidate = Users.query.filter(or_(Users.email == request.form.get('email'), Users.username == request.form.get('username'))).one_or_none()

    if not userValidate:
        newUser = Users(request.form.get('name'), request.form.get('email'), request.form.get('username'), bcrypt.hashpw(request.form.get('password'), bcrypt.gensalt()))
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
        newShop = Shops(request.form.get('name'), user.id, request.form.get('address'), request.form.get('shopcode'), request.form.get('cellphone'))
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
    Adverts.query.filter(Adverts.owner == shops.id).delete()
    db.session.commit()

    adverts_arr = Adverts.query.join(Shops, Shops.id==Adverts.owner).all()

    for x in adverts_arr:
        x.shop_name = db.session.query(Shops.name).filter(Shops.id == x.owner).one_or_none()['name']

    return redirect(url_for('index'))


@app.route("/shop/create-product", methods=['POST'])
def createProduct():
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    shops = Shops.query.filter(Shops.user_id == decodedInfos['id']).one_or_none()

    product = Adverts(request.form.get('name'), request.form.get('price'), request.form.get('quantity'), request.form.get('category'), shops.id)

    shops.products.append(product)
    db.session.add(shops)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/product/detail/<id>/<edit_flag>")
def productDetailsPage(id, edit_flag):
    return render_template('productPage.html', product = Adverts.query.filter(Adverts.id == id).one_or_none(), edit_flag = edit_flag)

@app.route("/product/favorite/<id>", methods=['POST'])
def favoriteProduct(id):
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    user = Users.query.filter(Users.id == decodedInfos['id']).one_or_none()

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    product = Adverts.query.filter(Adverts.id == id).one_or_none()

    if not product:
        return jokerAction('Not Found', {'title': 'Product not found', 'message': 'product not found in database'})

    for x in user.favs:
        if x.id == product.id:
            return jokerAction('Already Favorite', {'title': 'Product already favorite', 'message': 'product already favorite'})

    user.favs.append(product)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/product/buy/<id>", methods=['POST'])
def buyProduct(id):
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    user = Users.query.filter(Users.id == decodedInfos['id']).one_or_none()

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    product = Adverts.query.filter(Adverts.id == id).one_or_none()

    if not product:
        return jokerAction('Not Found', {'title': 'Product not found', 'message': 'product not found in database'})

    if product.quantity == 0:
        return jokerAction('Product has no Quantity', {'title': 'Product out of stock', 'message': 'product out of stock'})

    sales = Sales(product.id, product.owner, user.id)
    product.quantity -= 1;
    db.session.add(sales)
    db.session.add(product)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/product/delete/<id>", methods=['POST'])
def deleteProduct(id):
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    user = Users.query.filter(Users.id == decodedInfos['id']).one_or_none()

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    product = Adverts.query.filter(Adverts.id == id).one_or_none()

    if not product:
        return jokerAction('Not Found', {'title': 'Product not found', 'message': 'product not found in database'})

    db.session.delete(product)
    Sales.query.filter(Sales.product_id == product.id).delete()
    db.session.commit()

    return redirect(url_for("shopPage"))   

@app.route("/product/edit/<product_id>", methods=['POST'])
def editProduct(product_id):
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    user = Users.query.filter(Users.id == decodedInfos['id']).one_or_none()

    if not user:
        return jokerAction('Not Found', {'title': 'User not found', 'message': 'user not found in database'})

    product = Adverts.query.filter(Adverts.id == product_id).one_or_none()

    if not product:
        return jokerAction('Not Found', {'title': 'Product not found', 'message': 'product not found in database'})

    product.name = request.form.get('name') or product.name
    product.price = request.form.get('price') or product.name
    product.category = request.form.get('category') or product.category
    product.quantity = request.form.get('quantity') or product.quantity
    
    db.session.add(product)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/<type>/report", methods=['POST'])
def reportsSalesPage(type):
    if not checkUser(request.cookies.get('token')):
        return abort(401)

    decodedInfos = jwt.decode(request.cookies.get('token'), app.config['SECRET_JWT_KEY'])
    user = Users.query.filter(Users.id == decodedInfos['id']).one_or_none()

    if type == 'shop':
        shop = Shops.query.filter(Shops.user_id == user.id).one_or_none()
        
        if not shop:
            return jokerAction('Not Found', {'title': 'Report not found', 'message': 'report type not found in database'})

        reports = Sales.query.filter(Sales.owner_id == shop.id).all()

        for x in reports:
            x.product = db.session.query(Adverts.name).filter(Adverts.id == x.product_id).one_or_none()['name']
            x.product_price = db.session.query(Adverts.price).filter(Adverts.id == x.product_id).one_or_none()['price']
            x.owner = db.session.query(Shops.name).filter(Shops.id == x.owner_id).one_or_none()['name']
            x.buyer = db.session.query(Users.name).filter(Users.id == x.buyer_id).one_or_none()['name']
            x.created_at = x.created_at.strftime('%d/%m/%Y')

        return render_template('reportSales.html', type=type, reports=reports)
    elif type == 'user':
        reports = Sales.query.filter(Sales.buyer_id == user.id).all()

        for x in reports:
            x.product = db.session.query(Adverts.name).filter(Adverts.id == x.product_id).one_or_none()['name']
            x.product_price = db.session.query(Adverts.price).filter(Adverts.id == x.product_id).one_or_none()['price']
            x.owner = db.session.query(Shops.name).filter(Shops.id == x.owner_id).one_or_none()['name']
            x.buyer = db.session.query(Users.name).filter(Users.id == x.buyer_id).one_or_none()['name']
            x.created_at = x.created_at.strftime('%d/%m/%Y')

        return render_template('reportSales.html', type=type, reports=reports)
    else:
        return jokerAction('Not Found', {'title': 'Report not found', 'message': 'report type not found in database'})

if __name__ == 'main':
    db.create_all()
    app.run()