from flask import Flask, make_response
from markupsafe import escape
from flask import render_template
from flask import request
from flask_sqlalchemy import SQLAlchemy
from flask import redirect
from flask import url_for
from flask import jsonify

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Luis_147147@localhost:3306/toledo_ecommerce'
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

    def __init__(this, name, email, username, password, salt, role, shops_id):
        this.name = name
        this.email = email
        this.username = username
        this.password = password
        this.salt = salt
        this.role = role
        this.shops_id = shops_id

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

@app.route("/")
def index():
    return render_template('home.html', username=request.cookies.get('username'), users = Users.query.all())

@app.route("/login")
def loginPage():
    return render_template('login.html')

@app.route("/user-login", methods=['POST'])
def login():
    result = Users.query.filter(Users.username == request.form.get('username'), Users.password == request.form.get('password')).first()

    if(result == None):
        return jsonify(
            ok = False,
            code = 404,
            message = "User not Found"
        )

    return result.as_dict()

@app.route("/register")
def registerPage(): 
    return render_template('register.html')

@app.route("/register-user", methods=['POST'])
def registerUser():
    newUser = Users(request.form.get('name'), request.form.get('email'), request.form.get('username'), request.form.get('password'), '', '', None)
    db.session.add(newUser)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/profile/details/")
@app.route("/profile/details")
def userProfilePage(): 
    return render_template('profile.html', username=request.cookies.get('username'))

@app.route("/shop")
def shopPage():
    return render_template('shops.html')

@app.route("/shop/register")
def registerShopPage(): 
    return render_template('registerShop.html')

@app.route("/shop/edit")
def updateShopPage():
    return render_template('editShop.html')

@app.route("/shop/report")
def reportsSalesShopPage():
    return render_template('reportSales.html')

@app.route("/product/<product_id>")
def productDetailPage():
    return render_template('product.html')

if __name__ == 'main':
    db.create_all()