from flask import Flask, make_response
from markupsafe import escape
from flask import render_template
from flask import request
from flask_sqlalchemy import SQLAlchemy
from flask import redirect
from flask import url_for

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Luis_147147@localhost:3306/toledo_ecommerce'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Users(db.Model): 
    id = db.Column('id', db.Integer, primary_key = True)
    name = db.Column('name', db.String(256))
    email = db.Column('email', db.String(256))
    password = db.Column('password', db.String(256))
    salt = db.Column('salt', db.String(256))
    role = db.Column('role', db.String(256))
    shops_id = db.Column('shops_id', db.Integer)

    def __init__(this, name, email, password, salt, role, shops_id):
        this.name = name
        this.email = email
        this.password = password
        this.salt = salt
        this.role = role
        this.shops_id = shops_id

@app.route("/")
def index():
    return render_template('home.html', username=request.cookies.get('username'), users = Users.query.all())

@app.route("/register")
def register(): 
    return render_template('register.html')

@app.route("/register-user", methods=['POST'])
def registerUser():
    newUser = Users(request.form.get('name'), request.form.get('email'), request.form.get('password'), '', '', None)
    db.session.add(newUser)
    db.session.commit()

    return redirect(url_for('index'))

@app.route("/profile/<username>")
def username(username):
    cookie = make_response(f"""
        <div>
            <span>
                <b>Hello {username} - <a href='/'>Back to Home</a></b>
            </span>
        </div>
    """)

    cookie.set_cookie('username', username)
    return cookie

@app.route("/profile/details/")
@app.route("/profile/details")
def userProfile(): 
    return render_template('profile.html', username=request.cookies.get('username'))

@app.route("/shop")
def shop():
    return render_template('shops.html')

@app.route("/shop/register")
def registerShop(): 
    return render_template('registerShop.html')

@app.route("/shop/edit")
def updateShop():
    return render_template('editShop.html')

@app.route("/shop/report")
def reportsSalesShop():
    return render_template('reportSales.html')

@app.route("/product/<product_id>")
def productDetail():
    return render_template('product.html')

if __name__ == 'main':
    db.create_all()