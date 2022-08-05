from flask import Flask, make_response
from markupsafe import escape
from flask import render_template
from flask import request

app = Flask(__name__)

@app.route("/")
def index():
    return render_template('home.html',  username=request.cookies.get('username'))

@app.route("/register")
def register(): 
    return render_template('register.html')

@app.route("/register-user", methods=['POST'])
def registerUser():
    return request.form

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