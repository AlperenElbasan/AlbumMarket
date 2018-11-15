from flask import Flask, render_template, request, make_response, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import jwt
import json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'MainDatabase.db')
app.config['SECRET_KEY'] = 'alel-berk'
app.config['ALBUMS_PHOTO'] = 'static/albums'

db = SQLAlchemy(app)
ma = Marshmallow(app)


class Customer(db.Model):
    username = db.Column(db.String(20), primary_key=True)
    gsm = db.Column(db.CHAR(4))
    email = db.Column(db.String(30), unique=True, nullable=False)
    address = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(20), nullable=False)

    def __init__(self, username, gsm, email, address, password):
        self.username = username
        self.gsm = gsm
        self.email = email
        self.address = address
        self.password = password


class Album(db.Model):
    artist = db.Column(db.String(30), nullable=False)
    album_name = db.Column(db.String(30), primary_key=True)
    year = db.Column(db.String(4))
    cost = db.Column(db.Float, nullable=False)
    genre = db.Column(db.String(20))
    rating_avg = db.Column(db.String(4))
    producer_name = db.Column(db.String(30), db.ForeignKey('producer.producer_name'), nullable=False)

    def __init__(self, artist, album_name, year, cost, genre, producer_name):
        self.artist = artist
        self.album_name = album_name
        self.year = year
        self.cost = cost
        self.genre = genre
        self.producer_name = producer_name


class AlbumSchema(ma.Schema):
    class Meta:
        fields = ('artist', 'album_name', 'year', 'cost', 'rating_avg', 'producer_name')


album_schema = AlbumSchema()
albums_schema = AlbumSchema(many=True)


class Producer(db.Model):
    producer_name = db.Column(db.String(30), primary_key=True)

    def __init__(self, producer_name):
        self.producer_name = producer_name


class Buy(db.Model):
    buy_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, db.ForeignKey('customer.username'), nullable=False)
    album_name = db.Column(db.String(30), db.ForeignKey('album.album_name'), nullable=False)

    def __init__(self, username, album_name):
        self.username = username
        self.album_name = album_name


class Rate(db.Model):
    rate_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), db.ForeignKey('customer.username'), nullable=False)
    album_name = db.Column(db.String(30), db.ForeignKey('album.album_name'), nullable=False)
    comment = db.Column(db.String(100))
    rate = db.Column(db.Integer)

    def __init__(self, username, album_name, comment, rate):
        self.username = username
        self.album_name = album_name
        self.comment = comment
        self.rate = rate


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'token' in request.cookies:
            token = request.cookies.get('token')

        if not token:
            return make_response(redirect("/login"))

        current_user = validate_token(token)

        if current_user is None:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


def validate_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = Customer.query.filter_by(username=data['username']).first()
        return current_user
    except Exception as e:
        print("print")
        print(str(e))
        return None


@app.route('/', methods=["GET"])
@token_required
def get_page(id):
    token = request.cookies.get('token')
    if token is None:
        return make_response(redirect("/login"))
    elif validate_token(token) is None:
        return make_response("Token is invalid", 401)
    else:
        return get_home_page()


@app.route("/home")
@token_required
def get_home_page(id):
    all_albums = Album.query.all()
    dumped_albums = albums_schema.dumps(all_albums)
    result_albums = json.loads(dumped_albums.data)
    return render_template("homepage.html", albums=result_albums)


@app.route("/login", methods=["GET"])
def get_login():
    return render_template("login.html")


@app.route("/register", methods=["GET"])
def get_register():
    return render_template("register.html")


@app.route("/users/signup", methods=["POST"])
def post_register():
    data = request.json
    username = data['username']
    gsm = data['gsm']
    email = data['email']
    address = data['address']
    password = data['password']

    if not username or not email or not address or not password:
        return make_response('Missing attribute', 401)

    hashed_password = generate_password_hash(password, method="sha256")
    new_customer = Customer(username, gsm, email, address, hashed_password)

    db.session.add(new_customer)
    db.session.commit()

    return render_template("login.html")


@app.route("/users/signin", methods=["POST"])
def post_login():
    data = request.json
    username = data['username']
    password = data['password']

    print(username + ", "+ password)
    if not username or not password:
        return make_response('Enter values please', 401)

    user = Customer.query.filter_by(username=username).first()
    if not user:
        return make_response('Invalid user', 401)
    if check_password_hash(user.password, password):
        token = jwt.encode(
            {'username': user.username},
            app.config['SECRET_KEY']
        )
        out = jsonify(success=True)
        out.set_cookie('token', token)
        return out
    return make_response('Password didn\'t match', 401)


if __name__ == '__main__':
    app.run(debug=True)

