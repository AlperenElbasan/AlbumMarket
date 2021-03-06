from flask import Flask, render_template, request, make_response, redirect, jsonify, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import jwt
import json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import random
import time

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'MainDatabase.db')
app.config['SECRET_KEY'] = 'alel-berk'
app.config['ALBUMS_PHOTO'] = 'static/albums'
app.config['ADMIN_NAME'] = 'Admin'
app.config['ADMIN_PASS'] = 'alperen'

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


class RateSchema(ma.Schema):
    class Meta:
        fields = ('rate_id', 'username', 'album_name', 'comment', 'rate')


rate_schema = RateSchema()
rates_schema = RateSchema(many=True)


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

    all_rates = Rate.query.all()

    for album in all_albums:
        album.rating_avg = get_rate_avg(album, all_rates)

    user = validate_token(request.cookies.get('token'))

    if user.username == app.config['ADMIN_NAME']:
        return render_template("adminaddalbum.html", albums=result_albums)
    else:
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
    print("users")
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


@app.route("/buy/<string:album_name>")
def buy_album(album_name):

    user = validate_token(request.cookies.get('token'))
    new_buy_transaction = Buy(user.username, str(album_name))

    db.session.add(new_buy_transaction)
    db.session.commit()

    random_days = random.randint(2, 9)

    return render_template("buypage.html", random_days=random_days, album_name=album_name)


@app.route("/like/<album_name>", methods=['POST'])
def like_album():
    return make_response("not yet.")


@app.route("/rate/<string:album_name>", methods=['POST'])
@token_required
def rate_album(id, album_name):
    print("rating")
    user = validate_token(request.cookies.get('token'))

    data = request.json
    comment = data['comment']
    rate = data['rate']

    all_rates = Rate.query.all()

    for search_rate in all_rates:
        if album_name == search_rate.album_name:
            print(search_rate.comment + ", " + album_name)
            if user.username == search_rate.username:
                print("IF:" + search_rate.comment)
                db.session.delete(search_rate)
                break

    new_rate = Rate(user.username, album_name, comment, rate)

    db.session.add(new_rate)
    db.session.commit()

    return get_home_page()


@app.route("/search_album/<string:album_name>", methods=['GET'])
@token_required
def search_album(id, album_name):

    album = Album.query.filter_by(album_name=album_name).first()

    message = "No such album is found. Redirected to home page."

    if album is None:
        flash(message)
        print(message)
        return redirect(url_for('get_home_page'))
    else:
        return render_template("album.html", album=album)


@app.route("/album/<string:album_name>", methods=['GET'])
@token_required
def comment_album(id, album_name):
    user = validate_token(request.cookies.get('token'))

    album = Album.query.filter_by(album_name=album_name).first()

    all_rates = Rate.query.all()
    dumped_rates = rates_schema.dumps(all_rates)
    result_rates = json.loads(dumped_rates.data)

    album.rating_avg = get_rate_avg(album, all_rates)

    return render_template("album.html", album=album, username=user.username, rates=result_rates)


@app.route('/addalbum/', methods=['POST'])
@token_required
def add_album(id):
    user = validate_token(request.cookies.get('token'))
    if user.username != app.config['ADMIN_NAME']:
        return

    data = request.json

    artist = data['artist']
    album_name = data['album_name']
    year = data['year']
    cost = data['cost']
    genre = data['genre']
    producer_name = data['producer_name']

    album = Album(artist, album_name, year, cost, genre, producer_name)

    db.session.add(album)
    db.session.commit()

    return render_template("albumadded.html")


@app.route('/deletealbum/<string:albumname>', methods=['GET'])
@token_required
def delete_album(id,albumname):

    print(albumname)
    user = validate_token(request.cookies.get('token'))
    if user.username != app.config['ADMIN_NAME']:
        return

    db.session.delete(Album.query.filter_by(album_name=albumname).first())
    db.session.commit()

    return get_home_page()


def get_rate_avg(album, all_rates):

    rate_count = 0
    rate_sum = 0
    for rate in all_rates:
        if rate.album_name == album.album_name:
            rate_count += 1
            rate_sum += rate.rate

    if rate_count > 0:
        rate_avg = rate_sum / rate_count
    else:
        rate_avg = 0

    return str(round(rate_avg, 2))


if __name__ == '__main__':
    app.run(debug=True)

