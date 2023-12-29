from flask import Flask
from flask_cors import CORS, cross_origin
from flask import jsonify
from flask import request
from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app =  Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

#localhost DB
app.config.update(
    SECRET_KEY = 'Halothedog123',
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:Halothedog123@localhost/openbackline',
    SQLALCHEMY_TRACK_MODIFICATIONS = False
)

db = SQLAlchemy(app)

print(db)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

# create tables
class Customer(db.Model):
    __tablename__ = 'customer'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    zipcode = db.Column(db.String(10))

    # def __init__(self, email, password_hash, zipcode, username):
    #     self.id = id
    #     self.email = email
    #     self.password_hash = password_hash
    #     self.zipcode = zipcode
    #     self.username = username
    #     def __repr__(self):
    #         return '<User %r>' % self.email

#hello world route
@app.route('/', methods=['GET'])
@cross_origin()
def index():
    return jsonify({'message': 'Hello World!'})

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
@cross_origin()
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if email != "test@test.com" or password != "test":
        print('bad email or password')
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=email)
    print(access_token)
    return jsonify(access_token=access_token)

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/check_auth", methods=["GET"])
@cross_origin()
@jwt_required()
def check_auth():
    # Access the identity of the current user with get_jwt_identity
    print('check_auth')
    try:
        current_user = get_jwt_identity()
    except Exception as e:
        print(e)
        return jsonify({"msg": "Bad username or password"}), 401
    print(current_user)
    return jsonify(logged_in_as=current_user), 200


@app.route("/signup", methods=["POST"])
@cross_origin()
def signup():
    print(request)
    print('Signed up!')
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    zipcode = request.json.get("zipcode", None)
    username = request.json.get("username", None)

    if not email or not password or not zipcode:
        return jsonify({"msg": "Missing required fields"}), 400

    existing_user = Customer.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"msg": "User already exists"}), 409

    new_user = Customer(email=email, password_hash=password, zipcode=zipcode, username=username)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)