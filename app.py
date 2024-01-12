from flask import Flask
from flask_cors import CORS, cross_origin
from flask import jsonify
from flask import request
from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies
from datetime import timedelta
from flask_jwt_extended import jwt_required, create_access_token
from werkzeug.security import check_password_hash, generate_password_hash

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
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)
app.config["JWT_TOKEN_LOCATION"] = ["headers"]


# create tables
class Customer(db.Model):
    __tablename__ = 'customer'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    zipcode = db.Column(db.String(10))


#hello world route
@app.route('/', methods=['GET'])
@cross_origin()
def index():
    return jsonify({'message': 'Hello World!'})



# create a check_auth route that checks the user's jwt auth token
@app.route("/check_auth", methods=["GET"])
@cross_origin()
@jwt_required()
def check_auth():
    print('checking auth')
    return jsonify({"msg": "You are authenticated"}), 200



# create flask jwt login route using headers
@app.route("/login", methods=["POST"])
@cross_origin()
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    user = Customer.query.filter_by(email=email).first()
    if not user or not (check_password_hash(user.password, password)):
        print('bad credentials')
        return jsonify({"msg":"Invalid email or password"}), 401
    # Generate access token with 10-day expiration
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=0.5))
    return jsonify({"msg":"login successful", "access_token":f"{access_token}"}), 200


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

    new_user = Customer(email=email, password_hash=generate_password_hash(password), zipcode=zipcode, username=username)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201


# Update a customer in the Customer table
@app.route("/customer/<int:customer_id>", methods=["PUT"])
@cross_origin()
@jwt_required
def update_customer(customer_id):
    customer = Customer.query.get(customer_id)
    if customer:
        # Update the customer record with new data
        customer.username = request.json.get("username", customer.username)
        customer.email = request.json.get("email", customer.email)
        customer.password_hash = request.json.get("password", customer.password_hash)
        customer.zipcode = request.json.get("zipcode", customer.zipcode)

        db.session.commit()
        return jsonify({"msg": "Customer updated successfully"}), 200
    else:
        return jsonify({"msg": "Customer not found"}), 404



# Delete a customer from the Customer table
@app.route("/customer/<int:customer_id>", methods=["DELETE"])
@cross_origin()
@jwt_required()
def delete_customer(customer_id):
    customer = Customer.query.get(customer_id)
    if customer:
        db.session.delete(customer)
        db.session.commit()
        return jsonify({"msg": "Customer deleted successfully"}), 200
    else:
        return jsonify({"msg": "Customer not found"}), 404


@app.route("/customer/<int:customer_id>/get_listings", methods=["GET"])
@cross_origin()
@jwt_required()
def get_listings(customer_id):
    print('HERE')
    customer = Customer.query.get(customer_id)
    if customer:
        return jsonify({
      "id": 1,
      "title": "1999 Fender Telecaster",
      "location": "Nashville, TN",
      "lat": 36.1627,
      "long": 86.7816,
      "price": 200.0,
      "imageUrl": "https://picsum.photos/300/200",
      "description":
        "This is a great guitar. I've played it for years and it's never let me down. I'm only selling it because I need the money.",
    },
    {
      "id": 2,
      "title": "1994 Fender Strat",
      "location": "Nashville, TN",
      "lat": 36.1627,
      "long": 86.7816,
      "price": 200.0,
      "imageUrl": "https://picsum.photos/300/200",
      "description":
        "This is a great guitar. I've played it for years and it's never let me down. I'm only selling it because I need the money.",
    }), 200
    else:
        return jsonify({"msg": "Customer not found"}), 404
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)