from flask import Flask
from flask_cors import CORS, cross_origin
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app =  Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

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

if __name__ == "__main__":
    app.run()