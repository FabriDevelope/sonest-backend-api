from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_super_secreta'

# Conexión MongoDB
MONGO_URI = "mongodb+srv://sonestadm:99oHTTgvK7FnYTZ4@db-sonest-user.lreknik.mongodb.net/?retryWrites=true&w=majority&appName=DB-Sonest-User"
client = MongoClient(MONGO_URI)
db = client["sonest_db"]
users_col = db["users"]

bcrypt = Bcrypt(app)

# Decorador para rutas protegidas con JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # El token debe venir en headers 'x-access-token'
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_col.find_one({"email": data['email']})
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    nombre = data.get('nombre')
    password = data.get('password')

    if users_col.find_one({"email": email}):
        return jsonify({'message': 'User already exists'}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

    user = {
        "email": email,
        "nombre": nombre,
        "password": hashed_pw,
        "rol": "cliente",
        "servicios": []
    }
    users_col.insert_one(user)

    return jsonify({'message': 'User created successfully'}), 201

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if bcrypt.check_password_hash(user['password'], password):
        token = jwt.encode({
            'email': user['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401

# Dashboard protegido
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
    user_data = {
        "email": current_user['email'],
        "nombre": current_user['nombre'],
        "servicios": current_user.get('servicios', [])
    }
    return jsonify(user_data)

if __name__ == '__main__':
    app.run(debug=True)
