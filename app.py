from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from werkzeug.utils import secure_filename
import os
from cryptography.fernet import Fernet

# Initialize Flask app
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a secure key
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'pptx', 'docx', 'xlsx'}

# Initialize JWT
jwt = JWTManager(app)

# Encryption key for URLs (store securely in production)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes

# Home Route
@app.route('/')
def home():
    return "Flask is running!"

# Ops User Login
@app.route('/ops/login', methods=['GET', 'POST'])
def ops_login():
    if request.method == 'GET':
        return "This route requires a POST request with username and password."
    username = request.json.get('username')
    password = request.json.get('password')
    # Dummy authentication (replace with database check)
    if username == 'ops_user' and password == 'password':
        access_token = create_access_token(identity={'role': 'ops_user'})
        return jsonify(access_token=access_token), 200
    return jsonify({'msg': 'Invalid credentials'}), 401

# Upload File (Ops User Only)
@app.route('/ops/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = request.json.get('identity')
    if current_user['role'] != 'ops_user':
        return jsonify({'msg': 'Access denied'}), 403

    if 'file' not in request.files:
        return jsonify({'msg': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'msg': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'msg': 'File uploaded successfully'}), 200

    return jsonify({'msg': 'Invalid file type'}), 400

# Client User Sign Up
@app.route('/client/signup', methods=['POST'])
def client_signup():
    email = request.json.get('email')
    password = request.json.get('password')
    # Dummy user creation (replace with database logic)
    encrypted_url = cipher_suite.encrypt(email.encode()).decode()
    return jsonify({'msg': 'User signed up successfully', 'encrypted_url': encrypted_url}), 201

# Email Verification (Dummy Implementation)
@app.route('/client/verify-email', methods=['POST'])
def verify_email():
    email = request.json.get('email')
    # Dummy email verification logic
    return jsonify({'msg': f'Verification email sent to {email}'}), 200

# Client User Login
@app.route('/client/login', methods=['POST'])
def client_login():
    email = request.json.get('email')
    password = request.json.get('password')
    # Dummy authentication (replace with database check)
    if email == 'client_user@example.com' and password == 'password':
        access_token = create_access_token(identity={'role': 'client_user'})
        return jsonify(access_token=access_token), 200
    return jsonify({'msg': 'Invalid credentials'}), 401

# List All Uploaded Files (Client User Only)
@app.route('/client/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = request.json.get('identity')
    if current_user['role'] != 'client_user':
        return jsonify({'msg': 'Access denied'}), 403

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return jsonify({'files': files}), 200

# Download File (Client User Only)
@app.route('/client/download/<filename>', methods=['GET'])
@jwt_required()
def download_file(filename):
    current_user = request.json.get('identity')
    if current_user['role'] != 'client_user':
        return jsonify({'msg': 'Access denied'}), 403

    try:
        encrypted_filename = cipher_suite.encrypt(filename.encode()).decode()
        return jsonify({'download_url': encrypted_filename}), 200
    except Exception as e:
        return jsonify({'msg': 'Error generating download URL', 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
