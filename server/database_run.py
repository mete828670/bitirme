from flask import Flask, request, jsonify, make_response
from flask_restful import Api
import pyodbc
import bcrypt
import traceback
from flask_cors import CORS
import secrets
import time
import redis
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
CORS(app)
api = Api(app)

# Replace with your actual SQL Server UID and PWD
UID = 'sa'
PWD = 'MeTe14531915.'
SERVER = '192.168.1.101,1435'

# Initialize Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())


def generate_nonce():
    return secrets.token_hex(16)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        nickname = data['nickname']
        email = data['email']
        password = data['password']
        public_key = data['public_key']

        # Connect to the database
        conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={SERVER};DATABASE=FileSharingDB;UID={UID};PWD={PWD};TrustServerCertificate=yes')
        cursor = conn.cursor()

        # Check if the username or email already exists
        cursor.execute("SELECT COUNT(*) FROM [User] WHERE nickname = ?", nickname)
        if cursor.fetchone()[0] > 0:
            return make_response(jsonify({'error': 'Username already exists'}), 400)

        cursor.execute("SELECT COUNT(*) FROM [User] WHERE email = ?", email)
        if cursor.fetchone()[0] > 0:
            return make_response(jsonify({'error': 'Email already exists'}), 400)

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the database
        cursor.execute("INSERT INTO [User] (nickname, password, email, PublicKey) VALUES (?, ?, ?, ?)", 
                       (nickname, hashed_password.decode('utf-8'), email, public_key))
        conn.commit()
        cursor.close()
        conn.close()

        return make_response(jsonify({'message': 'User registered successfully'}), 200)
    except pyodbc.Error as e:
        print("Database error:", e)
        traceback.print_exc()
        return make_response(jsonify({'error': str(e)}), 500)
    except Exception as e:
        print("Unexpected error:", e)
        traceback.print_exc()
        return make_response(jsonify({'error': str(e)}), 500)

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    try:
        data = request.get_json()
        username = data['username']
        session_token = data['session_token']
        signed_nonce = bytes.fromhex(data['signed_nonce'])

        user_session = redis_client.hgetall(username)
        if user_session and user_session.get(b'session_token').decode() == session_token:
            if user_session.get(b'ip').decode() != request.remote_addr:
                return make_response(jsonify({'error': 'Invalid IP address'}), 403)

            public_key_pem = user_session.get(b'public_key').decode().encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key_pem)

            try:
                public_key.verify(
                    signed_nonce,
                    user_session.get(b'nonce').decode().encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                new_nonce = generate_nonce()
                redis_client.hset(username, mapping={
                    'nonce': new_nonce,
                    'last_seen': time.time()
                })
                redis_client.sadd('online_users', username)
                return make_response(jsonify({'nonce': new_nonce}), 200)
            except Exception as e:
                print("Nonce signature verification failed:", e)
                return make_response(jsonify({'error': 'Invalid nonce signature'}), 403)
        else:
            return make_response(jsonify({'error': 'Invalid session token'}), 403)
    except Exception as e:
        print("Heartbeat processing failed:", e)
        return make_response(jsonify({'error': str(e)}), 500)



@app.route('/online_users', methods=['GET'])
def get_online_users():
    try:
        online_users = list(redis_client.smembers('online_users'))
        online_users = [user.decode('utf-8') for user in online_users]
        return jsonify(online_users)
    except Exception as e:
        return make_response(jsonify({'error': str(e)}), 500)

@app.route('/authenticate', methods=['POST'])
def authenticate():
    try:
        data = request.get_json()
        username = data['username']
        timestamp = data['timestamp']
        nonce = data['nonce']
        signature = bytes.fromhex(data['signature'])

        # Connect to the database
        conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={SERVER};DATABASE=FileSharingDB;UID={UID};PWD={PWD};TrustServerCertificate=yes')
        cursor = conn.cursor()
        cursor.execute("SELECT PublicKey FROM [User] WHERE nickname = ?", username)
        row = cursor.fetchone()
        conn.close()

        if row:
            public_key_pem = row[0].encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key_pem)

            data_to_verify = username + timestamp + nonce
            try:
                public_key.verify(
                    signature,
                    data_to_verify.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                session_token = secrets.token_hex(16)
                new_nonce = generate_nonce()
                redis_client.hset(username, mapping={
                    'session_token': session_token,
                    'nonce': new_nonce,
                    'last_seen': time.time(),
                    'ip': request.remote_addr,
                    'public_key': row[0]
                })
                return make_response(jsonify({'session_token': session_token, 'nonce': new_nonce}), 200)
            except Exception as e:
                return make_response(jsonify({'error': 'Invalid signature'}), 403)
        else:
            return make_response(jsonify({'error': 'User not found'}), 404)
    except Exception as e:
        return make_response(jsonify({'error': str(e)}), 500)

@app.route('/database', methods=['GET'])
def get_database():
    try:
        conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={SERVER};DATABASE=FileSharingDB;UID={UID};PWD={PWD};TrustServerCertificate=yes')
        cursor = conn.cursor()
        cursor.execute("SELECT nickname, email, PublicKey FROM [User]")
        rows = cursor.fetchall()
        conn.close()

        data = []
        for row in rows:
            data.append({
                'nickname': row[0],
                'email': row[1],
                'public_key': row[2]
            })

        return jsonify(data)
    except Exception as e:
        return str(e), 500

def update_user_status():
    while True:
        current_time = time.time()
        for user in redis_client.smembers('online_users'):
            user = user.decode('utf-8')
            last_seen = float(redis_client.hget(user, 'last_seen'))
            if current_time - last_seen > 30:
                redis_client.srem('online_users', user)
        time.sleep(10)

# Start the status update thread
import threading
status_thread = threading.Thread(target=update_user_status)
status_thread.daemon = True
status_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

