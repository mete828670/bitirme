from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource
import pyodbc
import bcrypt
import traceback  # For detailed error logging
from flask_cors import CORS  # Import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS
api = Api(app)

# Replace with your actual SQL Server UID and PWD
UID = 'sa'  # or your SQL Server user
PWD = 'MeTe14531915.'  # replace with your actual password
SERVER = '192.168.1.101,1435'  # Use the IP address and port of your SQL Server

class Register(Resource):
    def post(self):
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
            traceback.print_exc()  # Print the detailed error traceback
            return make_response(jsonify({'error': str(e)}), 500)
        except Exception as e:
            print("Unexpected error:", e)
            traceback.print_exc()  # Print the detailed error traceback
            return make_response(jsonify({'error': str(e)}), 500)

api.add_resource(Register, '/register')

@app.route('/heartbeat', methods=['GET'])
def heartbeat():
    return "OK", 200

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

