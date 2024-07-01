from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource
import pyodbc
import bcrypt
import traceback  # Add this import for detailed error logging

app = Flask(__name__)
api = Api(app)

# Replace with your actual SQL Server UID and PWD
UID = 'sa'  # or your SQL Server user
PWD = 'MeTe14531915.'  # replace with your actual password
SERVER = '192.168.1.101,1435'  # Use the IP address of your SQL Server with the specified port

class Register(Resource):
    def post(self):
        try:
            data = request.get_json()
            nickname = data['nickname']
            email = data['email']
            password = data['password']
            public_key = data['public_key']

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Connect to the database
            conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={SERVER};DATABASE=FileSharingDB;UID={UID};PWD={PWD};TrustServerCertificate=yes')
            cursor = conn.cursor()

            # Insert the new user into the database
            cursor.execute("INSERT INTO [User] (nickname, password, email, PublicKey) VALUES (?, ?, ?, ?)", (nickname, hashed_password.decode('utf-8'), email, public_key))
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

