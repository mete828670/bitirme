import pyodbc
import bcrypt

# Replace with your actual SQL Server UID and PWD
UID = 'sa'  # or your SQL Server user
PWD = 'MeTe14531915.'  # replace with your actual password

# Function to hash a password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

try:
    # Establish a connection to MSSQL Server with autocommit enabled
    conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER=localhost;UID={UID};PWD={PWD};TrustServerCertificate=yes', autocommit=True)
    cursor = conn.cursor()
    # Execute the CREATE DATABASE command if it doesn't exist
    cursor.execute("IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'FileSharingDB') CREATE DATABASE FileSharingDB;")
    cursor.close()
    conn.close()
    print("Database created successfully or already exists.")
except pyodbc.Error as e:
    print(f"Error creating database: {e}")

try:
    # Connect to the new database
    conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER=localhost;DATABASE=FileSharingDB;UID={UID};PWD={PWD};TrustServerCertificate=yes')
    cursor = conn.cursor()

    # Check if the User table exists
    cursor.execute("SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'User'")
    table_exists = cursor.fetchone()

    if table_exists:
        # Alter the User table if it exists to change the password column to NVARCHAR(MAX)
        cursor.execute("ALTER TABLE [User] ALTER COLUMN password NVARCHAR(MAX)")
    else:
        # Create the User table with square brackets around the table name
        cursor.execute('''
            CREATE TABLE [User] (
                userID INT PRIMARY KEY IDENTITY(1,1),
                nickname NVARCHAR(50),
                password NVARCHAR(MAX),  -- Use MAX to store bcrypt hash
                email NVARCHAR(50),
                PublicKey NVARCHAR(MAX)
            );
        ''')
    conn.commit()

    # Retrieve existing users' data
    cursor.execute("SELECT userID, nickname, password, email, PublicKey FROM [User]")
    users = cursor.fetchall()

    # Hash the existing passwords and update the database
    for user in users:
        userID, nickname, old_password, email, public_key = user
        new_hashed_password = hash_password(old_password)
        cursor.execute("UPDATE [User] SET password = ? WHERE userID = ?", (new_hashed_password, userID))

    conn.commit()

    # Close the connection
    cursor.close()
    conn.close()
    print("Table created/updated and data inserted/updated successfully.")
except pyodbc.Error as e:
    print(f"Error connecting to database or creating table/inserting data: {e}")

