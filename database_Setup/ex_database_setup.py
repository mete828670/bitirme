import pyodbc

# Replace with your actual SQL Server UID and PWD
UID = 'sa'  # or your SQL Server user
PWD = 'MeTe14531915.'  # replace with your actual password

try:
    # Connect to the new database
    conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER=localhost;DATABASE=FileSharingDB;UID={UID};PWD={PWD};TrustServerCertificate=yes')
    cursor = conn.cursor()

    # Create the User table with square brackets around the table name
    cursor.execute('''
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'User')
        CREATE TABLE [User] (
            userID INT PRIMARY KEY IDENTITY(1,1),
            nickname NVARCHAR(50),
            password NVARCHAR(50),
            email NVARCHAR(50),
            PublicKey NVARCHAR(MAX)
        );
    ''')
    conn.commit()

    # Insert example entries
    users = [
        ('Node1', 'password1', 'node1@example.com', '/home/mete/PycharmProjects/pythonProject/Node1_public_key.pem'),
        ('Node2', 'password2', 'node2@example.com', '/home/mete/PycharmProjects/pythonProject/Node2_public_key.pem'),
        ('Node3', 'password3', 'node3@example.com', '/home/mete/PycharmProjects/pythonProject/Node3_public_key.pem'),
        ('Node4', 'password4', 'node4@example.com', '/home/mete/PycharmProjects/pythonProject/Node4_public_key.pem'),
        ('Node5', 'password5', 'node5@example.com', '/home/mete/PycharmProjects/pythonProject/Node5_public_key.pem'),
        ('mete', 'mete', 'mete@mete.mete', '/home/mete/PycharmProjects/pythonProject/mete_public_key.pem')
    ]

    for user in users:
        cursor.execute("INSERT INTO [User] (nickname, password, email, PublicKey) VALUES (?, ?, ?, ?)", user)
    conn.commit()

    # Close the connection
    cursor.close()
    conn.close()
    print("Table created and data inserted successfully.")
except pyodbc.Error as e:
    print(f"Error connecting to database or creating table/inserting data: {e}")

