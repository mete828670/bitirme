import pyodbc

# Replace with your actual SQL Server UID and PWD
UID = 'sa'  # or your SQL Server user
PWD = 'MeTe14531915.'  # replace with your actual password

try:
    # Establish a connection to MSSQL Server with autocommit enabled
    conn = pyodbc.connect(f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER=localhost;UID={UID};PWD={PWD};TrustServerCertificate=yes', autocommit=True)
    cursor = conn.cursor()
    # Execute the CREATE DATABASE command
    cursor.execute("IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'FileSharingDB') CREATE DATABASE FileSharingDB;")
    cursor.close()
    conn.close()
    print("Database created successfully or already exists.")
except pyodbc.Error as e:
    print(f"Error creating database: {e}")

