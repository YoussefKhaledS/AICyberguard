import bcrypt 


def connectToDB(name="DB.db"):
    import sqlite3
    return sqlite3.connect(name, check_same_thread=False)


def init_DB(connection):
    cursor = connection.cursor()
    # users table
    cursor.execute('''
	CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
            isAdmin BOOLEAN NOT NULL DEFAULT FALSE
		)
	''')
    
    connection.commit()


def getUser(connection, username , email = None):
    cursor = connection.cursor()
    query = '''SELECT * FROM users WHERE username = ? OR email = ?'''
    cursor.execute(query, (username, email))
    return cursor.fetchone() 


def addUser(connection, username, email, password):
    cursor = connection.cursor()
    hashedPassword = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    query = '''INSERT INTO users (username , email, password) VALUES (?,?,?)'''
    cursor.execute(query, (username,email, hashedPassword))
    connection.commit()


def makeAmdin(connection, username):
    cursor = connection.cursor()
    query = f'''UPDATE users SET isAdmin = 1 WHERE username = ?'''
    cursor.execute(query, (username,))
    connection.commit()
    

def getAllUsers(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT id, username, email, isAdmin FROM users")
    users = cursor.fetchall()  # Fetch all users from the database
    return users  # Returns a list of tuples (id, username, email, isAdmin)
