import mysql.connector
import os
import hashlib
import secrets

# MySQL connection config
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "QAS123f@",
    "database": "securechat"
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

def create_users_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

def register_user(email, username, password):
    conn = get_connection()
    cursor = conn.cursor()

    # check if user exists
    cursor.execute("SELECT * FROM users WHERE email=%s OR username=%s", (email, username))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return False, "User/email already exists"

    # generate salt
    salt = secrets.token_bytes(16)
    # hash password
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

    cursor.execute(
        "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
        (email, username, salt, pwd_hash)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return True, "User registered successfully"

def verify_login(email, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row:
        return False, "User not found"
    salt, stored_hash = row
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    if pwd_hash == stored_hash:
        return True, "Login successful"
    return False, "Invalid password"
