from app.storage import db

# Test table creation
db.create_users_table()

# Test user registration
ok, msg = db.register_user("test@example.com", "haziq", "12345")
print("Register:", ok, msg)

# Test login
ok, msg = db.verify_login("test@example.com", "12345")
print("Login:", ok, msg)
