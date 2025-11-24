# Temporary test users store for development
import bcrypt

# Create a test user with hashed password
test_password = "test123"
password_bytes = test_password.encode('utf-8')
hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

TEST_USERS = {
    "test@example.com": {
        "id": "test-user-id",
        "name": "Test User",
        "email": "test@example.com", 
        "password": hashed_password,
        "auth_provider": "email",
        "avatar_url": None
    }
}

async def get_test_user(email):
    """Get test user from memory store"""
    return TEST_USERS.get(email)

async def create_test_user(user_data):
    """Create test user in memory store"""
    user_id = f"user-{len(TEST_USERS) + 1}"
    password_bytes = user_data["password"].encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
    
    TEST_USERS[user_data["email"]] = {
        "id": user_id,
        "name": user_data["name"],
        "email": user_data["email"],
        "password": hashed_password,
        "auth_provider": "email",
        "avatar_url": None
    }
    
    return TEST_USERS[user_data["email"]]