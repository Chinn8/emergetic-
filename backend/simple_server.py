from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
from datetime import datetime, timedelta
import uuid

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT configuration
JWT_SECRET = "pleader_ai_jwt_secret_key_2025_secure"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = timedelta(days=7)

# In-memory user store for testing
USERS = {}

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

def create_token(user_id: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + JWT_EXPIRATION,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

@app.get("/")
async def root():
    return {"message": "Pleader.ai API is running"}

@app.post("/api/auth/signup")
async def signup(user_data: UserCreate):
    """Register a new user"""
    # Check if user already exists
    if user_data.email in USERS:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    password_bytes = user_data.password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
    
    # Create user
    user_id = str(uuid.uuid4())
    USERS[user_data.email] = {
        "id": user_id,
        "name": user_data.name,
        "email": user_data.email,
        "password": hashed_password,
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Create token
    token = create_token(user_id)
    
    return {
        "token": token,
        "user": {
            "id": user_id,
            "name": user_data.name,
            "email": user_data.email,
            "avatar_url": None
        }
    }

@app.post("/api/auth/login")
async def login(credentials: UserLogin):
    """Login user"""
    # Check if user exists
    if credentials.email not in USERS:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    user = USERS[credentials.email]
    
    # Verify password
    password_bytes = credentials.password.encode('utf-8')
    stored_password = user["password"].encode('utf-8')
    if not bcrypt.checkpw(password_bytes, stored_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create token
    token = create_token(user["id"])
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "avatar_url": None
        }
    }

# JWT token verification
def verify_token(token: str):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("user_id")
    except jwt.InvalidTokenError:
        return None

# Dependency to get current user from token
async def get_current_user_from_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    user_id = verify_token(token)
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Find user by ID
    for email, user_data in USERS.items():
        if user_data["id"] == user_id:
            return user_data
    
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/auth/me")
async def get_current_user():
    """Get current user info"""
    return {"message": "Authentication endpoint available"}

# Chat endpoints
CHATS = {}  # In-memory chat storage

class ChatMessage(BaseModel):
    message: str
    chat_id: str = None

@app.post("/api/chat/send")
async def send_message(message_data: ChatMessage, authorization: str = Header(None)):
    """Send a chat message and get AI response"""
    # Verify user authentication (simplified)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        token = authorization.split(" ")[1]
        user_id = verify_token(token)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Create or get chat
    chat_id = message_data.chat_id or str(uuid.uuid4())
    
    if chat_id not in CHATS:
        CHATS[chat_id] = {
            "id": chat_id,
            "user_id": user_id,
            "messages": [],
            "created_at": datetime.utcnow().isoformat(),
            "title": message_data.message[:50] + "..." if len(message_data.message) > 50 else message_data.message
        }
    
    # Add user message
    user_message = {
        "id": str(uuid.uuid4()),
        "sender": "user",
        "content": message_data.message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    CHATS[chat_id]["messages"].append(user_message)
    
    # Generate AI response (mock response for now)
    ai_response = f"Thank you for your message: '{message_data.message}'. This is a mock AI response. The backend is working correctly, but the AI integration would need to be configured with proper API keys."
    
    ai_message = {
        "id": str(uuid.uuid4()),
        "sender": "ai",
        "content": ai_response,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    CHATS[chat_id]["messages"].append(ai_message)
    
    return {
        "success": True,
        "chat_id": chat_id,
        "ai_message": ai_message,
        "response": ai_response
    }

@app.get("/api/chat/history")
async def get_chat_history(authorization: str = Header(None)):
    """Get user's chat history"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        token = authorization.split(" ")[1]
        user_id = verify_token(token)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Filter chats by user
    user_chats = []
    for chat_id, chat in CHATS.items():
        if chat["user_id"] == user_id:
            user_chats.append({
                "id": chat_id,
                "title": chat["title"],
                "created_at": chat["created_at"],
                "message_count": len(chat["messages"])
            })
    
    return {"chats": user_chats}

@app.get("/api/chat/{chat_id}")
async def get_chat(chat_id: str, authorization: str = Header(None)):
    """Get specific chat messages"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        token = authorization.split(" ")[1]
        user_id = verify_token(token)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if chat_id not in CHATS:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    chat = CHATS[chat_id]
    if chat["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {
        "id": chat_id,
        "title": chat["title"],
        "messages": chat["messages"],
        "created_at": chat["created_at"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)