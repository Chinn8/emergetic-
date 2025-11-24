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

class ChatMessage(BaseModel):
    message: str
    chat_id: str = None

@app.get("/")
async def root():
    return {"message": "Pleader.ai backend is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

def create_token(user_id: str):
    """Create JWT token for user"""
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + JWT_EXPIRATION
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def verify_token(token: str):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("user_id")
    except jwt.InvalidTokenError:
        return None

@app.post("/api/auth/signup")
async def signup(user: UserCreate):
    """Register new user"""
    if user.email in USERS:
        raise HTTPException(status_code=409, detail="Email already registered")
    
    # Hash password
    password_bytes = user.password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # Create user
    user_id = str(uuid.uuid4())
    USERS[user.email] = {
        "id": user_id,
        "name": user.name,
        "email": user.email,
        "password": hashed_password.decode('utf-8'),
        "created_at": datetime.utcnow()
    }
    
    # Create token
    token = create_token(user_id)
    
    return {
        "message": "User created successfully",
        "token": token,
        "user": {
            "id": user_id,
            "name": user.name,
            "email": user.email,
            "avatar_url": None
        }
    }

@app.post("/api/auth/login")
async def login(credentials: UserLogin):
    """Login user"""
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

# Chat endpoints
CHATS = {}  # In-memory chat storage

@app.post("/api/chat/send")
async def send_message(message_data: ChatMessage, authorization: str = Header(None)):
    """Send a chat message and get AI response"""
    print(f"Received chat request: {message_data}")
    print(f"Authorization header: {authorization}")
    
    # Verify user authentication
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
        
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    try:
        token = authorization.split(" ")[1]
        user_id = verify_token(token)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Token verification error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Create or get chat
    chat_id = message_data.chat_id or str(uuid.uuid4())
    
    if chat_id not in CHATS:
        CHATS[chat_id] = {
            "id": chat_id,
            "user_id": user_id,
            "messages": [],
            "created_at": datetime.utcnow(),
            "title": message_data.message[:50] + "..." if len(message_data.message) > 50 else message_data.message
        }
    
    # Add user message
    user_message = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": message_data.message,
        "timestamp": datetime.utcnow()
    }
    
    CHATS[chat_id]["messages"].append(user_message)
    
    # Generate AI response (mock response for now)
    ai_response = f"Thank you for your message: '{message_data.message}'. This is a mock AI response. The backend is working correctly!"
    
    ai_message = {
        "id": str(uuid.uuid4()),
        "role": "assistant", 
        "content": ai_response,
        "timestamp": datetime.utcnow()
    }
    
    CHATS[chat_id]["messages"].append(ai_message)
    
    return {
        "success": True,
        "chat_id": chat_id,
        "message": ai_message,
        "response": ai_response
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)