# FastAPI Security Features and Van den Berghe's Security Patterns

## Overview

This document maps FastAPI's built-in security features to the authentication patterns from Van den Berghe's security pattern catalogue, showing how to implement each pattern and which additional libraries are needed for complete implementations.

---

## 1. Password-Based Authentication

### Pattern Summary
Subjects authenticate by providing an identifier (username/email) and password. The system verifies the password hash against stored credentials.

### FastAPI Implementation

**Built-in FastAPI Components:**
- `OAuth2PasswordRequestForm` / `OAuth2PasswordRequestFormStrict` - Collects username and password from form data
- `OAuth2PasswordBearer` - Acts as the Enforcer, requiring authentication for endpoints
- `HTTPBasic` / `HTTPBasicCredentials` - Alternative for HTTP Basic authentication

**Pattern Role Mapping:**
- **Subject**: The API client/user
- **Enforcer**: `OAuth2PasswordBearer` dependency
- **Verification Manager + Comparator + Hasher**: Custom implementation (external library needed)
- **Password Store**: Database with external ORM (SQLAlchemy, Tortoise-ORM, etc.)
- **Registrar**: Custom endpoint with password hashing

### Required External Libraries

```python
# Password hashing (Hasher role)
from passlib.context import CryptContext

# Or use bcrypt directly
import bcrypt

# Database (Password Store role)
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

# Or with async support
from tortoise import fields, models
from tortoise.contrib.fastapi import register_tortoise
```

### Complete Implementation Example

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional

# Password hashing (Hasher + Comparator)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme (Enforcer)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# Mock database (Password Store)
fake_users_db = {
    "john": {
        "username": "john",
        "hashed_password": pwd_context.hash("secret"),
        "email": "john@example.com"
    }
}

class User(BaseModel):
    username: str
    email: Optional[str] = None

# Verification Manager functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Comparator role"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hasher role"""
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    """Verification Manager role"""
    user = fake_users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

# Login endpoint (Registrar for tokens)
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Subject registration - issues tokens after password verification"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Return token (typically JWT for stateless auth)
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint (demonstrates Enforcer)
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    """Enforcer ensures authentication before access"""
    # Token verification would happen here
    return {"username": "john"}

# Registration endpoint (Registrar for new users)
@app.post("/register")
async def register_user(username: str, password: str, email: str):
    """Registrar role - adds new credentials to Password Store"""
    if username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Hash password before storage
    hashed_password = get_password_hash(password)
    
    # Store in database (Password Store)
    fake_users_db[username] = {
        "username": username,
        "hashed_password": hashed_password,
        "email": email
    }
    return {"message": "User created successfully"}
```

### Pattern Considerations Met

✅ **Password hashing**: Uses Passlib/bcrypt for secure hashing  
✅ **Salt**: Automatically handled by bcrypt  
✅ **Pepper**: Can be added via encryption layer (see below)  
✅ **Password policy**: Implement with custom validators  
✅ **Error messages**: Generic messages prevent user enumeration  

### Adding Pepper Support

```python
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, pepper_key: bytes):
        """Pepper Store and Encrypter roles"""
        self.cipher = Fernet(pepper_key)
        self.pwd_context = CryptContext(schemes=["bcrypt"])
    
    def hash_and_encrypt(self, password: str) -> bytes:
        """Hash with salt, then encrypt with pepper"""
        hashed = self.pwd_context.hash(password)
        encrypted = self.cipher.encrypt(hashed.encode())
        return encrypted
    
    def decrypt_and_verify(self, password: str, stored_pwd: bytes) -> bool:
        """Decrypt, then verify password"""
        try:
            decrypted = self.cipher.decrypt(stored_pwd).decode()
            return self.pwd_context.verify(password, decrypted)
        except:
            return False
```

---

## 2. Verifiable Token-Based Authentication (JWT)

### Pattern Summary
Subjects authenticate using self-contained tokens (JWTs) that include identity information and are cryptographically signed. The system verifies token integrity without storing them.

### FastAPI Implementation

**Built-in FastAPI Components:**
- `HTTPBearer` - Enforcer for Bearer token authentication
- `OAuth2PasswordBearer` - Can also be used as Enforcer

**Pattern Role Mapping:**
- **Subject**: API client with JWT
- **Enforcer**: `HTTPBearer` or `OAuth2PasswordBearer` dependency
- **Verifier + Cryptographer**: JWT library (python-jose, PyJWT)
- **Key Manager**: Custom implementation or secrets management
- **Registrar**: Login endpoint that issues JWTs
- **Token Generator**: JWT encoding function

### Required External Libraries

```python
# JWT handling (Verifier, Cryptographer, Token Generator)
from jose import JWTError, jwt
# Alternative: import jwt as PyJWT

# For key management
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
```

### Complete Implementation Example

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# Key Manager configuration
SECRET_KEY = "your-secret-key-keep-it-secret"  # For HMAC (MAC-based)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# For digital signatures (asymmetric), use RS256:
# ALGORITHM = "RS256"
# PRIVATE_KEY = load_private_key()
# PUBLIC_KEY = load_public_key()

security = HTTPBearer()  # Enforcer

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    disabled: Optional[bool] = False

# Token Generator role
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Generates verifiable token with:
    - Principal (username)
    - Expiration date
    - Signature for integrity
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    
    # Cryptographer role - sign the token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Verifier role
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verifies:
    1. Token signature (integrity)
    2. Token expiration
    3. Extracts principal
    """
    token = credentials.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Cryptographer role - verify signature and decode
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
        
        token_data = TokenData(username=username)
        
    except JWTError:
        raise credentials_exception
    
    return token_data

# Login endpoint (Registrar)
@app.post("/token")
async def login_for_token(username: str, password: str):
    """Issues new JWT token after authentication"""
    # Authenticate user (typically with password-based auth)
    user = authenticate_user(username, password)  # From previous pattern
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Generate token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint with Enforcer
@app.get("/users/me")
async def read_current_user(token_data: TokenData = Depends(verify_token)):
    """Enforcer ensures valid JWT before access"""
    # Principal is now verified and available
    return {"username": token_data.username}

# Example with token refresh
@app.post("/token/refresh")
async def refresh_token(token_data: TokenData = Depends(verify_token)):
    """Issues new token for authenticated user"""
    new_token = create_access_token(data={"sub": token_data.username})
    return {"access_token": new_token, "token_type": "bearer"}
```

### Using Digital Signatures (RS256) Instead of MAC (HS256)

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Key Manager - generate keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize for storage
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Use RS256 algorithm
ALGORITHM = "RS256"

def create_access_token_rs256(data: dict):
    """Token Generator with digital signature"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    
    # Sign with private key
    encoded_jwt = jwt.encode(to_encode, private_pem, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token_rs256(token: str):
    """Verifier with digital signature verification"""
    try:
        # Verify with public key
        payload = jwt.decode(token, public_pem, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### Pattern Considerations Met

✅ **Token integrity**: JWT signature ensures no tampering  
✅ **Token lifetime**: `exp` claim enforces expiration  
✅ **Self-contained**: Principal in token (no server-side storage)  
✅ **Stateless**: No session storage needed  
⚠️ **Token revocation**: Requires additional implementation (see below)

### Adding Token Revocation Support

```python
from typing import Set
from datetime import datetime

# Token Manager for revoked tokens
class TokenBlacklist:
    """Tracks revoked but not yet expired tokens"""
    def __init__(self):
        self.revoked_tokens: Set[str] = set()
    
    def revoke(self, token: str):
        self.revoked_tokens.add(token)
    
    def is_revoked(self, token: str) -> bool:
        return token in self.revoked_tokens
    
    def cleanup_expired(self, current_time: datetime):
        """Remove expired tokens from blacklist"""
        # Implementation would decode tokens and check exp
        pass

blacklist = TokenBlacklist()

def verify_token_with_revocation(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Enhanced verifier checking revocation list"""
    token = credentials.credentials
    
    # Check blacklist first
    if blacklist.is_revoked(token):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    
    # Then verify normally
    return verify_token(credentials)

@app.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Revoke current token"""
    token = credentials.credentials
    blacklist.revoke(token)
    return {"message": "Successfully logged out"}
```

---

## 3. Opaque Token-Based Authentication

### Pattern Summary
Subjects authenticate using opaque tokens (session IDs) that the system generates and tracks. The token itself contains no information; the system maps tokens to principals.

### FastAPI Implementation

**Built-in FastAPI Components:**
- `APIKeyCookie` - For cookie-based session tokens (Enforcer)
- `APIKeyHeader` - For header-based session tokens (Enforcer)
- `OAuth2PasswordBearer` - Can also act as Enforcer

**Pattern Role Mapping:**
- **Subject**: API client with session token
- **Enforcer**: `APIKeyCookie`, `APIKeyHeader`, or custom dependency
- **Verifier**: Custom session verification logic
- **Principal Provider**: Session storage (Redis, database)
- **Token Generator**: Secure random generator (`secrets` module)
- **Registrar**: Login endpoint that creates sessions

### Required External Libraries

```python
# Session storage (Principal Provider)
import redis.asyncio as redis
from redis import Redis

# Or in-memory with TTL
from cachetools import TTLCache

# Secure token generation
import secrets
import hashlib
```

### Complete Implementation Example

```python
from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import APIKeyCookie
from typing import Optional, Dict
import secrets
import hashlib
from datetime import datetime, timedelta
import redis.asyncio as redis

app = FastAPI()

# Principal Provider - session storage
class SessionManager:
    """
    Principal Provider role
    Manages mapping of tokens to principals
    """
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.session_timeout = 1800  # 30 minutes
        self.absolute_timeout = 43200  # 12 hours
    
    async def create_session(self, principal: str) -> str:
        """
        Token Generator + Registrar roles
        Generates secure opaque token
        """
        # Generate cryptographically secure token (128 bits = 16 bytes)
        token = secrets.token_urlsafe(32)  # Base64 URL-safe encoding
        
        session_data = {
            "principal": principal,
            "created_at": datetime.utcnow().isoformat(),
            "last_activity": datetime.utcnow().isoformat()
        }
        
        # Store in Redis with expiration
        await self.redis.setex(
            f"session:{token}",
            self.absolute_timeout,
            str(session_data)
        )
        
        return token
    
    async def get_principal(self, token: str) -> Optional[str]:
        """
        Verifier role
        Retrieves principal for valid token
        """
        session_data = await self.redis.get(f"session:{token}")
        
        if not session_data:
            return None
        
        # Parse session data
        import ast
        data = ast.literal_eval(session_data.decode())
        
        # Check activity timeout
        last_activity = datetime.fromisoformat(data["last_activity"])
        if (datetime.utcnow() - last_activity).seconds > self.session_timeout:
            await self.invalidate_session(token)
            return None
        
        # Update last activity
        data["last_activity"] = datetime.utcnow().isoformat()
        await self.redis.setex(
            f"session:{token}",
            self.absolute_timeout,
            str(data)
        )
        
        return data["principal"]
    
    async def invalidate_session(self, token: str):
        """Explicitly invalidate a session (logout)"""
        await self.redis.delete(f"session:{token}")
    
    async def invalidate_all_sessions(self, principal: str):
        """Invalidate all sessions for a principal"""
        # Scan for all sessions belonging to principal
        async for key in self.redis.scan_iter(match="session:*"):
            session_data = await self.redis.get(key)
            if session_data:
                import ast
                data = ast.literal_eval(session_data.decode())
                if data.get("principal") == principal:
                    await self.redis.delete(key)

# Initialize Redis connection
redis_client = None

@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = await redis.from_url("redis://localhost")

@app.on_event("shutdown")
async def shutdown():
    await redis_client.close()

# Create session manager
def get_session_manager() -> SessionManager:
    return SessionManager(redis_client)

# Cookie-based session (Enforcer)
cookie_scheme = APIKeyCookie(name="session_id")

# Verifier dependency
async def get_current_user(
    session_id: str = Depends(cookie_scheme),
    session_manager: SessionManager = Depends(get_session_manager)
):
    """
    Enforcer + Verifier roles
    Validates session and extracts principal
    """
    principal = await session_manager.get_principal(session_id)
    
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    return principal

# Login endpoint (Registrar)
@app.post("/login")
async def login(
    username: str,
    password: str,
    response: Response,
    session_manager: SessionManager = Depends(get_session_manager)
):
    """
    Registrar role
    Creates new session after password authentication
    """
    # Authenticate user (using password-based pattern)
    user = authenticate_user(username, password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create session
    session_id = await session_manager.create_session(username)
    
    # Set cookie with security attributes
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,  # Prevent JavaScript access
        secure=True,    # HTTPS only
        samesite="lax", # CSRF protection
        max_age=43200   # 12 hours
    )
    
    return {"message": "Login successful"}

# Protected endpoint
@app.get("/users/me")
async def get_current_user_profile(principal: str = Depends(get_current_user)):
    """Enforcer ensures valid session"""
    return {"username": principal}

# Logout endpoint
@app.post("/logout")
async def logout(
    response: Response,
    session_id: str = Depends(cookie_scheme),
    session_manager: SessionManager = Depends(get_session_manager)
):
    """Invalidate session"""
    await session_manager.invalidate_session(session_id)
    response.delete_cookie("session_id")
    return {"message": "Logged out successfully"}

# Force logout from all devices
@app.post("/logout/all")
async def logout_all_sessions(
    principal: str = Depends(get_current_user),
    session_manager: SessionManager = Depends(get_session_manager)
):
    """Invalidate all sessions for current user"""
    await session_manager.invalidate_all_sessions(principal)
    return {"message": "Logged out from all devices"}
```

### Alternative: In-Memory Session Storage

```python
from cachetools import TTLCache
import threading

class InMemorySessionManager:
    """
    Principal Provider using in-memory storage
    Suitable for single-server deployments
    """
    def __init__(self):
        self.sessions = TTLCache(maxsize=10000, ttl=1800)
        self.lock = threading.Lock()
    
    def create_session(self, principal: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = {
                "principal": principal,
                "created_at": datetime.utcnow()
            }
        return token
    
    def get_principal(self, token: str) -> Optional[str]:
        with self.lock:
            session = self.sessions.get(token)
            return session["principal"] if session else None
    
    def invalidate_session(self, token: str):
        with self.lock:
            self.sessions.pop(token, None)
```

### Pattern Considerations Met

✅ **Unpredictable tokens**: Uses `secrets.token_urlsafe()` (CSPRNG)  
✅ **Entropy**: 32 bytes = 256 bits (exceeds 64-bit minimum)  
✅ **Activity timeout**: Updates last activity time  
✅ **Absolute timeout**: Maximum session duration enforced  
✅ **Token lifetime management**: Redis TTL + activity checks  
✅ **Session fixation prevention**: New token on re-authentication  
✅ **Secure storage**: HttpOnly, Secure, SameSite cookies  

---

## 4. Session-Based Access Control

### Pattern Summary
Combines opaque token authentication with authorization. Session ID authenticates the user, and their privileges are checked for each action.

### FastAPI Implementation

**Built-in FastAPI Components:**
- `APIKeyCookie` - Session token enforcement
- `SecurityScopes` - For scope-based authorization
- Custom dependencies for authorization

**Pattern Role Mapping:**
- **Subject**: API client with session
- **Authentication Enforcer**: `APIKeyCookie` + session verification
- **Verifier**: Session validation logic
- **Session Manager**: Redis/database session storage
- **Authorization Enforcer**: Custom authorization dependency
- **Decider**: Permission checking logic
- **Policy Provider**: Database with user permissions

### Required External Libraries

```python
import redis.asyncio as redis
from sqlalchemy.orm import Session
from enum import Enum
from typing import List, Set
```

### Complete Implementation Example

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyCookie
from typing import Optional, Set, List
from enum import Enum
import redis.asyncio as redis
from pydantic import BaseModel

app = FastAPI()

# Define permissions
class Permission(str, Enum):
    READ_USERS = "users:read"
    WRITE_USERS = "users:write"
    DELETE_USERS = "users:delete"
    READ_POSTS = "posts:read"
    WRITE_POSTS = "posts:write"

class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

# Session data model
class SessionData(BaseModel):
    principal: str
    role: Role
    permissions: Set[Permission]

# Policy Provider - stores role-permission mappings
class PolicyProvider:
    """
    Manages authorization policies
    Maps principals to roles and permissions
    """
    def __init__(self):
        self.role_permissions = {
            Role.ADMIN: {
                Permission.READ_USERS,
                Permission.WRITE_USERS,
                Permission.DELETE_USERS,
                Permission.READ_POSTS,
                Permission.WRITE_POSTS,
            },
            Role.USER: {
                Permission.READ_USERS,
                Permission.READ_POSTS,
                Permission.WRITE_POSTS,
            },
            Role.GUEST: {
                Permission.READ_POSTS,
            }
        }
        
        # Map users to roles (would typically be in database)
        self.user_roles = {
            "alice": Role.ADMIN,
            "bob": Role.USER,
            "charlie": Role.GUEST
        }
    
    def get_user_role(self, principal: str) -> Role:
        """Get role for a principal"""
        return self.user_roles.get(principal, Role.GUEST)
    
    def get_role_permissions(self, role: Role) -> Set[Permission]:
        """Get privileges for a role"""
        return self.role_permissions.get(role, set())
    
    def get_user_permissions(self, principal: str) -> Set[Permission]:
        """Get all privileges for a principal"""
        role = self.get_user_role(principal)
        return self.get_role_permissions(role)

# Enhanced Session Manager with authorization data
class SessionManager:
    """
    Session Manager role
    Stores session with principal and permissions
    """
    def __init__(self, redis_client: redis.Redis, policy_provider: PolicyProvider):
        self.redis = redis_client
        self.policy_provider = policy_provider
        self.session_timeout = 1800
    
    async def create_session(self, principal: str) -> str:
        """Create session with authorization data"""
        token = secrets.token_urlsafe(32)
        
        # Get user permissions from Policy Provider
        role = self.policy_provider.get_user_role(principal)
        permissions = self.policy_provider.get_user_permissions(principal)
        
        session_data = SessionData(
            principal=principal,
            role=role,
            permissions=permissions
        )
        
        await self.redis.setex(
            f"session:{token}",
            self.session_timeout,
            session_data.json()
        )
        
        return token
    
    async def get_session(self, token: str) -> Optional[SessionData]:
        """Retrieve session with authorization data"""
        data = await self.redis.get(f"session:{token}")
        
        if not data:
            return None
        
        return SessionData.parse_raw(data)
    
    async def invalidate_session(self, token: str):
        await self.redis.delete(f"session:{token}")

# Authentication Enforcer
cookie_scheme = APIKeyCookie(name="session_id")

# Combined Verifier + Decider
class AuthorizationChecker:
    """
    Combines authentication verification and authorization decision
    """
    def __init__(self, required_permissions: Optional[List[Permission]] = None):
        self.required_permissions = required_permissions or []
    
    async def __call__(
        self,
        session_id: str = Depends(cookie_scheme),
        session_manager: SessionManager = Depends(get_session_manager)
    ) -> SessionData:
        """
        1. Authentication: Verify session (Verifier role)
        2. Authorization: Check permissions (Decider role)
        """
        # Authentication verification
        session = await session_manager.get_session(session_id)
        
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )
        
        # Authorization decision
        if self.required_permissions:
            missing_perms = set(self.required_permissions) - session.permissions
            if missing_perms:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permissions: {missing_perms}"
                )
        
        return session

# Helper to create permission checkers
def require_permissions(permissions: List[Permission]):
    """Factory for creating authorization dependencies"""
    return AuthorizationChecker(required_permissions=permissions)

# Registrar - login with session creation
@app.post("/login")
async def login(
    username: str,
    password: str,
    response: Response,
    session_manager: SessionManager = Depends(get_session_manager)
):
    """Create authenticated session with authorization data"""
    # Authenticate user
    user = authenticate_user(username, password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create session (includes authorization data)
    session_id = await session_manager.create_session(username)
    
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=1800
    )
    
    return {"message": "Login successful"}

# Public endpoint - no authentication required
@app.get("/posts/public")
async def list_public_posts():
    """No enforcer - public access"""
    return {"posts": ["post1", "post2"]}

# Authenticated endpoint - requires valid session
@app.get("/users/me")
async def get_current_user(
    session: SessionData = Depends(AuthorizationChecker())
):
    """Authentication enforcer only - any valid session"""
    return {
        "username": session.principal,
        "role": session.role,
        "permissions": list(session.permissions)
    }

# Authorized endpoint - requires specific permission
@app.get("/users")
async def list_users(
    session: SessionData = Depends(require_permissions([Permission.READ_USERS]))
):
    """
    Both authentication and authorization enforcement
    Requires READ_USERS permission
    """
    return {"users": ["alice", "bob", "charlie"]}

# Multiple permissions required
@app.post("/users")
async def create_user(
    username: str,
    session: SessionData = Depends(
        require_permissions([Permission.WRITE_USERS])
    )
):
    """Requires WRITE_USERS permission"""
    return {"message": f"User {username} created by {session.principal}"}

@app.delete("/users/{username}")
async def delete_user(
    username: str,
    session: SessionData = Depends(
        require_permissions([Permission.DELETE_USERS])
    )
):
    """Requires DELETE_USERS permission - admin only"""
    return {"message": f"User {username} deleted by {session.principal}"}

# Resource-based authorization
@app.get("/posts/{post_id}")
async def get_post(
    post_id: int,
    session: SessionData = Depends(
        require_permissions([Permission.READ_POSTS])
    )
):
    """Resource access with permission check"""
    # Could add additional checks here:
    # - Is user the post owner?
    # - Is post public/private?
    return {"post_id": post_id, "accessed_by": session.principal}

@app.put("/posts/{post_id}")
async def update_post(
    post_id: int,
    content: str,
    session: SessionData = Depends(
        require_permissions([Permission.WRITE_POSTS])
    )
):
    """Update requires WRITE_POSTS permission"""
    # Additional check: is user the post owner?
    return {"post_id": post_id, "updated_by": session.principal}

# Logout
@app.post("/logout")
async def logout(
    response: Response,
    session_id: str = Depends(cookie_scheme),
    session_manager: SessionManager = Depends(get_session_manager)
):
    """Invalidate session"""
    await session_manager.invalidate_session(session_id)
    response.delete_cookie("session_id")
    return {"message": "Logged out"}
```

### Advanced: Attribute-Based Access Control (ABAC)

```python
from typing import Callable, Dict, Any

class ABACDecider:
    """
    Advanced authorization decider using attributes
    """
    def __init__(
        self,
        policy_function: Callable[[SessionData, Dict[str, Any]], bool]
    ):
        self.policy_function = policy_function
    
    async def __call__(
        self,
        session: SessionData = Depends(AuthorizationChecker()),
        **context
    ):
        """
        Evaluate policy based on:
        - Subject attributes (from session)
        - Resource attributes (from context)
        - Action attributes (from context)
        - Environment attributes (time, IP, etc.)
        """
        if not self.policy_function(session, context):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied by policy"
            )
        return session

# Example ABAC policy
def can_edit_post_policy(session: SessionData, context: Dict[str, Any]) -> bool:
    """
    Allow if:
    - User is admin, OR
    - User is post owner AND post is not locked
    """
    post_owner = context.get("post_owner")
    post_locked = context.get("post_locked", False)
    
    if session.role == Role.ADMIN:
        return True
    
    if session.principal == post_owner and not post_locked:
        return True
    
    return False

# Use ABAC
@app.put("/posts/{post_id}/abac")
async def update_post_abac(
    post_id: int,
    session: SessionData = Depends(ABACDecider(can_edit_post_policy))
):
    """ABAC-based authorization"""
    # Get post details and pass to policy
    # This would typically come from database
    context = {
        "post_owner": "alice",
        "post_locked": False
    }
    return {"message": "Post updated"}
```

### Pattern Considerations Met

✅ **Authentication first**: Session verified before authorization  
✅ **Session-based**: Opaque token for authentication  
✅ **Authorization per action**: Permissions checked per endpoint  
✅ **Role-based permissions**: Policy provider maps roles to permissions  
✅ **Resource protection**: Both authentication and authorization enforced  
✅ **Session management**: Proper session lifecycle  

---

## 5. Obscure Token-Based Access Control (API Keys)

### Pattern Summary
Long-lived, secret tokens that combine authentication and authorization. Common for API keys and Personal Access Tokens (PATs).

### FastAPI Implementation

**Built-in FastAPI Components:**
- `APIKeyHeader` - For API keys in headers (Enforcer)
- `APIKeyQuery` - For API keys in query parameters (Enforcer)
- Custom security schemes

**Pattern Role Mapping:**
- **Subject**: API client with API key
- **Enforcer**: `APIKeyHeader` or `APIKeyQuery`
- **Validator**: Combined authentication + authorization logic
- **Hasher**: Hash function for token storage
- **Token Manager**: Database storing token hashes and permissions
- **Registrar**: Endpoint to generate new API keys
- **Token Generator**: Secure random generator

### Required External Libraries

```python
import secrets
import hashlib
from sqlalchemy import create_engine, Column, String, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
```

### Complete Implementation Example

```python
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import APIKeyHeader
from typing import Optional, Set, List
from pydantic import BaseModel
from datetime import datetime, timedelta
import secrets
import hashlib
from sqlalchemy import Column, String, JSON, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

app = FastAPI()

# Database setup for Token Manager
Base = declarative_base()

class APIKey(Base):
    """Token Manager storage"""
    __tablename__ = "api_keys"
    
    id = Column(String, primary_key=True)
    token_hash = Column(String, unique=True, nullable=False)
    principal = Column(String, nullable=False)
    name = Column(String)  # User-friendly name
    permissions = Column(JSON)  # List of permissions
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used = Column(DateTime, nullable=True)

engine = create_engine("sqlite:///./api_keys.db")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Models
class TokenInfo(BaseModel):
    principal: str
    permissions: Set[str]
    name: Optional[str] = None

# Token Manager implementation
class APIKeyManager:
    """
    Token Manager role
    Manages API keys with hashing
    """
    def __init__(self, db: Session):
        self.db = db
    
    @staticmethod
    def generate_token() -> str:
        """
        Token Generator role
        Generates cryptographically secure token
        At least 128 bits (16 bytes) for security
        """
        return secrets.token_urlsafe(32)  # 256 bits
    
    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hasher role
        One-way hash for secure storage
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    def create_api_key(
        self,
        principal: str,
        permissions: List[str],
        name: Optional[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Registrar role
        Creates new API key with permissions
        """
        # Generate token (shown to user only once)
        token = self.generate_token()
        
        # Hash for storage (evidence)
        token_hash = self.hash_token(token)
        
        # Calculate expiration
        expires_at = None
        if expires_delta:
            expires_at = datetime.utcnow() + expires_delta
        
        # Store in database
        api_key = APIKey(
            id=secrets.token_urlsafe(16),
            token_hash=token_hash,
            principal=principal,
            name=name,
            permissions=permissions,
            expires_at=expires_at
        )
        
        self.db.add(api_key)
        self.db.commit()
        
        # Return plaintext token (shown only once)
        return token
    
    def validate_token(self, token: str) -> Optional[TokenInfo]:
        """
        Validator role
        Verifies token and returns principal + permissions
        """
        # Hash the provided token
        token_hash = self.hash_token(token)
        
        # Look up in database
        api_key = self.db.query(APIKey).filter(
            APIKey.token_hash == token_hash
        ).first()
        
        if not api_key:
            return None
        
        # Check expiration
        if api_key.expires_at and datetime.utcnow() > api_key.expires_at:
            return None
        
        # Update last used timestamp
        api_key.last_used = datetime.utcnow()
        self.db.commit()
        
        return TokenInfo(
            principal=api_key.principal,
            permissions=set(api_key.permissions),
            name=api_key.name
        )
    
    def revoke_token(self, token: str) -> bool:
        """Revoke an API key"""
        token_hash = self.hash_token(token)
        api_key = self.db.query(APIKey).filter(
            APIKey.token_hash == token_hash
        ).first()
        
        if api_key:
            self.db.delete(api_key)
            self.db.commit()
            return True
        return False
    
    def list_user_keys(self, principal: str) -> List[APIKey]:
        """List all API keys for a user"""
        return self.db.query(APIKey).filter(
            APIKey.principal == principal
        ).all()

# Security scheme - Enforcer
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Validator dependency
class APIKeyValidator:
    """
    Enforcer + Validator roles
    Validates API key and checks permissions
    """
    def __init__(self, required_permissions: Optional[List[str]] = None):
        self.required_permissions = required_permissions or []
    
    async def __call__(
        self,
        api_key: Optional[str] = Security(api_key_header),
        db: Session = Depends(get_db)
    ) -> TokenInfo:
        """
        1. Validate API key (authentication)
        2. Check permissions (authorization)
        """
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key"
            )
        
        # Validate token
        manager = APIKeyManager(db)
        token_info = manager.validate_token(api_key)
        
        if not token_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key"
            )
        
        # Check authorization
        if self.required_permissions:
            missing = set(self.required_permissions) - token_info.permissions
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permissions: {missing}"
                )
        
        return token_info

# Helper function
def require_api_permissions(permissions: List[str]):
    """Factory for creating API key validators with permissions"""
    return APIKeyValidator(required_permissions=permissions)

# API endpoints

# Generate new API key (requires user authentication)
@app.post("/api-keys")
async def create_api_key(
    name: str,
    permissions: List[str],
    expires_days: Optional[int] = None,
    principal: str = Depends(get_authenticated_user),  # From password auth
    db: Session = Depends(get_db)
):
    """
    Registrar endpoint
    Creates new API key (shown only once)
    """
    manager = APIKeyManager(db)
    
    expires_delta = None
    if expires_days:
        expires_delta = timedelta(days=expires_days)
    
    token = manager.create_api_key(
        principal=principal,
        permissions=permissions,
        name=name,
        expires_delta=expires_delta
    )
    
    return {
        "api_key": token,
        "message": "Save this key securely. It won't be shown again.",
        "permissions": permissions,
        "expires_in_days": expires_days
    }

# List user's API keys
@app.get("/api-keys")
async def list_api_keys(
    principal: str = Depends(get_authenticated_user),
    db: Session = Depends(get_db)
):
    """List all API keys for authenticated user"""
    manager = APIKeyManager(db)
    keys = manager.list_user_keys(principal)
    
    return {
        "api_keys": [
            {
                "id": key.id,
                "name": key.name,
                "permissions": key.permissions,
                "created_at": key.created_at,
                "expires_at": key.expires_at,
                "last_used": key.last_used
            }
            for key in keys
        ]
    }

# Revoke API key
@app.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    principal: str = Depends(get_authenticated_user),
    db: Session = Depends(get_db)
):
    """Revoke an API key"""
    # Verify ownership
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.principal == principal
    ).first()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    db.delete(api_key)
    db.commit()
    
    return {"message": "API key revoked"}

# Public endpoint - no API key required
@app.get("/public")
async def public_endpoint():
    """No enforcer - public access"""
    return {"message": "This is public"}

# Protected endpoint - requires valid API key
@app.get("/protected")
async def protected_endpoint(
    token_info: TokenInfo = Depends(APIKeyValidator())
):
    """Requires any valid API key"""
    return {
        "message": "Access granted",
        "principal": token_info.principal,
        "permissions": list(token_info.permissions)
    }

# Endpoint requiring specific permissions
@app.get("/data/read")
async def read_data(
    token_info: TokenInfo = Depends(
        require_api_permissions(["data:read"])
    )
):
    """Requires 'data:read' permission"""
    return {"data": "sensitive information", "accessed_by": token_info.principal}

@app.post("/data/write")
async def write_data(
    content: str,
    token_info: TokenInfo = Depends(
        require_api_permissions(["data:write"])
    )
):
    """Requires 'data:write' permission"""
    return {"message": "Data written", "by": token_info.principal}

@app.delete("/data/delete")
async def delete_data(
    token_info: TokenInfo = Depends(
        require_api_permissions(["data:delete"])
    )
):
    """Requires 'data:delete' permission - highly privileged"""
    return {"message": "Data deleted", "by": token_info.principal}

# Sensitive action - API key should NOT be allowed
@app.post("/account/delete")
async def delete_account(
    principal: str = Depends(get_authenticated_user)  # Requires password auth
):
    """
    Sensitive action - requires full authentication
    NOT accessible with API key
    """
    return {"message": f"Account {principal} deleted"}
```

### Pattern Considerations Met

✅ **Unpredictable tokens**: Uses `secrets` module (CSPRNG)  
✅ **Sufficient entropy**: 256 bits (exceeds 64-bit requirement)  
✅ **Hash storage**: Stores SHA-256 hash, not plaintext  
✅ **Long-lived**: Optional expiration dates  
✅ **Combined auth + authz**: Single token validates and authorizes  
✅ **Revocable**: Users can revoke keys  
✅ **Limited privileges**: Scoped permissions per key  
✅ **Sensitive actions restricted**: Password auth required for critical operations  

---

## Summary Matrix

| Pattern | FastAPI Built-in | Required Libraries | Implementation Complexity |
|---------|-----------------|-------------------|-------------------------|
| **Password-Based** | `OAuth2PasswordRequestForm`, `OAuth2PasswordBearer` | `passlib`, `bcrypt`, database ORM | Medium |
| **Verifiable Token (JWT)** | `HTTPBearer`, `OAuth2PasswordBearer` | `python-jose` or `PyJWT` | Low-Medium |
| **Opaque Token** | `APIKeyCookie`, `APIKeyHeader` | `redis` or in-memory cache | Medium |
| **Session-Based Access Control** | `APIKeyCookie`, `SecurityScopes` | `redis`, database ORM | High |
| **Obscure Token (API Keys)** | `APIKeyHeader`, `APIKeyQuery` | database ORM, `secrets` | Medium-High |

## Key Library Recommendations

### Password Hashing
```bash
pip install passlib[bcrypt]
# or
pip install bcrypt
```

### JWT Handling
```bash
pip install python-jose[cryptography]
# or
pip install PyJWT cryptography
```

### Session Storage
```bash
pip install redis
# or for async
pip install redis[asyncio]
```

### Database
```bash
pip install sqlalchemy
# or for async
pip install sqlalchemy[asyncio]
# or
pip install tortoise-orm
```

### Additional Security
```bash
pip install cryptography  # For encryption, key management
pip install python-multipart  # For form data
```

## Best Practices Across All Patterns

1. **Always use HTTPS** - All tokens/credentials must be transmitted securely
2. **HTTPOnly cookies** - Prevent XSS attacks on session tokens
3. **SameSite cookies** - Prevent CSRF attacks
4. **Rate limiting** - Use `slowapi` or similar
5. **Logging** - Log all authentication/authorization failures
6. **Secret management** - Use environment variables or secret managers
7. **Token rotation** - Implement refresh tokens for long sessions
8. **Input validation** - Use Pydantic models
9. **Error messages** - Generic messages to prevent enumeration
10. **Security headers** - Use middleware for HSTS, CSP, etc.

