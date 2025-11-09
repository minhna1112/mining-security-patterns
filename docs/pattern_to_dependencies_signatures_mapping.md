# Security Pattern to Dependencies and Signatures Mapping Table

This table maps Van den Berghe's security patterns to their implementation dependencies and specific function signatures/API calls for each pattern role.

---

## 1. Password-Based Authentication

| Role | Dependencies | Signature/API Usage |
|------|--------------|---------------------|
| **Enforcer** | `fastapi` | `OAuth2PasswordBearer(tokenUrl="token")`<br>`OAuth2PasswordRequestForm = Depends()`<br>`HTTPBasic()` |
| **Verification Manager** | `passlib` | `pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")`<br>`pwd_context.verify(plain_password, hashed_password)` |
| **Comparator** | `passlib` | `pwd_context.verify(plain_password, hashed_password)` |
| **Hasher** | `passlib`, `bcrypt` | `pwd_context.hash(password)`<br>Alternative: `bcrypt.hashpw(password.encode(), bcrypt.gensalt())` |
| **Password Store** | `sqlalchemy`, `tortoise-orm` | `session.query(User).filter(User.username == username).first()`<br>`User.objects.get(username=username)` |
| **Pepper Store** | `cryptography` | `Fernet(pepper_key)`<br>`cipher.encrypt(hashed_password.encode())` |
| **Encrypter** | `cryptography` | `from cryptography.fernet import Fernet`<br>`cipher = Fernet(key)`<br>`cipher.encrypt(data)` |
| **System** | `fastapi` | `@app.post("/login")`<br>`async def login(...)` |
| **Registrar** | `fastapi`, `passlib` | `@app.post("/register")`<br>`hashed = pwd_context.hash(password)`<br>`db.add(new_user)` |
| **Password Policy** | `pydantic`, custom | `@validator("password")`<br>`def validate_password(cls, v):`<br>`    if len(v) < 8: raise ValueError(...)` |
| **SRNG** | `secrets` | `secrets.token_urlsafe(32)`<br>`secrets.token_bytes(32)` |

**Complete Dependencies:** `fastapi`, `passlib[bcrypt]`, `cryptography`, `sqlalchemy` or `tortoise-orm`, `pydantic`

---

## 2. Verifiable Token-Based Authentication (JWT)

| Role | Dependencies | Signature/API Usage |
|------|--------------|---------------------|
| **Enforcer** | `fastapi` | `HTTPBearer()`<br>`OAuth2PasswordBearer(tokenUrl="token")`<br>`credentials: HTTPAuthorizationCredentials = Depends(security)` |
| **Verifier** | `python-jose`, `PyJWT` | `jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])`<br>Alternative: `PyJWT.decode(token, public_key, algorithms=["RS256"])` |
| **Cryptographer** (MAC) | `python-jose` | `jwt.encode(data, SECRET_KEY, algorithm="HS256")`<br>`jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` |
| **Cryptographer** (Digital Signature) | `python-jose`, `cryptography` | `jwt.encode(data, private_key, algorithm="RS256")`<br>`jwt.decode(token, public_key, algorithms=["RS256"])` |
| **Key Manager** (HMAC) | Built-in | `SECRET_KEY = "your-secret-key"`<br>Store in environment variables |
| **Key Manager** (RSA) | `cryptography` | `from cryptography.hazmat.primitives.asymmetric import rsa`<br>`private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)`<br>`public_key = private_key.public_key()` |
| **Token Generator** | `python-jose` | `access_token = jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm="HS256")` |
| **Registrar** | `fastapi`, `python-jose` | `@app.post("/token")`<br>`token = create_access_token(data={"sub": user.username})`<br>`return {"access_token": token, "token_type": "bearer"}` |
| **Token Blacklist** (for revocation) | `redis`, `cachetools` | `redis_client.sadd("revoked_tokens", token)`<br>`redis_client.sismember("revoked_tokens", token)` |

**Complete Dependencies:** `fastapi`, `python-jose[cryptography]` or `PyJWT`, `cryptography`, optional: `redis` for revocation

---

## 3. Opaque Token-Based Authentication (Session)

| Role | Dependencies | Signature/API Usage |
|------|--------------|---------------------|
| **Enforcer** | `fastapi` | `APIKeyCookie(name="session_id")`<br>`APIKeyHeader(name="X-Session-Token")`<br>`session_id: str = Depends(cookie_scheme)` |
| **Verifier** | Custom with storage backend | `async def verify_session(session_id: str):`<br>`    session = await session_manager.get_session(session_id)`<br>`    if not session: raise HTTPException(401)` |
| **Principal Provider** (Redis) | `redis[asyncio]` | `await redis_client.get(f"session:{token}")`<br>`await redis_client.setex(f"session:{token}", ttl, data)` |
| **Principal Provider** (In-memory) | `cachetools` | `sessions = TTLCache(maxsize=10000, ttl=1800)`<br>`sessions[token] = {"principal": username, ...}` |
| **Token Generator** | `secrets` | `session_id = secrets.token_urlsafe(32)`<br>`session_id = secrets.token_hex(32)` |
| **Registrar** | `fastapi`, `secrets`, storage | `@app.post("/login")`<br>`session_id = secrets.token_urlsafe(32)`<br>`await redis.setex(f"session:{session_id}", 1800, user_data)`<br>`response.set_cookie("session_id", session_id, httponly=True)` |
| **Session Manager** | `redis` or custom | `class SessionManager:`<br>`    async def create_session(self, principal: str) -> str`<br>`    async def get_principal(self, token: str) -> Optional[str]`<br>`    async def invalidate_session(self, token: str)` |

**Complete Dependencies:** `fastapi`, `redis[asyncio]` or `cachetools`, `secrets` (built-in)

---

## 4. Session-Based Access Control

| Role | Dependencies | Signature/API Usage |
|------|--------------|---------------------|
| **Authentication Enforcer** | `fastapi` | `APIKeyCookie(name="session_id")`<br>`session_id: str = Depends(cookie_scheme)` |
| **Verifier** | `redis`, custom | `session = await session_manager.get_session(session_id)`<br>`if not session: raise HTTPException(401)` |
| **Session Manager** | `redis[asyncio]` | `await redis.setex(f"session:{token}", ttl, session_data.json())`<br>`data = await redis.get(f"session:{token}")` |
| **Session ID Generator** | `secrets` | `secrets.token_urlsafe(32)` |
| **Authorization Enforcer** | `fastapi`, custom | `class AuthorizationChecker:`<br>`    def __init__(self, required_permissions: List[str])`<br>`    async def __call__(self, session_id: str = Depends(...)): ...` |
| **Decider** | Custom logic | `if required_permissions.issubset(session.permissions):`<br>`    return session`<br>`raise HTTPException(403)` |
| **Policy Provider** | `sqlalchemy`, `redis` | `db.query(Role).filter(Role.name == role_name).first()`<br>`role_permissions = policy_provider.get_role_permissions(role)` |
| **Registrar** | `fastapi`, `secrets`, `redis` | `@app.post("/login")`<br>`session_id = await session_manager.create_session(username)`<br>`response.set_cookie("session_id", session_id, httponly=True, secure=True)` |

**Complete Dependencies:** `fastapi`, `redis[asyncio]`, `sqlalchemy` or database ORM, `secrets` (built-in), `pydantic`

---

## 5. Obscure Token-Based Access Control (API Keys)

| Role | Dependencies | Signature/API Usage |
|------|--------------|---------------------|
| **Enforcer** | `fastapi` | `APIKeyHeader(name="X-API-Key", auto_error=False)`<br>`APIKeyQuery(name="api_key")`<br>`api_key: str = Security(api_key_header)` |
| **Validator** (Auth + Authz) | Custom with DB | `class APIKeyValidator:`<br>`    async def __call__(self, api_key: str = Security(...)):`<br>`        token_info = manager.validate_token(api_key)`<br>`        if not token_info: raise HTTPException(401)`<br>`        if missing_perms: raise HTTPException(403)` |
| **Hasher** | `hashlib` | `import hashlib`<br>`hashlib.sha256(token.encode()).hexdigest()`<br>`hashlib.blake2b(token.encode()).hexdigest()` |
| **Token Manager** (Database) | `sqlalchemy` | `db.query(APIKey).filter(APIKey.token_hash == hash).first()`<br>`api_key = APIKey(token_hash=hash, principal=user, permissions=perms)`<br>`db.add(api_key)` |
| **Token Generator** | `secrets` | `secrets.token_urlsafe(32)`<br>`secrets.token_hex(32)` |
| **Registrar** | `fastapi`, `secrets`, `sqlalchemy` | `@app.post("/api-keys")`<br>`token = secrets.token_urlsafe(32)`<br>`token_hash = hashlib.sha256(token.encode()).hexdigest()`<br>`db.add(APIKey(token_hash=token_hash, principal=user, permissions=perms))`<br>`return {"api_key": token}` |
| **Permission Checker** | Custom | `if required_permissions.issubset(token_info.permissions):`<br>`    return token_info`<br>`raise HTTPException(403, "Missing permissions")` |

**Complete Dependencies:** `fastapi`, `sqlalchemy` or database ORM, `hashlib` (built-in), `secrets` (built-in)

---

## Cross-Pattern Common Components

### Database ORMs (Password Store, Token Manager, Policy Provider)

| Library | Connection | Query | Insert | Update | Delete |
|---------|-----------|-------|--------|--------|--------|
| **SQLAlchemy** | `engine = create_engine("postgresql://...")`<br>`SessionLocal = sessionmaker(bind=engine)` | `db.query(User).filter(User.username == name).first()` | `db.add(user)`<br>`db.commit()` | `user.password = new_hash`<br>`db.commit()` | `db.delete(user)`<br>`db.commit()` |
| **Tortoise ORM** | `await Tortoise.init(db_url="...", modules={"models": [...]})`<br>`await Tortoise.generate_schemas()` | `await User.get(username=name)`<br>`await User.filter(username=name).first()` | `user = User(username=name, ...)`<br>`await user.save()` | `user.password = new_hash`<br>`await user.save()` | `await user.delete()` |

### Redis (Session Storage, Token Blacklist)

| Operation | Synchronous (redis-py) | Asynchronous (redis[asyncio]) |
|-----------|----------------------|------------------------------|
| **Connect** | `redis.Redis(host="localhost", port=6379, db=0)` | `await redis.from_url("redis://localhost")` |
| **Set with TTL** | `client.setex("key", 3600, "value")` | `await client.setex("key", 3600, "value")` |
| **Get** | `value = client.get("key")` | `value = await client.get("key")` |
| **Delete** | `client.delete("key")` | `await client.delete("key")` |
| **Check exists** | `client.exists("key")` | `await client.exists("key")` |
| **Set add** | `client.sadd("set_key", "member")` | `await client.sadd("set_key", "member")` |
| **Set check** | `client.sismember("set_key", "member")` | `await client.sismember("set_key", "member")` |

### Cryptography (Hasher, Encrypter, Key Manager)

| Purpose | Library | Signature/API Usage |
|---------|---------|---------------------|
| **Password Hashing** | `passlib` | `from passlib.context import CryptContext`<br>`pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")`<br>`hash = pwd_context.hash(password)`<br>`is_valid = pwd_context.verify(password, hash)` |
| **Password Hashing** | `bcrypt` | `import bcrypt`<br>`salt = bcrypt.gensalt()`<br>`hash = bcrypt.hashpw(password.encode(), salt)`<br>`is_valid = bcrypt.checkpw(password.encode(), hash)` |
| **General Hashing** | `hashlib` | `import hashlib`<br>`hash = hashlib.sha256(data.encode()).hexdigest()`<br>`hash = hashlib.blake2b(data.encode()).hexdigest()` |
| **Symmetric Encryption** | `cryptography` | `from cryptography.fernet import Fernet`<br>`key = Fernet.generate_key()`<br>`cipher = Fernet(key)`<br>`encrypted = cipher.encrypt(data.encode())`<br>`decrypted = cipher.decrypt(encrypted).decode()` |
| **RSA Key Generation** | `cryptography` | `from cryptography.hazmat.primitives.asymmetric import rsa`<br>`private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)` |
| **JWT with HMAC** | `python-jose` | `from jose import jwt`<br>`token = jwt.encode({"sub": user}, SECRET_KEY, algorithm="HS256")`<br>`payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` |
| **JWT with RSA** | `python-jose` | `token = jwt.encode({"sub": user}, private_key, algorithm="RS256")`<br>`payload = jwt.decode(token, public_key, algorithms=["RS256"])` |
| **Random Generation** | `secrets` | `token = secrets.token_urlsafe(32)`<br>`token = secrets.token_hex(32)`<br>`random_bytes = secrets.token_bytes(32)` |

---

## FastAPI Security Utilities (Enforcer Role)

| Security Scheme | Import | Initialization | Usage in Dependency |
|-----------------|--------|----------------|---------------------|
| **OAuth2PasswordBearer** | `from fastapi.security import OAuth2PasswordBearer` | `oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")` | `async def get_user(token: str = Depends(oauth2_scheme))` |
| **OAuth2PasswordRequestForm** | `from fastapi.security import OAuth2PasswordRequestForm` | N/A | `async def login(form: OAuth2PasswordRequestForm = Depends())` |
| **HTTPBearer** | `from fastapi.security import HTTPBearer` | `security = HTTPBearer()` | `async def verify(creds: HTTPAuthorizationCredentials = Depends(security))` |
| **HTTPBasic** | `from fastapi.security import HTTPBasic` | `security = HTTPBasic()` | `async def verify(creds: HTTPBasicCredentials = Depends(security))` |
| **APIKeyHeader** | `from fastapi.security import APIKeyHeader` | `api_key_header = APIKeyHeader(name="X-API-Key")` | `async def verify(api_key: str = Depends(api_key_header))` |
| **APIKeyCookie** | `from fastapi.security import APIKeyCookie` | `cookie_scheme = APIKeyCookie(name="session_id")` | `async def verify(session: str = Depends(cookie_scheme))` |
| **APIKeyQuery** | `from fastapi.security import APIKeyQuery` | `api_key_query = APIKeyQuery(name="api_key")` | `async def verify(key: str = Depends(api_key_query))` |
| **SecurityScopes** | `from fastapi.security import SecurityScopes` | N/A | `async def check(scopes: SecurityScopes, token: str = Depends(...))` |

---

## Pattern-Specific Zoekt Query Signatures

These are example search patterns to find implementations in codebases:

### Password-Based Authentication

```
# Find Enforcer implementations
OAuth2PasswordBearer\s*\(
OAuth2PasswordRequestForm\s*=\s*Depends\(\)

# Find Hasher implementations  
CryptContext\s*\(\s*schemes\s*=\s*\[
pwd_context\.hash\(
bcrypt\.hashpw\(

# Find Comparator implementations
pwd_context\.verify\(
bcrypt\.checkpw\(

# Find Registrar endpoints
@app\.post\(["\']/(register|signup)
```

### Verifiable Token-Based Authentication (JWT)

```
# Find Enforcer implementations
HTTPBearer\s*\(\)
OAuth2PasswordBearer\s*\(

# Find Token Generator implementations
jwt\.encode\(
create_access_token\(

# Find Verifier implementations
jwt\.decode\(
verify_token\(

# Find Key Manager (RSA)
rsa\.generate_private_key\(
private_key\.public_key\(\)
```

### Opaque Token-Based Authentication

```
# Find Enforcer implementations
APIKeyCookie\s*\(
APIKeyHeader\s*\(

# Find Token Generator implementations
secrets\.token_urlsafe\(
secrets\.token_hex\(

# Find Session Manager implementations
redis.*setex.*session
TTLCache\s*\(
session_manager\.create_session\(
session_manager\.get_principal\(
```

### Session-Based Access Control

```
# Find combined auth+authz implementations
class\s+.*Checker.*:\s*def\s+__init__.*required_permissions
session\.permissions
raise\s+HTTPException\s*\(\s*status_code\s*=\s*(403|status\.HTTP_403_FORBIDDEN)

# Find Policy Provider implementations
get_role_permissions\(
get_user_permissions\(
policy_provider\.get_privileges\(
```

### Obscure Token-Based Access Control (API Keys)

```
# Find Enforcer implementations
APIKeyHeader\s*\(.*name\s*=\s*["\']X-API-Key
Security\s*\(\s*api_key_header\s*\)

# Find Token Manager implementations
APIKey\s*\(.*token_hash
hashlib\.sha256\(.*token
api_key\.permissions

# Find Validator implementations
validate_token\(
token_hash\s*=.*hashlib
required_permissions.*issubset
```

---

## Complete Dependency Installation Commands

```bash
# Password-Based Authentication
pip install fastapi[all] passlib[bcrypt] sqlalchemy cryptography pydantic python-multipart

# Verifiable Token-Based Authentication (JWT)
pip install fastapi[all] python-jose[cryptography] cryptography

# Opaque Token-Based Authentication
pip install fastapi[all] redis[asyncio]
# OR for in-memory
pip install fastapi[all] cachetools

# Session-Based Access Control
pip install fastapi[all] redis[asyncio] sqlalchemy pydantic

# Obscure Token-Based Access Control
pip install fastapi[all] sqlalchemy

# Complete installation (all patterns)
pip install fastapi[all] \
    passlib[bcrypt] \
    python-jose[cryptography] \
    cryptography \
    redis[asyncio] \
    sqlalchemy \
    pydantic \
    python-multipart
```

---

## Usage Pattern Template

### General Pattern for Any Security Implementation

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import [ENFORCER_CLASS]

app = FastAPI()

# 1. Initialize Enforcer
enforcer = [ENFORCER_CLASS]([PARAMETERS])

# 2. Create Verification Logic
async def verify_credentials([CREDENTIAL_PARAM] = Depends(enforcer)):
    # Verification logic using appropriate libraries
    [VERIFICATION_CODE]
    return [PRINCIPAL_OR_TOKEN_INFO]

# 3. Protected Endpoint
@app.get("/protected")
async def protected_route([USER_PARAM] = Depends(verify_credentials)):
    return {"message": "Access granted", "user": [USER_PARAM]}

# 4. Registration/Token Generation
@app.post("/[AUTH_ENDPOINT]")
async def authenticate([AUTH_PARAMS]):
    # Generate token/session
    [TOKEN_GENERATION_CODE]
    return {[TOKEN_RESPONSE]}
```

