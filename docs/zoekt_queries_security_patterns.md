# Zoekt Queries for Security Pattern Role Detection

This table provides Zoekt search queries to locate files containing implementations of specific security pattern roles in Python FastAPI projects.

---

## 1. Password-Based Authentication

| Role | Zoekt Query | Description |
|------|-------------|-------------|
| **Enforcer** | `OAuth2PasswordBearer OAuth2PasswordRequestForm` | Files containing both OAuth2 password authentication classes |
| **Enforcer** | `class OAuth2PasswordBearer case:yes` | Files with OAuth2PasswordBearer (case-sensitive) |
| **Enforcer** | `HTTPBasic HTTPBasicCredentials` | Files implementing HTTP Basic authentication |
| **Verification Manager** | `CryptContext pwd_context.verify` | Files with password verification context |
| **Verification Manager** | `def verify_password lang:python` | Python functions that verify passwords |
| **Comparator** | `pwd_context.verify bcrypt.checkpw` | Files containing password comparison functions |
| **Hasher** | `pwd_context.hash bcrypt.hashpw` | Files with password hashing implementations |
| **Hasher** | `CryptContext schemes bcrypt` | Files configuring bcrypt hashing |
| **Password Store** | `hashed_password User.query` | Files with user password storage queries |
| **Password Store** | `class User password sqlalchemy` | SQLAlchemy User models with password fields |
| **Pepper Store** | `Fernet pepper_key encrypt` | Files implementing pepper encryption |
| **Encrypter** | `from cryptography.fernet import Fernet` | Files importing Fernet encryption |
| **System** | `@app.post /login async def` | Login endpoint implementations |
| **Registrar** | `@app.post /register pwd_context.hash` | Registration endpoints with password hashing |
| **Registrar** | `def register_user db.add` | User registration functions |
| **Password Policy** | `@validator password len` | Pydantic password validators |
| **Password Policy** | `class PasswordPolicy validate` | Password policy validation classes |
| **SRNG** | `secrets.token_urlsafe secrets.token_bytes` | Secure random number generation |

---

## 2. Verifiable Token-Based Authentication (JWT)

| Role | Zoekt Query | Description |
|------|-------------|-------------|
| **Enforcer** | `HTTPBearer OAuth2PasswordBearer` | Bearer token enforcement |
| **Enforcer** | `HTTPAuthorizationCredentials Depends` | HTTP authorization credentials dependency |
| **Verifier** | `jwt.decode SECRET_KEY algorithms` | JWT token verification |
| **Verifier** | `def verify_token jwt.decode` | Token verification functions |
| **Cryptographer (MAC)** | `jwt.encode HS256 SECRET_KEY` | JWT encoding with HMAC |
| **Cryptographer (MAC)** | `from jose import jwt` | Python-jose JWT import |
| **Cryptographer (Sig)** | `jwt.encode RS256 private_key` | JWT encoding with RSA signature |
| **Cryptographer (Sig)** | `jwt.decode public_key RS256` | JWT verification with public key |
| **Key Manager (RSA)** | `rsa.generate_private_key public_exponent` | RSA key generation |
| **Key Manager (RSA)** | `from cryptography.hazmat.primitives.asymmetric import rsa` | RSA key management imports |
| **Token Generator** | `def create_access_token jwt.encode` | Access token creation functions |
| **Token Generator** | `jwt.encode exp sub` | JWT encoding with expiration and subject |
| **Registrar** | `@app.post /token create_access_token` | Token issuance endpoints |
| **Registrar** | `return access_token token_type bearer` | Token response formatting |
| **Token Blacklist** | `redis.sadd revoked_tokens jwt` | Token revocation with Redis |
| **Token Blacklist** | `blacklist.revoke token` | Token blacklist management |

---

## 3. Opaque Token-Based Authentication (Session)

| Role | Zoekt Query | Description |
|------|-------------|-------------|
| **Enforcer** | `APIKeyCookie name session_id` | Cookie-based session enforcement |
| **Enforcer** | `APIKeyHeader X-Session-Token` | Header-based session enforcement |
| **Verifier** | `async def verify_session session_manager` | Session verification functions |
| **Verifier** | `session_id HTTPException 401` | Session validation with error handling |
| **Principal Provider (Redis)** | `redis.setex session: principal` | Redis session storage |
| **Principal Provider (Redis)** | `await redis.get session:` | Async Redis session retrieval |
| **Principal Provider (Memory)** | `TTLCache maxsize ttl` | In-memory session cache |
| **Token Generator** | `secrets.token_urlsafe secrets.token_hex` | Secure session token generation |
| **Token Generator** | `session_id = secrets.token` | Session ID generation |
| **Registrar** | `@app.post /login response.set_cookie session_id` | Login with session cookie creation |
| **Registrar** | `redis.setex httponly secure` | Session registration with secure cookies |
| **Session Manager** | `class SessionManager create_session` | Session management class |
| **Session Manager** | `async def get_principal async def invalidate_session` | Session lifecycle methods |
| **Session Manager** | `session_timeout absolute_timeout` | Session timeout configuration |

---

## 4. Session-Based Access Control

| Role | Zoekt Query | Description |
|------|-------------|-------------|
| **Authentication Enforcer** | `APIKeyCookie session_id Depends` | Session-based authentication enforcement |
| **Verifier** | `session_manager.get_session HTTPException` | Session verification with error handling |
| **Session Manager** | `class SessionManager permissions role` | Session manager with authorization data |
| **Session Manager** | `redis.setex session: SessionData.json` | Session storage with permissions |
| **Session ID Generator** | `secrets.token_urlsafe 32` | Session ID generation (32 bytes) |
| **Authorization Enforcer** | `class AuthorizationChecker required_permissions` | Authorization enforcement class |
| **Authorization Enforcer** | `def __call__ session_id required_permissions` | Authorization checker callable |
| **Decider** | `required_permissions.issubset session.permissions` | Permission checking logic |
| **Decider** | `HTTPException 403 Missing permissions` | Authorization denial |
| **Policy Provider** | `class PolicyProvider get_role_permissions` | Policy management class |
| **Policy Provider** | `role_permissions user_roles` | Role-permission mapping |
| **Policy Provider** | `db.query Role permissions` | Database role queries |
| **Registrar** | `create_session policy_provider.get_user_permissions` | Session creation with permissions |
| **Combined Enforcer** | `async def verify_credentials session.permissions` | Combined auth+authz verification |

---

## 5. Obscure Token-Based Access Control (API Keys)

| Role | Zoekt Query | Description |
|------|-------------|-------------|
| **Enforcer** | `APIKeyHeader X-API-Key auto_error` | API key header enforcement |
| **Enforcer** | `APIKeyQuery api_key Security` | API key query parameter enforcement |
| **Validator (Combined)** | `class APIKeyValidator required_permissions` | Combined auth+authz validator |
| **Validator** | `validate_token HTTPException 401 403` | API key validation with auth/authz errors |
| **Hasher** | `hashlib.sha256 token.encode hexdigest` | Token hashing with SHA-256 |
| **Hasher** | `hashlib.blake2b token_hash` | Token hashing with BLAKE2b |
| **Token Manager** | `class APIKey token_hash principal permissions` | API key database model |
| **Token Manager** | `db.query APIKey token_hash` | API key database queries |
| **Token Generator** | `secrets.token_urlsafe 32` | Secure API key generation (32+ bytes) |
| **Registrar** | `@app.post /api-keys secrets.token` | API key creation endpoint |
| **Registrar** | `token_hash = hashlib.sha256 db.add APIKey` | API key registration with hashing |
| **Registrar** | `return api_key Save this key` | API key response (shown once) |
| **Permission Checker** | `token_info.permissions HTTPException 403` | Permission verification |
| **Revocation** | `@app.delete /api-keys db.delete` | API key revocation endpoint |

---

## Cross-Pattern Queries

### Database Integration (Password Store, Token Manager, Policy Provider)

| Component | Zoekt Query | Description |
|-----------|-------------|-------------|
| **SQLAlchemy Models** | `class User Base __tablename__` | SQLAlchemy user model definitions |
| **SQLAlchemy Queries** | `db.query User filter username` | User database queries |
| **Tortoise ORM** | `from tortoise import fields models` | Tortoise ORM imports |
| **Tortoise Queries** | `await User.get username` | Async user queries |
| **Database Session** | `SessionLocal sessionmaker create_engine` | Database session management |

### Redis Integration (Session Storage, Token Blacklist)

| Component | Zoekt Query | Description |
|-----------|-------------|-------------|
| **Redis Connection** | `redis.from_url redis://` | Redis connection setup |
| **Redis Session** | `redis.setex session: ttl` | Session storage with expiration |
| **Redis Async** | `await redis.get await redis.setex` | Async Redis operations |
| **Redis Set Operations** | `redis.sadd redis.sismember` | Set operations for blacklists |

### Cryptography Operations (Hasher, Encrypter, Key Manager)

| Component | Zoekt Query | Description |
|-----------|-------------|-------------|
| **Passlib** | `from passlib.context import CryptContext` | Passlib password hashing |
| **Bcrypt** | `import bcrypt hashpw gensalt` | Bcrypt password hashing |
| **Fernet Encryption** | `from cryptography.fernet import Fernet` | Symmetric encryption |
| **RSA Keys** | `from cryptography.hazmat.primitives.asymmetric` | Asymmetric cryptography |
| **JWT Operations** | `from jose import jwt encode decode` | JWT token operations |
| **Secure Random** | `import secrets token_urlsafe` | Cryptographically secure random |

---

## Advanced Zoekt Queries

### Finding Complete Pattern Implementations

| Pattern | Zoekt Query | Description |
|---------|-------------|-------------|
| **Complete Password Auth** | `OAuth2PasswordBearer CryptContext pwd_context.hash pwd_context.verify lang:python` | Files with complete password authentication |
| **Complete JWT Auth** | `HTTPBearer jwt.encode jwt.decode SECRET_KEY lang:python` | Files with complete JWT authentication |
| **Complete Session Auth** | `APIKeyCookie secrets.token redis.setex response.set_cookie lang:python` | Files with complete session authentication |
| **Complete API Key** | `APIKeyHeader hashlib.sha256 secrets.token db.query APIKey lang:python` | Files with complete API key authentication |

### Finding Security Anti-Patterns

| Anti-Pattern | Zoekt Query | Description |
|--------------|-------------|-------------|
| **Weak Password Storage** | `password = User.password -hash -bcrypt -crypt` | Passwords stored without hashing |
| **Hardcoded Secrets** | `SECRET_KEY = "` | Hardcoded secret keys |
| **No HTTPS** | `set_cookie -secure -httponly` | Cookies without security flags |
| **Weak Random** | `random.randint -secrets -uuid4` | Weak random number generation |
| **SQL Injection Risk** | `f"SELECT * FROM users WHERE username = '{username}'"` | String interpolation in SQL |

### Finding Authentication Endpoints

| Endpoint Type | Zoekt Query | Description |
|---------------|-------------|-------------|
| **Login** | `@app.post /login /signin /auth` | Login endpoint definitions |
| **Registration** | `@app.post /register /signup` | Registration endpoints |
| **Logout** | `@app.post /logout invalidate delete_cookie` | Logout endpoints |
| **Token Refresh** | `@app.post /refresh /token/refresh` | Token refresh endpoints |
| **Password Reset** | `@app.post /reset-password /forgot-password` | Password reset endpoints |

### Finding Authorization Logic

| Authorization Type | Zoekt Query | Description |
|-------------------|-------------|-------------|
| **Permission Checks** | `required_permissions HTTPException 403` | Permission verification code |
| **Role Checks** | `role == Role.ADMIN session.role` | Role-based access control |
| **Scope Checks** | `SecurityScopes scopes` | OAuth2 scope verification |
| **Resource Ownership** | `if user.id == resource.owner_id` | Resource ownership checks |

---

## File Type Filters

Add these to any query to filter by file type:

| Filter | Zoekt Syntax | Description |
|--------|-------------|-------------|
| **Python Files** | `lang:python` | Only Python files |
| **Python Files** | `f:\\.py$` | Files ending in .py |
| **Config Files** | `file:config file:settings` | Configuration files |
| **Main/Init Files** | `file:__init__ file:main` | Main entry points |
| **Test Files** | `file:test_ file:_test` | Test files |
| **Exclude Tests** | `-file:test -file:_test` | Exclude test files |

---

## Repository Filters

Filter searches by repository characteristics:

| Filter | Zoekt Syntax | Description |
|--------|-------------|-------------|
| **FastAPI Repos** | `r:fastapi` | Repositories with "fastapi" in name |
| **Python Repos** | `lang:python r:api r:auth` | Python repos with api/auth in name |
| **Exclude Forks** | `fork:no` | Exclude forked repositories |
| **Archived** | `archived:no` | Exclude archived repositories |
| **Public Only** | `public:yes` | Only public repositories |

---

## Combined Query Examples

### Example 1: Find Password Authentication in FastAPI Projects
```
OAuth2PasswordBearer CryptContext lang:python f:\.py$ fork:no archived:no
```

### Example 2: Find JWT Token Generation with RS256
```
jwt.encode RS256 private_key create_access_token lang:python -file:test
```

### Example 3: Find Session Management with Redis
```
APIKeyCookie redis.setex session: response.set_cookie httponly lang:python
```

### Example 4: Find API Key Authentication
```
APIKeyHeader hashlib.sha256 token_hash permissions lang:python -file:test
```

### Example 5: Find Complete Session-Based Access Control
```
APIKeyCookie required_permissions session.permissions HTTPException 403 lang:python
```

### Example 6: Find Secure Cookie Implementation
```
set_cookie httponly secure samesite session_id lang:python
```

### Example 7: Find Password Reset Implementation
```
@app.post reset-password secrets.token send_email lang:python
```

### Example 8: Find Multi-Factor Authentication
```
OAuth2PasswordBearer pyotp totp verify lang:python
```

---

## Pattern Detection Strategy

For each security pattern, use this search strategy:

### 1. **Identify Enforcer** (Entry Point)
Search for FastAPI security dependencies to find files that enforce authentication.

### 2. **Identify Verifier** (Core Logic)
Search for verification functions that validate credentials/tokens.

### 3. **Identify Storage** (Persistence)
Search for database models and Redis operations for credential/session storage.

### 4. **Identify Generators** (Token/Password Creation)
Search for functions that create new credentials or tokens.

### 5. **Verify Complete Implementation**
Combine all role queries to find files with complete pattern implementations.

---

## Query Optimization Tips

1. **Start Broad**: Begin with key terms like `OAuth2PasswordBearer` or `jwt.encode`
2. **Add Context**: Add co-occurring terms like `CryptContext lang:python`
3. **Filter Noise**: Use `-file:test` to exclude test files
4. **Use Case Sensitivity**: Use `case:yes` for exact class/function names
5. **Combine Related Terms**: Use space for AND, `OR` for alternatives
6. **Exclude Negations**: Use `-term` to exclude unwanted matches
7. **File Extensions**: Use `f:\.py$` to ensure Python files only
8. **Repository Quality**: Add `fork:no archived:no` for active projects

---

## Usage in SecPat Tool

To use these queries in your SecPat pipeline:

```python
# Example: Search for Password-Based Authentication Enforcer
query = "OAuth2PasswordBearer OAuth2PasswordRequestForm lang:python"
results = zoekt_search(query, repository_path)

# Example: Find complete JWT implementation
query = "HTTPBearer jwt.encode jwt.decode SECRET_KEY lang:python -file:test"
results = zoekt_search(query, repository_path)

# Example: Multi-role search for Session-Based Access Control
queries = {
    "enforcer": "APIKeyCookie session_id Depends",
    "verifier": "session_manager.get_session HTTPException",
    "policy_provider": "get_role_permissions user_roles",
    "decider": "required_permissions.issubset HTTPException 403"
}

for role, query in queries.items():
    results[role] = zoekt_search(f"{query} lang:python", repo_path)
```

