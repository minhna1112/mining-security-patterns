# Security Pattern Zoekt Query Definitions

This directory contains YAML files defining Zoekt search queries for detecting security pattern implementations in Python FastAPI codebases. These files are used by the `SecurityPatternExtractor` to construct role-specific queries for finding pattern implementations in indexed repositories.

## Purpose

The YAML files serve as metadata for each security pattern, mapping pattern roles (from Van den Berghe's security patterns) to concrete implementation signatures found in security libraries. The `QueriesLoader` reads these files and generates Zoekt queries that search for specific API usage patterns in repositories.

## Files Structure

```
context_retriever/queries_library/
└── python/
    └── fastapi/
        └── patterns/
            ├── password_based_authentication.yaml
            ├── verifiable_token_authentication.yaml (planned)
            ├── opaque_token_authentication.yaml (planned)
            ├── session_based_access_control.yaml (planned)
            └── obscure_token_access_control.yaml (planned)
```

### Currently Implemented

1. **password_based_authentication.yaml** - Password-Based Authentication pattern

### Planned

2. **verifiable_token_authentication.yaml** - Verifiable Token-Based Authentication (JWT) pattern
3. **opaque_token_authentication.yaml** - Opaque Token-Based Authentication (Session) pattern
4. **session_based_access_control.yaml** - Session-Based Access Control pattern
5. **obscure_token_access_control.yaml** - Obscure Token-Based Access Control (API Keys) pattern

## YAML Structure

Each YAML file follows this structure:

```yaml
pattern:
  name: "Pattern Name"
  id: "01_01_XXX"  # Van den Berghe catalogue ID
  description: "Brief description of the pattern"
  language: python
  web_framework: fastapi

# Repositories metadata file (from Phase 1: Mining)
repo_metadata_file:
  - "fastapi_passlib_mutual_dependents.jsonl"

# Dependencies required for this pattern
dependencies:
  - fastapi
  - passlib

# Pattern roles and their search queries
roles:
  role_name:
    description: "What this role does in the pattern"
    queries:
      - query: "specific_api_call("
        description: "What this query finds"
        priority: high  # high|medium|low
      - query: "another_signature"
        description: "Alternative implementation"
        priority: medium

  another_role:
    description: "Another role description"
    queries:
      - query: "role_specific_api"
        description: "Query description"
        priority: high

# Optional: queries for complete implementations
complete_implementation:
  description: "Queries for finding complete pattern implementations"
  queries:
    - query: "term1 AND term2 AND term3"
      description: "What complete implementation looks like"
      priority: critical
      min_matches: 3  # minimum terms that should match

# Optional: endpoint patterns to search for
endpoints:
  endpoint_type:
    - "/login"
    - "/register"
    - "/auth/token"

# Optional: anti-patterns to detect
anti_patterns:
  description: "Security anti-patterns to detect"
  pattern_name:
    query: "dangerous_pattern"
    severity: critical  # critical|high|medium|low
    description: "Why this is dangerous"

# Optional: search filters
filters:
  language: python
  file_extension: "\\.py$"
  exclude_tests: true
  exclude_patterns:
    - "test_"
    - "tests/"
```

## How It Works

### 1. Loading Pattern Metadata

```python
# In SecurityPatternExtractor
self.query_constructor = QueriesLoader(
    language="python",
    pattern="password_based_authentication",
    web_framework="fastapi",
    config=QueriesLoaderConfig
)

# Load YAML file
self.query_constructor.load_from_pattern_metadata_file(
    file_path="./context_retriever/queries_library/python/fastapi/patterns/password_based_authentication.yaml"
)
```

### 2. Generating Queries

For each role in the YAML file, the `QueriesLoader`:
1. Reads the `repo_metadata_file` to get list of repositories from Phase 1
2. For each repository and each role:
   - Takes the query string from YAML
   - Adds language filter: `lang:python`
   - Adds repository constraint: `r:github.com/owner/repo`
   - Creates a `Query` object

Example transformation:
```yaml
# YAML
roles:
  hasher:
    queries:
      - query: "pwd_context.hash("
```

Becomes:
```python
Query(
    repo="github.com/owner/repo",
    role="hasher",
    query="pwd_context.hash( lang:python r:github.com/owner/repo",
    webframework="fastapi",
    pattern="password_based_authentication"
)
```

### 3. Searching with Zoekt

The generated queries are sent to Zoekt, which:
1. Searches the indexed codebases
2. Returns file matches with line numbers
3. Extracts code snippets showing the implementation

### 4. Output Format

Queries are saved to: `build/volumes/data/output_queries/<pattern>_<framework>_queries.jsonl`

Search results are saved to: `build/volumes/data/search_results/<pattern>_<framework>_search_results.jsonl`

## Example: Password-Based Authentication

### YAML Definition (simplified)

```yaml
pattern:
  name: "Password-Based Authentication"
  id: "01_01_password_based_authentication"
  
repo_metadata_file:
  - "fastapi_passlib_mutual_dependents.jsonl"

dependencies:
  - fastapi
  - passlib

roles:
  enforcer:
    description: "Enforces authentication requirement"
    queries:
      - query: "OAuth2PasswordBearer("
        description: "FastAPI OAuth2 password flow"
        priority: high
      - query: "OAuth2PasswordRequestForm"
        description: "Form for password authentication"
        priority: high

  hasher:
    description: "Hashes passwords for storage"
    queries:
      - query: "pwd_context.hash("
        description: "Passlib password hashing"
        priority: high
      - query: "CryptContext(schemes="
        description: "Passlib context initialization"
        priority: high

  comparator:
    description: "Verifies password against hash"
    queries:
      - query: "pwd_context.verify("
        description: "Passlib password verification"
        priority: high
```

### Generated Queries

If repository `github.com/user/fastapi-auth-app` is in the metadata file:

```json
[
  {
    "repo": "github.com/user/fastapi-auth-app",
    "role": "enforcer",
    "query": "OAuth2PasswordBearer( lang:python r:github.com/user/fastapi-auth-app",
    "webframework": "fastapi",
    "pattern": "password_based_authentication"
  },
  {
    "repo": "github.com/user/fastapi-auth-app",
    "role": "hasher",
    "query": "pwd_context.hash( lang:python r:github.com/user/fastapi-auth-app",
    "webframework": "fastapi",
    "pattern": "password_based_authentication"
  },
  {
    "repo": "github.com/user/fastapi-auth-app",
    "role": "comparator",
    "query": "pwd_context.verify( lang:python r:github.com/user/fastapi-auth-app",
    "webframework": "fastapi",
    "pattern": "password_based_authentication"
  }
]
```

### Search Results

```json
{
  "repo": "github.com/user/fastapi-auth-app",
  "role": "hasher",
  "query": "pwd_context.hash( lang:python r:github.com/user/fastapi-auth-app",
  "webframework": "fastapi",
  "pattern": "password_based_authentication",
  "success": true,
  "contexts": [
    {
      "filepath": "user_fastapi-auth-app/app/auth.py",
      "start_line": 15,
      "end_line": 20,
      "snippet": "def hash_password(password: str) -> str:\n    \"\"\"Hash a password using bcrypt.\"\"\"\n    return pwd_context.hash(password)\n"
    }
  ]
}
```

## Query Syntax

Queries use Zoekt's search syntax, which supports:

- **Literal strings**: `OAuth2PasswordBearer(`
- **Regular expressions**: `pwd_context\.(hash|verify)`
- **Language filters**: `lang:python`
- **Repository filters**: `r:github.com/owner/repo`
- **File filters**: `file:\.py$`
- **Boolean operators**: `term1 AND term2`, `term1 OR term2`
- **Case sensitivity**: Default is case-sensitive

For more details, see [Zoekt documentation](https://github.com/sourcegraph/zoekt).

## Adding New Patterns

To add a new security pattern:

1. **Create YAML file**: `context_retriever/queries_library/python/fastapi/patterns/<pattern_name>.yaml`

2. **Define pattern metadata**:
   ```yaml
   pattern:
     name: "Your Pattern Name"
     id: "XX_XX_pattern_id"
     description: "Pattern description"
   ```

3. **Specify repository metadata file** (from Phase 1):
   ```yaml
   repo_metadata_file:
     - "package1_package2_mutual_dependents.jsonl"
   ```

4. **Define roles and queries**:
   ```yaml
   roles:
     role_name:
       description: "Role description"
       queries:
         - query: "api_signature("
           description: "What this finds"
           priority: high
   ```

5. **Run extraction**:
   ```bash
   python src/runner.py \
     --construct_queries \
     --search_queries \
     --pattern <pattern_name> \
     --web_framework fastapi \
     --language python
   ```

## Best Practices

1. **Query Specificity**: Make queries specific enough to avoid false positives
   - Good: `pwd_context.hash(` (targets specific API)
   - Bad: `hash(` (too generic)

2. **Priority Levels**:
   - `high`: Core pattern implementation signatures
   - `medium`: Alternative implementations or helper functions
   - `low`: Related but not essential patterns

3. **Multiple Queries per Role**: Provide alternatives for different implementations
   ```yaml
   hasher:
     queries:
       - query: "pwd_context.hash("  # Passlib
       - query: "bcrypt.hashpw("      # Direct bcrypt
   ```

4. **Repository Metadata**: Ensure the `repo_metadata_file` matches the output from Phase 1 mining

5. **Testing**: Test queries in Zoekt web interface first (`http://localhost:6070`) before adding to YAML

## Integration with Pipeline

```
Phase 1: Mining
  ├─ Find repositories using security libraries
  ├─ Save to: fastapi_passlib_mutual_dependents.jsonl
  └─ Clone and index repositories

Phase 2: Extraction
  ├─ Load YAML: password_based_authentication.yaml
  ├─ Read repo_metadata_file: fastapi_passlib_mutual_dependents.jsonl
  ├─ Generate queries for each role × repository
  ├─ Search using Zoekt API
  └─ Save results with code contexts
```

## References

- Van den Berghe's security patterns catalog
- FastAPI security documentation
- Passlib documentation
- Python-JOSE documentation
- Zoekt query syntax
