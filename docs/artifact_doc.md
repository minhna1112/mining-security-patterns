## Project Overview

This is a security pattern mining research project that identifies and analyzes how security libraries are integrated in real-world applications. The pipeline consists of two main phases:

### Phase 1: Repository Mining
1. Queries Libraries.io API to find packages that depend on specific security libraries
2. Identifies repositories that use multiple security packages (mutual dependents)
3. Clones these repositories for analysis
4. Indexes them using Zoekt for searchable code analysis

### Phase 2: Pattern Extraction
1. Loads security pattern metadata from YAML files (based on Van den Berghe's security patterns)
2. Constructs role-specific Zoekt queries for each security pattern
3. Searches indexed repositories using Zoekt to find pattern implementations
4. Extracts code contexts showing how each pattern role is implemented
5. Saves search results with file paths, line numbers, and code snippets

## Key Commands

### Phase 1: Repository Mining

**Full pipeline (fetch + crawl):**
```bash
python security_pattern_miner/src/runner.py \
  --get_dependents \
  --package_names fastapi passlib \
  --language python \
  --package_manager Pypi \
  --root_data_dir=./build/volumes/data \
  --max_pages=10 \
  --per_page=100
```

**Crawl only (using previously fetched data):**
```bash
python security_pattern_miner/src/runner.py \
  --crawl_only \
  --package_names fastapi passlib \
  --language python \
  --package_manager Pypi \
  --root_data_dir=./build/volumes/data \
  --start_index=0 \
  --end_index=10
```

**Clean saved dependent files:**
```bash
python security_pattern_miner/src/runner.py \
  --clean_only \
  --package_names fastapi passlib \
  --language python \
  --package_manager Pypi
```

### Phase 2: Pattern Extraction

**Construct queries only:**
```bash
python security_pattern_miner/src/runner.py \
  --construct_queries \
  --pattern password_based_authentication \
  --web_framework fastapi \
  --language python \
  --root_data_dir=./build/volumes/data
```

**Construct and search queries:**
```bash
python security_pattern_miner/src/runner.py \
  --construct_queries \
  --search_queries \
  --pattern password_based_authentication \
  --web_framework fastapi \
  --language python \
  --root_data_dir=./build/volumes/data \
  --zoekt_url=http://localhost:6070/api/search
```

### Using Docker Compose

**Run mining service:**
```bash
docker compose up security_pattern_miner
```

**Run extraction service (with search):**
```bash
docker compose up security_pattern_extractor
```

**Run Zoekt services:**
```bash
# Start indexer (one-time or periodic re-indexing)
docker compose up zoekt-indexer

# Start web server (for search interface and API)
docker compose up zoekt-webserver
```

**Access Zoekt web search interface:**
```
http://localhost:6070
```

## Architecture

### Core Components

**1. Security Pattern Miner** (`SecurityPatternMiner` class)
- Queries Libraries.io API to find packages that depend on target security libraries
- Supports Python (PyPI) and Java (Maven)
- Key operations:
  - `get_dependents()` - Fetches paginated dependents from Libraries.io API
  - `find_mutual_dependents()` - Finds intersection of dependent repos across multiple packages
  - `save_mutual_dependents()` - Persists results to JSONL format
  - `clean_saved_dependents()` - Deduplicates saved files

**2. Repository Crawler** (`repo_crawler.base.GitCrawler`)
- Clones GitHub repositories using GitPython
- Requires GitHub authentication via environment variables
- Key operations:
  - `crawl()` - Clones single repository
  - `crawl_from_dependent_repos_info()` - Bulk cloning with progress tracking
  - `load_dependedent_repos_info()` - Loads JSONL repo metadata

**3. Security Pattern Extractor** (`SecurityPatternExtractor` class)
- Constructs Zoekt queries from security pattern metadata (YAML files)
- Searches indexed repositories for pattern implementations
- Extracts code contexts for each pattern role
- Key operations:
  - `construct_queries()` - Builds queries from YAML pattern definitions
  - `search_and_save_results()` - Executes Zoekt searches and saves results

**4. Queries Loader** (`context_retriever.queries_loader.QueriesLoader`)
- Loads security pattern metadata from YAML files
- Maps pattern roles to specific API signatures and usage patterns
- Generates repository-specific queries
- Key operations:
  - `load_from_pattern_metadata_file()` - Parses YAML pattern definitions
  - `load_queries()` - Creates Query objects for each role/repo combination
  - `save_queries_to_file()` - Persists queries to JSONL

**5. Zoekt Search Requester** (`context_retriever.zoekt_retriever.ZoektSearchRequester`)
- Interfaces with Zoekt search API
- Processes search results and extracts code contexts
- Key operations:
  - `zoekt_search_request()` - Sends search queries to Zoekt API
  - `post_process_search_results()` - Extracts file paths, line numbers, snippets
  - `search_queries_and_save()` - Batch search with result aggregation
  - `save_search_results_to_file()` - Persists SearchedResponse objects to JSONL

**6. Code Indexer (Zoekt)**
- Creates searchable indexes of cloned repositories
- Two services:
  - `zoekt-indexer` - Builds indexes from cloned repos
  - `zoekt-webserver` - Provides web search interface on port 6070 and REST API

### Data Flow

```
Phase 1: Mining
SecurityPatternMiner.run()
  ├─ dependent_miner.get_dependents()          [Fetch from Libraries.io API]
  ├─ dependent_miner.find_mutual_dependents()  [Find intersection across packages]
  ├─ dependent_miner.save_mutual_dependents()  [Save to JSONL]
  └─ repo_crawler.crawl_from_dependent_repos_info() [Clone repositories]
       └─ Stored in: build/volumes/data/cloned_repos/
            └─ Indexed by Zoekt in: build/volumes/zoekt/index-data/

Phase 2: Extraction
SecurityPatternExtractor.run()
  ├─ query_constructor.load_from_pattern_metadata_file() [Load YAML]
  ├─ query_constructor.load_queries()          [Generate queries]
  ├─ query_constructor.save_queries_to_file()  [Save queries to JSONL]
  └─ zoekt_searcher.search_queries_and_save()  [Search & extract contexts]
       └─ Saved to: build/volumes/data/search_results/
```

### Directory Structure

```
security_pattern_miner/
├── src/
│   ├── config/              # Configuration (API keys, constants, paths)
│   │   ├── constants.py     # Language/platform constants
│   │   ├── libraries_io.py  # Libraries.io API config
│   │   ├── crawler.py       # Git crawler config
│   │   ├── queries_loader.py # Query construction config
│   │   └── zoekt.py         # Zoekt search config
│   ├── dependent_miner/     # Libraries.io API integration
│   │   ├── base.py          # Abstract base + LibrariesIODependentMiner
│   │   ├── python.py        # PyPI implementation
│   │   └── java.py          # Maven implementation
│   ├── repo_crawler/        # Git repository cloning
│   │   └── base.py          # GitCrawler implementation
│   ├── context_retriever/   # Query construction & search
│   │   ├── queries_loader.py      # YAML to queries
│   │   ├── zoekt_retriever.py     # Zoekt search integration
│   │   └── queries_library/       # YAML pattern definitions
│   │       └── python/fastapi/patterns/
│   │           └── password_based_authentication.yaml
│   ├── schemas/             # Pydantic data models
│   ├── utils/               # Helper functions (API, GitHub, logging)
│   └── runner.py            # Main entry point
│
build/volumes/data/
├── dependent_repos_info/    # JSONL files with repo metadata
├── cloned_repos/            # Cloned GitHub repositories
├── output_queries/          # Generated Zoekt queries (JSONL)
└── search_results/          # Search results with code contexts (JSONL)

zoekt/                       # Submodule for code search/indexing
build/volumes/zoekt/
└── index-data/              # Zoekt search indexes
```

## Important Implementation Details

### Phase 1: Mining

**Libraries.io API Integration**
- API key required: set `LIBRARIES_IO_API_KEY` in `.env`
- Paginated requests: configure `--max_pages` and `--per_page`
- Results saved to: `build/volumes/data/dependent_repos_info/<package>_dependents.jsonl`
- Mutual dependents saved to: `build/volumes/data/dependent_repos_info/<package1>_<package2>_mutual_dependents.jsonl`

**Git Repository Cloning**
- GitHub authentication: set `GITHUB_TOKEN` in `.env`
- Clones stored in: `build/volumes/data/cloned_repos/`
- Use `--start_index` and `--end_index` to clone specific ranges
- Skips repositories that already exist locally

**Zoekt Indexing**
- Automatically indexes all repositories in `cloned_repos/`
- Index stored in: `build/volumes/zoekt/index-data/`
- Supports both Git repositories and regular directories
- Re-run `zoekt-indexer` service to update indexes

### Phase 2: Extraction

**Pattern Metadata (YAML)**
- Located in: `context_retriever/queries_library/python/fastapi/patterns/`
- Defines pattern roles and their corresponding queries
- Maps roles to specific API signatures from security libraries
- Example: `password_based_authentication.yaml`

**Query Construction**
- Reads YAML files containing pattern definitions
- For each role, generates queries with:
  - Library-specific API signatures (e.g., `pwd_context.hash(`)
  - Language filters (e.g., `lang:python`)
  - Repository constraints (e.g., `r:github.com/owner/repo`)
- Queries saved to: `build/volumes/data/output_queries/<pattern>_<framework>_queries.jsonl`

**Zoekt Search**
- Sends queries to Zoekt API at configured URL
- Extracts code contexts including:
  - File path
  - Start and end line numbers
  - Code snippet (configurable: context lines or whole file)
- Search results saved to: `build/volumes/data/search_results/<pattern>_<framework>_search_results.jsonl`

**Search Result Schema**
```json
{
  "repo": "github.com/owner/repo",
  "role": "hasher",
  "query": "pwd_context.hash lang:python r:github.com/owner/repo",
  "webframework": "fastapi",
  "pattern": "password_based_authentication",
  "success": true,
  "contexts": [
    {
      "filepath": "owner_repo/app/security.py",
      "start_line": 10,
      "end_line": 15,
      "snippet": "def hash_password(password: str):\n    return pwd_context.hash(password)"
    }
  ]
}
```

### Supported Security Patterns

Based on Van den Berghe's security patterns:
1. **Password-Based Authentication** - Dependencies: `fastapi`, `passlib`
2. **Verifiable Token-Based Authentication** - Dependencies: `fastapi`, `pyjwt` or `python-jose`
3. **Opaque Token-Based Authentication** - Dependencies: `fastapi`, `redis` or caching libraries
4. **Session-Based Access Control** - Dependencies: `fastapi`, `redis`, database ORMs
5. **Obscure Token-Based Access Control** - Dependencies: `fastapi`, database ORMs

### Data Models

**Query** (Pydantic model):
- `repo`: Repository full name
- `role`: Security pattern role (e.g., "hasher", "enforcer")
- `query`: Zoekt search query string
- `webframework`: Web framework name
- `pattern`: Security pattern name

**Context** (Pydantic model):
- `filepath`: Relative path to source file
- `start_line`: Starting line number
- `end_line`: Ending line number
- `snippet`: Code snippet or full file content

**SearchedResponse** (extends Query):
- Inherits all Query fields
- `success`: Boolean indicating if search found results
- `contexts`: List of Context objects

## Configuration Files

**Environment Variables** (`.env`):
- `LIBRARIES_IO_API_KEY` - Libraries.io API key
- `GITHUB_TOKEN` - GitHub personal access token
- `ZOEKT_URL` - Zoekt API endpoint (default: `http://localhost:6070/api/search`)
- `NUM_CONTEXT_LINES` - Number of context lines around matches
- `MAX_RESULTS` - Maximum results per query
- `GET_WHOLE_FILE` - Whether to retrieve entire file or just context

**Docker Configuration** (`docker-compose.yml`):
- `security_pattern_miner` - Phase 1: Mine repositories
- `security_pattern_extractor` - Phase 2: Extract patterns (includes Zoekt search)
- `zoekt-webserver` - Zoekt search API and web interface
- `zoekt-indexer` - Indexes cloned repositories

**Application Configuration** (`security_pattern_miner/src/config/`):
- `constants.py` - Language/platform constants
- `libraries_io.py` - Libraries.io API settings
- `crawler.py` - Git crawler settings
- `queries_loader.py` - Query construction settings
- `zoekt.py` - Zoekt search settings

## Current Git State

- **Active branch:** `indexer` (Zoekt integration work)
- Build artifacts and cloned repos stored in `build/` (git-ignored)
- Zoekt added as git submodule
- Two-phase pipeline: mining (Phase 1) and extraction (Phase 2)

## Example Workflow

**Complete end-to-end workflow:**

```bash
# 1. Mine repositories that use both FastAPI and Passlib
docker compose up security_pattern_miner

# 2. Index the cloned repositories
docker compose up zoekt-indexer

# 3. Start Zoekt web server
docker compose up -d zoekt-webserver

# 4. Extract password-based authentication pattern implementations
docker compose up security_pattern_extractor

# 5. View results
cat build/volumes/data/search_results/password_based_authentication_fastapi_search_results.jsonl
```

**Manual workflow for testing:**

```bash
# Phase 1: Mining
python src/runner.py \
  --get_dependents \
  --package_names fastapi passlib \
  --language python \
  --package_manager Pypi \
  --root_data_dir=./build/volumes/data

# Index with Zoekt
docker compose up zoekt-indexer

# Phase 2: Extraction
python src/runner.py \
  --construct_queries \
  --search_queries \
  --pattern password_based_authentication \
  --web_framework fastapi \
  --language python \
  --root_data_dir=./build/volumes/data
```
