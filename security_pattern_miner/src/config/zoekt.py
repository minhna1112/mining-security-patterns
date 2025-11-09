import sys; sys.path.append("..")
from config.constants import NUM_CONTEXT_LINES
from enum import Enum
import os

class ZoektConfig():
    """
    Configuration class for search settings.
    """
    num_context_lines: int = int(os.getenv('NUM_CONTEXT_LINES', NUM_CONTEXT_LINES))
    max_results: int = int(os.getenv('MAX_RESULTS', 10))
    max_retries: int = int(os.getenv('MAX_RETRIES', 3))
    retry_delay: float = float(os.getenv('RETRY_DELAY', 0.2))
    zoekt_url: str = os.getenv('ZOEKT_URL', 'http://localhost:6070/api/search')
    max_candidates_used: int = int(os.getenv('MAX_CANDIDATES_USED', 10))
    top_k_files: int = int(os.getenv('TOP_K_FILES', 5))
    get_whole_file: bool = os.getenv('GET_WHOLE_FILE', 'False').lower() == 'true'
    root_data_dir: str = os.getenv('ROOT_DATA_DIR', '/data')
    cloned_repos_dir: str = os.path.join(root_data_dir, 'cloned_repos')
    search_results_dir: str = os.path.join(root_data_dir, 'search_results')