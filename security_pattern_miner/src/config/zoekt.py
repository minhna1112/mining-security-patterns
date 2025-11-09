import sys; sys.path.append("..")
from config.constants import NUM_CONTEXT_LINES
from enum import Enum
import os

class ZoektConfig():
    """
    Configuration class for search settings.
    """
    num_context_lines: int = os.getenv('NUM_CONTEXT_LINES', NUM_CONTEXT_LINES)
    max_results: int = os.getenv('MAX_RESULTS', 10)
    max_retries: int = os.getenv('MAX_RETRIES', 3)
    retry_delay: float = os.getenv('RETRY_DELAY', 0.2)
    zoekt_url: str = os.getenv('ZOEKT_URL', 'http://localhost:6070/api/search')
    max_candidates_used: int = os.getenv('MAX_CANDIDATES_USED', 10)
