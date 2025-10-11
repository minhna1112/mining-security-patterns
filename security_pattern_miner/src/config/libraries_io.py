import os

class LibrariesIOConfig:
    API_KEY = os.getenv("LIBRARIES_IO_API_KEY")
    max_num_pages = int(os.getenv("LIBRARIES_IO_MAX_NUM_PAGES", 10))
    max_per_page = int(os.getenv("LIBRARIES_IO_MAX_PER_PAGE", 100))
    start_page = int(os.getenv("LIBRARIES_IO_START_PAGE", 1))
    root_data_dir = os.getenv("ROOT_DATA_DIR", "/data")
    dependent_repo_info_save_dir = os.path.join(root_data_dir, "dependent_repos_info_dir")
    max_retries = 3
    retry_delay = 10  # in seconds