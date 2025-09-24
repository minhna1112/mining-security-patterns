import os

class GitCrawlerConfig:
    root_data_dir = os.getenv("ROOT_DATA_DIR", "/data")
    cloned_repos_dir = os.path.join(root_data_dir, "cloned_repos")
    start_index = int(os.getenv("GIT_CRAWLER_START_INDEX", 0))
    max_num_repos = int(os.getenv("GIT_CRAWLER_MAX_NUM_REPOS", 10))