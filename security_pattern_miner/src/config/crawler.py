import os

class GitCrawlerConfig:
    git_executable_path = os.getenv("GIT_EXECUTABLE_PATH", "/usr/bin/git")
    git_username = os.getenv("GIT_USERNAME", "")
    git_password = os.getenv("GIT_PASSWORD", "")
    root_data_dir = os.getenv("ROOT_DATA_DIR", "/data")
    cloned_repos_dir = os.path.join(root_data_dir, "cloned_repos")
    start_index = int(os.getenv("GIT_CRAWLER_START_INDEX", 0))
    end_index = int(os.getenv("GIT_CRAWLER_END_INDEX", -1))