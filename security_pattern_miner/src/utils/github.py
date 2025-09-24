import sys; sys.path.append(".")
from config.constants import GITHUB

def is_github(repo_url: str) -> bool:
    return GITHUB in repo_url

def construct_github_repo_url(owner: str, repo_name: str, username: str = "", password: str = "") -> str:
    if username and password:
        return f"https://{username}:{password}@{GITHUB}.com/{owner}/{repo_name}"
    return f"https://{GITHUB}.com/{owner}/{repo_name}"