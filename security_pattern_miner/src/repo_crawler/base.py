import os
import logging

import git
from config.crawler import GitCrawlerConfig
git.refresh(GitCrawlerConfig.git_executable_path)
import logging
from git import Repo
    
from schemas.libraries_io_response import DependentRepositoryInfo
from abc import ABC, abstractmethod

from utils.logger import logger
from utils.github import is_github, construct_github_repo_url
from tqdm import tqdm
import jsonlines

logger.setLevel(logging.INFO)


class RepoCrawler(ABC):
    @abstractmethod
    def crawl(self, dependent_repo_url: DependentRepositoryInfo):
        pass
    
    @abstractmethod
    def crawl_from_dependent_repos_info(self, dependent_repos: list[DependentRepositoryInfo]):
        pass
    



class GitCrawler(RepoCrawler):
    def __init__(self):
        super().__init__()
        self.root_data_dir = GitCrawlerConfig.root_data_dir
        self.cloned_repos_dir = GitCrawlerConfig.cloned_repos_dir
        if not os.path.exists(self.cloned_repos_dir):
            os.makedirs(self.cloned_repos_dir)

    def crawl(self, dependent_repo: DependentRepositoryInfo) -> str:
        owner, name = dependent_repo.full_name.split("/")
        repo_name = dependent_repo.full_name.replace("/", "_")
        repo_url = construct_github_repo_url(
            owner=owner,
            repo_name=name,
            username=GitCrawlerConfig.git_username,
            password=GitCrawlerConfig.git_password
        )
        local_path = os.path.join(self.cloned_repos_dir, repo_name)
        if os.path.exists(local_path):
            logger.info(f"Repository {repo_name} already cloned at {local_path}")
            return local_path
        try:
            logger.info(f"Cloning repository {repo_name} from {repo_url} to {local_path}")
            Repo.clone_from(repo_url, local_path)
            logger.info(f"Successfully cloned repository {repo_name} to {local_path}")
            return local_path
        except Exception as e:
            logger.error(f"Failed to clone repository {repo_name} from {repo_url}. Error: {e}")
            return ""

    def crawl_from_dependent_repos_info(self, dependent_repos: list[DependentRepositoryInfo]):
        successfully_cloned = 0
        start_index = GitCrawlerConfig.start_index
        end_index = GitCrawlerConfig.end_index
        for repo in tqdm(dependent_repos[start_index:end_index], desc="Cloning repositories"):
            cloned_path = self.crawl(repo)
            if cloned_path:
                successfully_cloned += 1
            tqdm.write(f"Finished cloning {repo.full_name}")
        logger.info(f"Successfully cloned {successfully_cloned} repositories in total of {end_index - start_index} dependent projects.")

    def load_dependedent_repos_info(self, file_path: str) -> list[DependentRepositoryInfo]:
        if not os.path.exists(file_path):
            logger.error(f"File {file_path} does not exist.")
            return []
        with jsonlines.open(file_path, "r") as f:
            dependent_repos = [DependentRepositoryInfo(**obj) for obj in f]
        logger.info(f"Loaded {len(dependent_repos)} dependent repositories from {file_path}")
        return dependent_repos