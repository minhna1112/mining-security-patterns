


import os
from utils.logger import logger
import logging
from dependent_miner.python import PythonDependentMiner
from repo_crawler.base import GitCrawler
from config.constants import PYTHON, PYPI
from config.crawler import GitCrawlerConfig
from config.libraries_io import LibrariesIOConfig


class Pipeline:
    def __init__(self, args):
        if args.language.lower() != PYTHON or args.package_manager != PYPI:
            raise ValueError("Currently, only Python language with PyPI package manager is supported.")
        
        self.args = args
        if args.max_pages:
            LibrariesIOConfig.max_num_pages = args.max_pages
        if args.per_page:
            LibrariesIOConfig.max_per_page = args.per_page
        if args.start_page:
            LibrariesIOConfig.start_page = args.start_page
        if args.start_index is not None:
            GitCrawlerConfig.start_index = args.start_index
        if args.end_index is not None:
            GitCrawlerConfig.end_index = args.end_index
        if args.root_data_dir:
            LibrariesIOConfig.root_data_dir = args.root_data_dir
            LibrariesIOConfig.dependent_repo_info_save_dir = os.path.join(args.root_data_dir, "dependent_repos_info")
            GitCrawlerConfig.root_data_dir = args.root_data_dir
            GitCrawlerConfig.cloned_repos_dir = os.path.join(args.root_data_dir, "cloned_repos")

        self.dependent_miner = PythonDependentMiner(LibrariesIOConfig)
        self.repo_crawler = GitCrawler(GitCrawlerConfig)

    def run(self, package_names: list[str]):
        if self.args.get_dependents:
            # Step 0 Get each package's dependents and save to files
            for pkg in package_names:
                self.dependent_miner.get_dependents(pkg)
                self.dependent_miner.clean_saved_dependents(pkg)
            if len(package_names) < 2:
                logger.warning("At least two package names are required to find mutual dependents. Stopping")
                return
        
        if self.args.crawl_only:
            # Step 1: Find mutual dependents
            mutual_dependents = self.dependent_miner.find_mutual_dependents(package_names)
            logger.info(f"Found {len(mutual_dependents)} mutual dependents for packages: {package_names}")

            # Step 2: Save mutual dependents to a JSONL file
            saved_jsonl_path = self.dependent_miner.save_mutual_dependents(package_names, mutual_dependents)
            logger.info(f"Saved mutual dependents to {saved_jsonl_path}")

            # Step 3: Load dependent repository info from the saved JSONL file
            dependent_repos = self.repo_crawler.load_dependedent_repos_info(saved_jsonl_path)
            logger.info(f"Loaded {len(dependent_repos)} dependent repositories from {saved_jsonl_path}")

            # Step 4: Crawl and clone the dependent repositories
            self.repo_crawler.crawl_from_dependent_repos_info(dependent_repos)
            logger.info("Completed crawling and cloning dependent repositories")
    

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the dependent miner and repo crawler")
    
    # Libaries.io related arguments
    parser.add_argument("--get_dependents", action="store_true", help="Flag to get dependents for the specified package names (from scratch)")
    parser.add_argument("--language", type=str, default=PYTHON, help="Programming language")
    parser.add_argument("--package_manager", type=str, default=PYPI, help="Package manager")
    parser.add_argument("--package_names", type=str, nargs='+', required=True, help="List of package names to find mutual dependents")
    parser.add_argument("--max_pages", type=int, default=2000, help="Maximum number of pages to fetch from Libraries.io")
    parser.add_argument("--per_page", type=int, default=100, help="Number of results per page from Libraries.io")
    parser.add_argument("--start_page", type=int, default=1, help="Starting page number for fetching dependents")
    parser.add_argument("--root_data_dir", type=str, default="/data", help="Directory to save dependent repository info")
    
    
    # Git crawler related arguments
    parser.add_argument("--crawl_only", action="store_true", help="Flag to only crawl repositories from previously saved dependent info")
    parser.add_argument("--start_index", type=int, default=0, help="Start index for crawling repositories")
    parser.add_argument("--end_index", type=int, default=-1, help="End index for crawling repositories")
    args = parser.parse_args()
    
    
    
    pipeline = Pipeline(args)
    # print(args.package_names)
    pipeline.run(args.package_names)
    # python_dependent_miner.get_dependents("flask")
    # python_dependent_miner.clean_saved_dependents("flask")
    
    # # Token-based authentication
    # token_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "pyjwt"])
    # python_dependent_miner.save_mutual_dependents(["fastapi", "pyjwt"], token_based_auth_repos)
    # # Password-based authentication
    # password_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "passlib"])
    # python_dependent_miner.save_mutual_dependents(["fastapi", "passlib"], password_based_auth_repos)


    # # Password-based and token-based authentication
    # password_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "passlib", "pyjwt"])
    # saved_jsonl_path = python_dependent_miner.save_mutual_dependents(["fastapi", "passlib", "pyjwt"], password_based_auth_repos)

    # # Password-based and token-based authentication
    # password_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "passlib", "pyjwt"])
    # saved_jsonl_path = python_dependent_miner.save_mutual_dependents(["fastapi", "passlib", "pyjwt"], password_based_auth_repos)


    # from repo_crawler.base import GitCrawler
    # git_crawler = GitCrawler()
    # dependent_repos = git_crawler.load_dependedent_repos_info(saved_jsonl_path)
    # git_crawler.crawl_from_dependent_repos_info(dependent_repos)