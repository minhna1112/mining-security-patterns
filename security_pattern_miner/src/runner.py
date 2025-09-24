


if __name__ == "__main__":
    
    from dependent_miner.python import PythonDependentMiner
    python_dependent_miner = PythonDependentMiner()
    # python_dependent_miner.get_dependents("flask")
    # python_dependent_miner.clean_saved_dependents("flask")
    
    # # Token-based authentication
    # token_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "pyjwt"])
    # python_dependent_miner.save_mutual_dependents(["fastapi", "pyjwt"], token_based_auth_repos)
    # # Password-based authentication
    # password_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "passlib"])
    # python_dependent_miner.save_mutual_dependents(["fastapi", "passlib"], password_based_auth_repos)


    # Password-based and token-based authentication
    password_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "passlib", "pyjwt"])
    saved_jsonl_path = python_dependent_miner.save_mutual_dependents(["fastapi", "passlib", "pyjwt"], password_based_auth_repos)


    from repo_crawler.base import GitCrawler
    git_crawler = GitCrawler()
    dependent_repos = git_crawler.load_dependedent_repos_info(saved_jsonl_path)
    git_crawler.crawl_from_dependent_repos_info(dependent_repos)