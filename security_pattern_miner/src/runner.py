


if __name__ == "__main__":
    
    from dependent_miner.python import PythonDependentMiner
    python_dependent_miner = PythonDependentMiner()
    # python_dependent_miner.get_dependents("fastapi")
    # Token-based authentication
    token_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "pyjwt"])
    python_dependent_miner.save_mutual_dependents(["fastapi", "pyjwt"], token_based_auth_repos)
    # Password-based authentication
    password_based_auth_repos = python_dependent_miner.find_mutual_dependents(["fastapi", "passlib"])
    python_dependent_miner.save_mutual_dependents(["fastapi", "passlib"], password_based_auth_repos)
