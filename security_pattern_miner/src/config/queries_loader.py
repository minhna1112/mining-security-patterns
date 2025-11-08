import os

class QueriesLoaderConfig:
    root_data_dir = os.getenv("ROOT_DATA_DIR", "/data")
    repos_name_dir = os.path.join(root_data_dir, "dependent_repos_info")
    output_queries_dir = os.path.join(root_data_dir, "output_queries")