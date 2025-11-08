import yaml
import jsonlines
import sys; sys.path.append("..")
from config.constants import  GITHUB, FASTAPI
from config.queries_loader import QueriesLoaderConfig
from typing import List
from  pydantic import BaseModel   
import os

class Query(BaseModel):
    repo: str
    role: str
    query: str
    webframework: str
    pattern: str

class QueriesLoader:
    def __init__(self, language: str, 
                 web_framework: str = FASTAPI,
                 pattern: str = "",
                 config: QueriesLoaderConfig = QueriesLoaderConfig
                 ):
        self.language = language
        self.web_framework = web_framework
        self.yaml_path_postfix = f"{language}/{web_framework}/patterns/{pattern}.yaml"
        self.pattern = pattern
        self.queries: List[Query] = []
        self.config = config

    def load_from_pattern_metadata_file(self, file_path: str):
        with open(file_path, 'r') as file:
            self.metadata = yaml.safe_load(file)
    
    def load_roles(self) -> List[str]:
        return self.metadata.get("roles", [])

    def load_repo_names(self, repo_meta_data_file_path: str) -> List[str]:
        self.repo_names = []
        with jsonlines.open(repo_meta_data_file_path, "r") as repo_data:
            for item in repo_data:
                self.repo_names.append(f"{GITHUB}.com/{item.get('full_name')}")
        # print(self.repo_names)
        return self.repo_names

    def process_query(self, query: str, repo : str) -> str:
        return " ".join([query, f"lang:{self.language}", f"r:{repo}"])

    def load_queries(self) -> List[Query]:
        self.queries: List[Query] = []
        repo_meta_data_file = self.metadata.get("repo_metadata_file", [])[0]
        repo_meta_data_file_path = os.path.join(self.config.repos_name_dir, repo_meta_data_file)
        for repo in self.load_repo_names(repo_meta_data_file_path= repo_meta_data_file_path):
            for role in self.load_roles():
                for query in self.metadata["roles"][role].get("queries", []):
                    self.queries.append(Query(repo=repo, role=role, query=self.process_query(query['query'], repo), webframework=self.web_framework, pattern=self.pattern))
        return self.queries
    
    def save_queries_to_file(self, output_file_path: str):
        with jsonlines.open(output_file_path, "w") as writer:
            for query in self.queries:
                writer.write(query.dict())