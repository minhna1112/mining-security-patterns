from abc import ABC, abstractmethod
import logging

import requests
from schemas.libraries_io_request import LibrariesIOGetDependentRequest
from schemas.libraries_io_response import DependentRepositoryInfo
from config.libraries_io import LibrariesIOConfig
from utils.libraries_io import get_libraries_io_url
from typing import List
from utils.logger import logger
import json
import jsonlines
from tqdm import tqdm

logger.setLevel(logging.INFO)
class DependentMiner(ABC):
    @abstractmethod
    def get_dependents(self, package_name: str):
        pass

class LibrariesIODependentMiner(DependentMiner):
    def __init__(self, package_manager: str, language: str, config: LibrariesIOConfig):
        super().__init__()
        self.package_manager = package_manager
        self.language = language
        self.config = config

    def get_dependents(self, package_name: str) -> List[DependentRepositoryInfo]:
        num_pages = self.config.start_page
        dependents = []
        while num_pages <= self.config.start_page + self.config.max_num_pages:
            dependents_in_page = self.get_dependents_in_page(
                package_name=package_name,
                page=num_pages,
                per_page=self.config.max_per_page
            )
            if not dependents_in_page:
                break

            if len(dependents_in_page) > self.config.max_per_page:
                logger.warning(f"Received unexpected number of dependents for package {package_name} on page {num_pages}: {len(dependents_in_page)}")
                break
            
            dependents.extend(dependents_in_page)
            # Here you would typically make the API call and process the response
            logger.info(f"Fetched {len(dependents_in_page)} dependents from page {num_pages} for package {package_name}")
            if len(dependents) == 0:
                self.save_dependents_to_file(package_name, dependents_in_page)
            else:
                self.append_dependents_to_file(package_name, dependents_in_page)
            num_pages += 1
            
        return dependents
            
    def get_dependents_in_page(self, 
                               package_name: str, 
                               page: int, 
                               per_page: int) -> List[DependentRepositoryInfo]:
        request = LibrariesIOGetDependentRequest(
            package_manager=self.package_manager,
            package_name=package_name,
            page=page,
            per_page=per_page
        )
        url = get_libraries_io_url(request)
        response = requests.get(url)
        if response.status_code == 200:
            dependents_data = response.json()
            # print(json.dumps(dependents_data, indent=2))
            dependents = [DependentRepositoryInfo(**data) for data in dependents_data]
            return dependents
        else:
            response.raise_for_status()
        # Here you would typically make the API call and process the response
        
    def save_dependents_to_file(self, package_name: str, dependents: List[DependentRepositoryInfo]):
        import os
        if not os.path.exists(self.config.dependent_repo_info_save_dir):
            os.makedirs(self.config.dependent_repo_info_save_dir)
        file_path = os.path.join(self.config.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{self.config.start_page}.jsonl")
        with jsonlines.open(file_path, "w") as f:
            f.write_all([dep.dict() for dep in dependents])
        logger.info(f"Saved {len(dependents)} dependents for package {package_name} to {file_path}")
    
    def merge_dependents_files(self, package_name: str):
        """
        Merge all dependent files for a package into a single file, removing duplicates.
        This means that all files named like {language}_{package_manager}_{package_name}_dependents_*.jsonl
        will be merged into one file named {language}_{package_manager}_{package_name}_dependents_1.jsonl
        """
        import os
        import glob
        if not os.path.exists(self.config.dependent_repo_info_save_dir):
            return
        pattern = os.path.join(self.config.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_*.jsonl")
        files = glob.glob(pattern)
        if not files:
            return
        unique_dependents = {}
        for file in files:
            with jsonlines.open(file, "r") as f:
                for dep in f:
                    unique_dependents[dep['full_name']] = dep
        merged_file_path = os.path.join(self.config.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_1.jsonl")
        with jsonlines.open(merged_file_path, "w") as f:
            f.write_all(unique_dependents.values())
        logger.info(f"Merged {len(files)} files into {merged_file_path} with {len(unique_dependents)} unique dependents")
        
        
    def append_dependents_to_file(self, package_name: str, dependents: List[DependentRepositoryInfo]):
        import os
        if not os.path.exists(self.config.dependent_repo_info_save_dir):
            os.makedirs(self.config.dependent_repo_info_save_dir)
        file_path = os.path.join(self.config.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{self.config.start_page}.jsonl")
        with jsonlines.open(file_path, "a") as f:
            f.write_all([dep.dict() for dep in dependents])
        logger.info(f"Appended {len(dependents)} dependents for package {package_name} to {file_path}")
        
    def clean_saved_dependents(self, package_name: str):
        # Remove duplicated JSON line (dependent ) in previously saved dependents file if exists
        import os
        if not os.path.exists(self.config.dependent_repo_info_save_dir):
            return
        file_path = os.path.join(LibrariesIOConfig.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{LibrariesIOConfig.start_page}.jsonl")
        cleaned_file_path = os.path.join(LibrariesIOConfig.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{LibrariesIOConfig.start_page}_cleaned.jsonl")
        if not os.path.exists(file_path):
            return
        unique_dependents = {}
        with jsonlines.open(file_path, "r") as f:
            for dep in f:
                unique_dependents[dep['full_name']] = dep
        with jsonlines.open(cleaned_file_path, "w") as f:
            f.write_all(unique_dependents.values())
    
    def load_saved_dependents(self, package_name: str) -> List[DependentRepositoryInfo]:
        import os
        if not os.path.exists(self.config.dependent_repo_info_save_dir):
            return []
        file_path = os.path.join(LibrariesIOConfig.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{LibrariesIOConfig.start_page}_cleaned.jsonl")
        if not os.path.exists(file_path):
            return []
        dependents = []
        with jsonlines.open(file_path, "r") as f:
            for dep in f:
                dependents.append(DependentRepositoryInfo(**dep))
        return dependents
            
    def find_mutual_dependents(self, package_names: List[str]) -> List[DependentRepositoryInfo]:
        if len(package_names) < 2:
            logger.warning("At least two package names are required to find mutual dependents.")
            return []
        mutual_dependents = {}
        for pkg in package_names:
            dependents = self.load_saved_dependents(pkg)
            logger.info(f"Loaded {len(dependents)} dependents for package: {pkg}")
            for dep in tqdm(dependents, desc=f"Processing dependents for package: {pkg}"):
                if dep.full_name not in mutual_dependents:
                    mutual_dependents[dep.full_name] = dep
        mutual_dependents = list(mutual_dependents.values())
        mutual_dependents.sort(key=lambda x: x.full_name)
        
        logger.info(f"Found {len(mutual_dependents)} mutual dependents for packages: {', '.join(package_names)}")
        return mutual_dependents

    def save_mutual_dependents(self, package_names: List[str], mutual_dependents: List[DependentRepositoryInfo]):
        import os
        if not os.path.exists(self.config.dependent_repo_info_save_dir):
            os.makedirs(self.config.dependent_repo_info_save_dir)
        package_names_str = "_".join(package_names)
        file_path = os.path.join(self.config.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_mutual_dependents_{package_names_str}.jsonl")
        with jsonlines.open(file_path, "w") as f:
            f.write_all([dep.dict() for dep in mutual_dependents])
        logger.info(f"Saved {len(mutual_dependents)} mutual dependents for packages {package_names_str} to {file_path}")
        return file_path