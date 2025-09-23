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
logger.setLevel(logging.INFO)
class DependentMiner(ABC):
    @abstractmethod
    def get_dependents(self, package_name: str):
        pass

class LibrariesIODependentMiner(DependentMiner):
    def __init__(self, package_manager: str, language: str):
        super().__init__()
        self.package_manager = package_manager
        self.language = language

    def get_dependents(self, package_name: str) -> List[DependentRepositoryInfo]:
        num_pages = LibrariesIOConfig.start_page
        dependents = []
        while num_pages <= LibrariesIOConfig.start_page + LibrariesIOConfig.max_num_pages:
            dependents_in_page = self.get_dependents_in_page(
                package_name=package_name,
                page=num_pages,
                per_page=LibrariesIOConfig.max_per_page
            )
            if not dependents_in_page:
                break

            if len(dependents_in_page) > LibrariesIOConfig.max_per_page:
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
        if not os.path.exists(LibrariesIOConfig.dependent_repo_info_save_dir):
            os.makedirs(LibrariesIOConfig.dependent_repo_info_save_dir)
        file_path = os.path.join(LibrariesIOConfig.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{LibrariesIOConfig.start_page}.jsonl")
        with jsonlines.open(file_path, "w") as f:
            f.write_all([dep.dict() for dep in dependents])
        logger.info(f"Saved {len(dependents)} dependents for package {package_name} to {file_path}")
        
    def append_dependents_to_file(self, package_name: str, dependents: List[DependentRepositoryInfo]):
        import os
        if not os.path.exists(LibrariesIOConfig.dependent_repo_info_save_dir):
            os.makedirs(LibrariesIOConfig.dependent_repo_info_save_dir)
        file_path = os.path.join(LibrariesIOConfig.dependent_repo_info_save_dir, f"{self.language}_{self.package_manager}_{package_name}_dependents_{LibrariesIOConfig.start_page}.jsonl")
        with jsonlines.open(file_path, "a") as f:
            f.write_all([dep.dict() for dep in dependents])
        logger.info(f"Appended {len(dependents)} dependents for package {package_name} to {file_path}")