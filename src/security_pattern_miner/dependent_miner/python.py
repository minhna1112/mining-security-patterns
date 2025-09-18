from .base import DependentMiner, LibrariesIODependentMiner
from utils.libraries_io import get_libraries_io_url
import requests
from schemas.libraries_io_request import LibrariesIOGetDependentRequest
from schemas.libraries_io_response import DependentRepositoryInfo, LibrariesIOGetDependentResponse
from typing import List
from config.constants import PYTHON, PYPI


class PythonDependentMiner(DependentMiner):
    def get_dependents(self, package_name: str) -> List[DependentRepositoryInfo]:
        request = LibrariesIOGetDependentRequest(
            package_manager=PYPI,
            package_name=package_name,
            page=1,
            per_page=30
        )
        url = get_libraries_io_url(request)
        response = requests.get(url)
        if response.status_code == 200:
            dependents_data = response.json()
            dependents = [DependentRepositoryInfo(**data) for data in dependents_data]
            return dependents
        else:
            response.raise_for_status()