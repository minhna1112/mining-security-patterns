from .base import DependentMiner, LibrariesIODependentMiner
import requests
from typing import List
from config.constants import PYTHON, PYPI
from schemas.libraries_io_response import DependentRepositoryInfo


class PythonDependentMiner(LibrariesIODependentMiner):
    def __init__(self):
        super().__init__(package_manager=PYPI, language=PYTHON)

    def get_dependents(self, package_name: str) -> List[DependentRepositoryInfo]:
        return super().get_dependents(package_name)