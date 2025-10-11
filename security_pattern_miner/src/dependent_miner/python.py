from config.libraries_io import LibrariesIOConfig
from .base import DependentMiner, LibrariesIODependentMiner
import requests
from typing import List
from config.constants import PYTHON, PYPI
from schemas.libraries_io_response import DependentRepositoryInfo


class PythonDependentMiner(LibrariesIODependentMiner):
    def __init__(self, config: LibrariesIOConfig):
        super().__init__(package_manager=PYPI, language=PYTHON, config=config)
