from config.libraries_io import LibrariesIOConfig
from .base import DependentMiner, LibrariesIODependentMiner
import requests
from typing import List
from config.constants import JAVA, MAVEN
from schemas.libraries_io_response import DependentRepositoryInfo


class JavaDependentMiner(LibrariesIODependentMiner):
    def __init__(self, config: LibrariesIOConfig):
        super().__init__(package_manager=MAVEN, language=JAVA, config=config)
