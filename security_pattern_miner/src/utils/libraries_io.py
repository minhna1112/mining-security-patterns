import sys; sys.path.append(".")
from config.libraries_io import LibrariesIOConfig
from schemas.libraries_io_request import LibrariesIOGetDependentRequest

def get_libraries_io_url(request: LibrariesIOGetDependentRequest) -> str:
    base_url = "https://libraries.io/api"
    api_key = LibrariesIOConfig.API_KEY
    return (f"{base_url}/{request.package_manager}/{request.package_name}/dependent_repositories"
            f"?api_key={api_key}&page={request.page}&per_page={request.per_page}")