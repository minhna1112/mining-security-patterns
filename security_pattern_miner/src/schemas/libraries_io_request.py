from typing import List, Optional
from pydantic import BaseModel

class LibrariesIOGetDependentRequest(BaseModel):
    package_manager: str
    package_name: str
    page: int = 1
    per_page: int = 30