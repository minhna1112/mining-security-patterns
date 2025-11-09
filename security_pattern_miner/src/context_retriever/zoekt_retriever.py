import os
import sys

sys.path.append("..")
from typing import List
from pydantic import BaseModel
from config.zoekt import ZoektConfig
from context_retriever.queries_loader import Query
import requests
from urllib3.exceptions import NewConnectionError
from requests.exceptions import ConnectionError, Timeout , RequestException
import  json
import time
from logging import getLogger
from typing import List
from base64 import decodebytes
logger = getLogger(__name__)

class Context(BaseModel):
    filepath: str
    start_line: int
    end_line: int
    snippet: str

class SearchedResponse(Query):
    success: bool
    contexts: List[Context] = []

class ZoektSearchRequester:
    """
    A class to handle search requests to Zoekt.
    """

    def __init__(self, config: ZoektConfig):
        self.config = config

    def zoekt_search_on_query_point(
            self,
            query_point: Query):
        query = query_point.query
        result = self.zoekt_search_request(query)
        if result and "Result" in result and "Files" in result["Result"]:
            files = result["Result"]["Files"]
            if files:
                logger.info(f"Found {len(files)} files for query: {query}")
                return files
        # count += 1
        # self.num_failed_searches += 1
        return []
    
    def zoekt_search_request(
                        self,
                        query: str,
                       ) -> dict:
        """
        Make a request to the zoekt search API with error handling and retry logic.
        
        Args:
            query: Search query string
            num_context_lines: Number of context lines to include
            max_results: Maximum number of results to return
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
        
        Returns:
            Dict containing search results or empty result on failure
        """
        if query is None or query.strip() == "":
            print("Empty query provided. Returning empty result.")
            return {"Result": {"Files": [], "FileCount": 0}}
        
        url = self.config.zoekt_url
        payload = json.dumps({
            "Q": query,
            "Opts": {
                "NumContextLines": self.config.num_context_lines,
                "MaxResults": self.config.max_results,
            }
        })
        headers = {
            'Content-Type': 'application/json'
        }

        for attempt in range(self.config.max_retries + 1):
            try:
                response = requests.request("POST", url, headers=headers, data=payload, timeout=30)
                
                # Check if response is successful
                if response.status_code == 200:
                    # print(response.json())
                    return response.json()
                else:
                    logger.error(f"HTTP {response.status_code} error: {response.text}")
                    if attempt < self.config.max_retries:
                        logger.info(f"Retrying in {self.config.retry_delay} seconds... (attempt {attempt + 1}/{self.config.max_retries})")
                        time.sleep(self.config.retry_delay)
                        continue
                    else:
                        logger.info("Max retries reached. Returning empty result.")
                        return {"Result": {"Files": [], "FileCount": 0}}
                        
            except (ConnectionError, NewConnectionError) as e:
                logger.error(f"Connection error on attempt {attempt + 1}: {e}")
                if attempt < self.config.max_retries:
                    logger.info(f"Zoekt service might be down. Retrying in {self.config.retry_delay} seconds...")
                    time.sleep(self.config.retry_delay)
                else:
                    logger.info("Failed to connect to Zoekt service after all retries.")
                    print("Please check if Zoekt is running on http://localhost:6070")
                    return {"Result": {"Files": [], "FileCount": 0}}
                    
            except Timeout as e:
                logger.error(f"Request timeout on attempt {attempt + 1}: {e}")
                if attempt < self.config.max_retries:
                    logger.info(f"Retrying in {self.config.retry_delay} seconds...")
                    time.sleep(self.config.retry_delay)
                else:
                    logger.info("Request timed out after all retries.")
                    return {"Result": {"Files": [], "FileCount": 0}}
                    
            except RequestException as e:
                logger.error(f"Request error on attempt {attempt + 1}: {e}")
                if attempt < self.config.max_retries:
                    logger.info(f"Retrying in {self.config.retry_delay} seconds...")
                    time.sleep(self.config.retry_delay)
                else:
                    logger.error("Request failed after all retries.")
                    return {"Result": {"Files": [], "FileCount": 0}}
                    
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                logger.error(f"Response content: {response.text if 'response' in locals() else 'No response'}")
                return {"Result": {"Files": [], "FileCount": 0}}
                
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                return {"Result": {"Files": [], "FileCount": 0}}
        
        # This should never be reached, but just in case
        return {"Result": {"Files": [], "FileCount": 0}}

    def handle_file_path( filepath: str) -> str:
        project_metadata,  navigation_path = filepath.split(":", 1)
        project_metadata = project_metadata.replace("/", "_").replace("github.com_", "")
        return os.path.join(project_metadata, navigation_path)
    def post_process_search_results(
            self,
            files: list,
            query_point: Query) -> SearchedResponse:
        searched_response = SearchedResponse()
        searched_response.query = query_point.query
        searched_response.success = False
        contexts = []
        for file in files:
            if "LineMatches" in file:
                line_matches = file["LineMatches"]
                for line_match in line_matches:
                    context = Context()
                    context.filepath = file.get("FileName", "")
                    context.start_line = max(0, line_match['LineNumber'] - self.config.num_context_lines - 1)
                    context.end_line = line_match['LineNumber'] + self.config.num_context_lines
                    if self.config.get_whole_file:
                        with open(os.path.join(self.config.cloned_repos_dir, context.filepath), 'r') as f:
                            context.snippet = f.read()
                    else:
                        context.snippet = decodebytes(line_match['Context'].encode()).decode('utf-8', errors='ignore')
                    contexts.append(context)
        if contexts:
            searched_response.success = True
        searched_response.contexts = contexts
        return searched_response
    