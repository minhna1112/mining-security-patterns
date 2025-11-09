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

    @staticmethod
    def handle_file_path(filepath: str) -> str:
        project_metadata, navigation_path = filepath.split(":", 1)
        project_metadata = project_metadata.replace("/", "_").replace("github.com_", "")
        return os.path.join(project_metadata, navigation_path)

    def post_process_search_results(
            self,
            files: list,
            query_point: Query) -> SearchedResponse:
        searched_response = SearchedResponse(
            repo=query_point.repo,
            role=query_point.role,
            query=query_point.query,
            webframework=query_point.webframework,
            pattern=query_point.pattern,
            success=False,
            contexts=[]
        )
        contexts = []
        for file in files:
            if "LineMatches" in file:
                line_matches = file["LineMatches"]
                for line_match in line_matches:
                    print(line_match)
                    context = Context(
                        filepath="",
                        start_line=0,
                        end_line=0,
                        snippet=""
                    )
                    context.filepath = file.get("FileName", "")
                    context.start_line = line_match['LineStart']
                    context.end_line = line_match['LineEnd']
                    if self.config.get_whole_file:
                        # try:
                            processed_filepath = self.handle_file_path(context.filepath)
                            full_path = os.path.join(self.config.cloned_repos_dir, processed_filepath)
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                context.snippet = f.read()
                        # except Exception as e:
                        #     logger.error(f"Error reading file {context.filepath}: {e}")
                        #     context.snippet = decodebytes(line_match['Content'].encode()).decode('utf-8', errors='ignore')
                    else:
                        before, current, after = line_match['Before'], line_match['Line'], line_match['After']
                        context.snippet = decodebytes((before + current + after).encode()).decode('utf-8', errors='ignore')
                    contexts.append(context)
        if contexts:
            searched_response.success = True
        searched_response.contexts = contexts
        return searched_response

    def save_search_results_to_file(self, search_results: List[SearchedResponse], output_file_path: str):
        """
        Save processed search results to a JSONL file.
        
        Args:
            search_results: List of SearchedResponse objects
            output_file_path: Path to the output JSONL file
        """
        import jsonlines
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        with jsonlines.open(output_file_path, "w") as writer:
            for result in search_results:
                writer.write(result.dict())
        
        logger.info(f"Saved {len(search_results)} search results to {output_file_path}")

    def search_queries_and_save(self, queries: List[Query], output_file_path: str):
        """
        Search all queries using Zoekt and save results to file.
        
        Args:
            queries: List of Query objects to search
            output_file_path: Path to save the search results
        """
        search_results = []
        
        logger.info(f"Starting search for {len(queries)} queries")
        
        for i, query in enumerate(queries):
            logger.info(f"Processing query {i+1}/{len(queries)}: {query.query[:100]}...")
            
            files = self.zoekt_search_on_query_point(query)
            searched_response = self.post_process_search_results(files, query)
            search_results.append(searched_response)
            
            # Log progress
            if searched_response.success:
                logger.info(f"Query {i+1} successful: found {len(searched_response.contexts)} contexts")
            else:
                logger.info(f"Query {i+1} returned no results")
        
        # Save all results
        self.save_search_results_to_file(search_results, output_file_path)
        return search_results
