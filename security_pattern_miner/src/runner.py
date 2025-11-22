import os
from utils.logger import logger
import logging
from dependent_miner.python import PythonDependentMiner
 
from dependent_miner.java import JavaDependentMiner
from repo_crawler.base import GitCrawler
from config.constants import PYTHON, PYPI, JAVA, MAVEN
from config.crawler import GitCrawlerConfig
from config.libraries_io import LibrariesIOConfig
from config.queries_loader import QueriesLoaderConfig
from config.zoekt import ZoektConfig
from context_retriever.queries_loader import QueriesLoader
from context_retriever.zoekt_retriever import ZoektSearchRequester
import yaml

dependent_miners = {
    (PYTHON, PYPI): PythonDependentMiner,
    (JAVA, MAVEN): JavaDependentMiner
}

class SecurityPatternMiner:
    """Handles mining of dependent repositories"""
    def __init__(self, args):
        self.args = args
        
        # Configure directories and limits
        if args.max_pages:
            LibrariesIOConfig.max_num_pages = args.max_pages
        if args.per_page:
            LibrariesIOConfig.max_per_page = args.per_page
        if args.start_page:
            LibrariesIOConfig.start_page = args.start_page
        if args.start_index is not None:
            GitCrawlerConfig.start_index = args.start_index
        if args.end_index is not None:
            GitCrawlerConfig.end_index = args.end_index
        if args.root_data_dir:
            LibrariesIOConfig.root_data_dir = args.root_data_dir
            LibrariesIOConfig.dependent_repo_info_save_dir = os.path.join(args.root_data_dir, "dependent_repos_info")
            GitCrawlerConfig.root_data_dir = args.root_data_dir
            GitCrawlerConfig.cloned_repos_dir = os.path.join(args.root_data_dir, "cloned_repos")

        self.dependent_miner = dependent_miners.get((args.language.lower(), args.package_manager), None)(LibrariesIOConfig)
        if not self.dependent_miner:
            raise ValueError(f"Unsupported language/package manager combination: {args.language}/{args.package_manager}")
        
        self.repo_crawler = GitCrawler(GitCrawlerConfig)

    @staticmethod
    def load_pattern_yaml(language: str, web_framework: str, pattern: str) -> dict:
        """Load pattern YAML file and return its contents"""
        yaml_path = os.path.join(
            './context_retriever/queries_library',
            language,
            web_framework,
            'patterns',
            f'{pattern}.yaml'
        )
        
        if not os.path.exists(yaml_path):
            raise FileNotFoundError(f"Pattern YAML file not found: {yaml_path}")
        
        with open(yaml_path, 'r') as file:
            return yaml.safe_load(file)
    
    @staticmethod
    def extract_dependencies_from_pattern(language: str, web_framework: str, pattern: str) -> list[str]:
        """Extract dependency package names from a pattern YAML file"""
        pattern_data = SecurityPatternMiner.load_pattern_yaml(language, web_framework, pattern)
        dependencies = pattern_data.get('dependencies', [])
        
        if not dependencies:
            logger.warning(f"No dependencies found in pattern '{pattern}'")
        else:
            logger.info(f"Extracted {len(dependencies)} dependencies from pattern '{pattern}': {', '.join(dependencies)}")
        
        return dependencies

    def run(self, package_names: list[str]):
        if self.args.get_dependents:
            # Step 0: Get each package's dependents and save to files
            logger.info(f"Starting dependent mining for packages: {', '.join(package_names)}")
            
            for pkg in package_names:
                logger.info(f"\n{'='*60}")
                logger.info(f"Processing package: {pkg}")
                logger.info(f"{'='*60}")
                
                # Check if cleaned file exists
                if self.dependent_miner.has_cleaned_dependents_file(pkg):
                    logger.info(f"✓ Package {pkg} already has cleaned dependents file")
                    logger.info(f"  Skipping API fetch. File will be used for mutual dependents calculation.")
                else:
                    logger.info(f"✗ Package {pkg} needs to fetch dependents from Libraries.io API")
                    self.dependent_miner.get_dependents(pkg)
                    self.dependent_miner.clean_saved_dependents(pkg)
                    logger.info(f"✓ Completed fetching and cleaning dependents for {pkg}")
            
            if len(package_names) < 2:
                logger.warning("At least two package names are required to find mutual dependents. Stopping")
                return
        
        if self.args.clean_only:
            logger.info("Running in clean-only mode...")
            for pkg in package_names:
                logger.info(f"Cleaning dependents for package: {pkg}")
                self.dependent_miner.clean_saved_dependents(pkg)
            logger.info("Cleaned saved dependents files. Stopping as --clean_only is set.")
            return  
        
        if self.args.crawl_only:
            # Step 1: Find mutual dependents
            mutual_dependents = self.dependent_miner.find_mutual_dependents(package_names)
            logger.info(f"Found {len(mutual_dependents)} mutual dependents for packages: {package_names}")

            # Step 2: Save mutual dependents to a JSONL file
            saved_jsonl_path = self.dependent_miner.save_mutual_dependents(package_names, mutual_dependents)
            logger.info(f"Saved mutual dependents to {saved_jsonl_path}")

            # Step 3: Load dependent repository info from the saved JSONL file
            dependent_repos = self.repo_crawler.load_dependedent_repos_info(saved_jsonl_path)
            logger.info(f"Loaded {len(dependent_repos)} dependent repositories from {saved_jsonl_path}")

            # Step 4: Crawl and clone the dependent repositories
            self.repo_crawler.crawl_from_dependent_repos_info(dependent_repos)
            logger.info("Completed crawling and cloning dependent repositories")


class SecurityPatternExtractor:
    """Handles construction of security pattern queries and retrieval of contexts using Zoekt"""
    def __init__(self, args):
        self.args = args
        
        # Configure directories
        if args.root_data_dir:
            QueriesLoaderConfig.root_data_dir = args.root_data_dir
            QueriesLoaderConfig.repos_name_dir = os.path.join(args.root_data_dir, "dependent_repos_info")
            QueriesLoaderConfig.output_queries_dir = os.path.join(args.root_data_dir, "output_queries")
            ZoektConfig.root_data_dir = args.root_data_dir
            ZoektConfig.cloned_repos_dir = os.path.join(args.root_data_dir, "cloned_repos")
            ZoektConfig.search_results_dir = os.path.join(args.root_data_dir, "search_results")

        if args.zoekt_url:
            ZoektConfig.zoekt_url = args.zoekt_url

        if not args.pattern:
            raise ValueError("Pattern is required for query construction")
            
        self.query_constructor = QueriesLoader(
            language=args.language.lower(),
            pattern=args.pattern,
            web_framework=args.web_framework,
            config=QueriesLoaderConfig
        )
        
        # Initialize Zoekt searcher if search is enabled
        if args.search_queries:
            self.zoekt_searcher = ZoektSearchRequester(ZoektConfig)

    def construct_queries(self):
        self.query_constructor.load_from_pattern_metadata_file(
            file_path=os.path.join('./context_retriever/queries_library', self.query_constructor.yaml_path_postfix)
        )
        queries = self.query_constructor.load_queries()
        logger.info(f"Loaded {len(queries)} queries for pattern {self.args.pattern}")
        
        # Ensure output directory exists
        os.makedirs(QueriesLoaderConfig.output_queries_dir, exist_ok=True)
        
        output_file_path = os.path.join(QueriesLoaderConfig.output_queries_dir, f"{self.args.pattern}_{self.args.web_framework}_queries.jsonl")
        self.query_constructor.save_queries_to_file(output_file_path)
        logger.info(f"Queries saved to {output_file_path}")
        
        return queries

    def search_and_save_results(self, queries):
        """Search queries using Zoekt and save results"""
        if not hasattr(self, 'zoekt_searcher'):
            logger.error("Zoekt searcher not initialized. Use --search_queries flag.")
            return
            
        # Ensure search results directory exists
        os.makedirs(ZoektConfig.search_results_dir, exist_ok=True)
        
        search_results_file = os.path.join(
            ZoektConfig.search_results_dir, 
            f"{self.args.pattern}_{self.args.web_framework}_search_results.jsonl"
        )
        
        logger.info(f"Starting search for {len(queries)} queries using Zoekt at {ZoektConfig.zoekt_url}")
        search_results = self.zoekt_searcher.search_queries_and_save(queries, search_results_file)
        
        # Log summary statistics
        successful_searches = sum(1 for result in search_results if result.success)
        total_contexts = sum(len(result.contexts) for result in search_results)
        
        logger.info(f"Search completed: {successful_searches}/{len(queries)} queries successful, {total_contexts} total contexts found")
        logger.info(f"Search results saved to {search_results_file}")

    def run(self):
        """Main execution method for the extractor"""
        # Step 1: Construct queries
        queries = self.construct_queries()
        
        # Step 2: Search queries if enabled
        if self.args.search_queries:
            self.search_and_save_results(queries)


def create_miner_parser():
    """Create argument parser for mining functionality"""
    parser = argparse.ArgumentParser(description="Mine dependent repositories")
    
    # Libraries.io related arguments
    parser.add_argument("--get_dependents", action="store_true", help="Flag to get dependents for the specified package names (from scratch)")
    parser.add_argument("--language", type=str, default=PYTHON, help="Programming language")
    parser.add_argument("--package_manager", type=str, default=PYPI, help="Package manager")
    parser.add_argument("--package_names", type=str, nargs='+', help="List of package names to find mutual dependents")
    parser.add_argument("--pattern", type=str, help="Security pattern name to extract dependencies from")
    parser.add_argument("--web_framework", type=str, default="fastapi", help="Web framework for pattern-based mining")
    parser.add_argument("--max_pages", type=int, default=2000, help="Maximum number of pages to fetch from Libraries.io")
    parser.add_argument("--per_page", type=int, default=100, help="Number of results per page from Libraries.io")
    parser.add_argument("--start_page", type=int, default=1, help="Starting page number for fetching dependents")
    parser.add_argument("--root_data_dir", type=str, default="/data", help="Directory to save dependent repository info")
    parser.add_argument("--clean_only", action="store_true", help="Flag to only clean previously saved dependent info files and exit")
    
    # Git crawler related arguments
    parser.add_argument("--crawl_only", action="store_true", help="Flag to only crawl repositories from previously saved dependent info")
    parser.add_argument("--start_index", type=int, default=0, help="Start index for crawling repositories")
    parser.add_argument("--end_index", type=int, default=-1, help="End index for crawling repositories")
    
    return parser


def create_extractor_parser():
    """Create argument parser for query extraction functionality"""
    parser = argparse.ArgumentParser(description="Extract security pattern queries")
    
    parser.add_argument("--construct_queries", action="store_true", help="Flag to construct queries based on the specified pattern")
    parser.add_argument("--search_queries", action="store_true", help="Flag to search constructed queries using Zoekt")
    parser.add_argument("--pattern", type=str, required=True, help="Security pattern name for query construction")
    parser.add_argument("--web_framework", type=str, default="fastapi", help="Web framework name for query construction")
    parser.add_argument("--language", type=str, default=PYTHON, help="Programming language")
    parser.add_argument("--root_data_dir", type=str, default="/data", help="Directory to save query outputs")
    parser.add_argument("--zoekt_url", type=str, help="Zoekt search API URL (overrides environment variable)")
    
    return parser


if __name__ == "__main__":
    import argparse
    import sys
    
    # Check if this is being run for mining or extracting
    if "--get_dependents" in sys.argv or "--crawl_only" in sys.argv or "--clean_only" in sys.argv:
        # Mining mode
        parser = create_miner_parser()
        args = parser.parse_args()
        
        # Determine package names: either from args or from pattern
        if args.pattern:
            logger.info(f"Using pattern '{args.pattern}' to extract dependencies")
            package_names = SecurityPatternMiner.extract_dependencies_from_pattern(
                args.language, 
                args.web_framework, 
                args.pattern
            )
        elif args.package_names:
            package_names = args.package_names
        else:
            parser.error("Either --package_names or --pattern must be specified")
        
        miner = SecurityPatternMiner(args)
        miner.run(package_names)
        
    elif "--construct_queries" in sys.argv:
        # Extracting mode
        parser = create_extractor_parser()
        args = parser.parse_args()
        
        extractor = SecurityPatternExtractor(args)
        extractor.run()
        
    else:
        print("Error: Please specify either mining arguments (--get_dependents, --crawl_only, --clean_only) or extraction arguments (--construct_queries)")
        print("For mining: use --get_dependents, --crawl_only, or --clean_only")
        print("For extraction: use --construct_queries")
        sys.exit(1)
