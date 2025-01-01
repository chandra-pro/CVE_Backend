"""
====================
pkct_main.py
Patch verification for kernel
Author: Chandramani Kumar, Shubham
===================
 
"""

import os
import re
import subprocess
import difflib
import requests
import csv
from git import Repo, exc
from git.exc import GitCommandError
from datetime import datetime
from bs4 import BeautifulSoup
import shutil
import settings
import django
import argparse
from uuid import UUID
import sys
import json
import logging
# Initialize Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings') 
django.setup()
from serverapp.models import CVEReference,MatchString, CPEMatch, CPEMatchInNode

LOGS_DIR = os.path.join(settings.PROJECT_DIR,'hmi','CVEHMI','hmiapp','media','logs')
HMI_REPORT = os.path.join(settings.PROJECT_DIR,'hmi','CVEHMI','hmiapp','media','reports')
os.makedirs(LOGS_DIR, exist_ok=True)



# Configure logging
def setup_logging(scan_id):
    log_file_path = os.path.join(LOGS_DIR, f"{scan_id}_scan.log")
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

logger = logging.getLogger()

DICTIONARY_PATH = settings.DICTIONARY_PATH
PKCT_REPORT_PATH = settings.PKCT_REPORT_PATH
DIFF_SIMILARITY_THRESHOLD = 1.0  # Threshold for diffs similarity comparison
# Path to the config.json file (adjust based on your project structure)
CONFIG_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'config.json'))
class DualLogger:
    def __init__(self, log_filename):
        self.terminal = sys.stdout
        self.log = open(log_filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

# Set up the dual logging
sys.stdout = DualLogger("PKCT_scan.log")


def load_paths_from_config():
    # Check if the config file exists
    if not os.path.exists(CONFIG_FILE_PATH):
        logger.warning(f"Config file {CONFIG_FILE_PATH} not found.")
        print(f"Config file {CONFIG_FILE_PATH} not found.")
        return None

    # Load the config file
    with open(CONFIG_FILE_PATH, 'r') as config_file:
        config_data = json.load(config_file)
        return config_data

def check_path_exists(path, path_name):
    if os.path.exists(path):
        logger.info(f"{path_name} exists: {path}")
        print(f"{path_name} exists: {path}")
    else:
        logger.info(f"{path_name} does NOT exist: {path}. Creating directory...")
        print(f"{path_name} does NOT exist: {path}. Creating directory...")
        os.makedirs(path)
        logger.info(f"Directory created: {path}")
        print(f"Directory created: {path}")


def parse_version(version):
    match = re.match(r"([\d\.]+)([a-zA-Z]*)", version)
    if match:
        version_str = match.group(1)
        suffix = match.group(2)
        try:
            version_tuple = tuple(map(int, version_str.split('.')))
            return version_tuple, suffix
        except ValueError:
            return None, None
    else:
        return None, None
 
def compare_versions(version1, version2):
    tuple1, suffix1 = parse_version(version1)
    tuple2, suffix2 = parse_version(version2)
   
    if tuple1 is None or tuple2 is None:
        logger.error("Invalid version format")
        raise ValueError("Invalid version format")
 
    if tuple1 < tuple2:
        return -1
    elif tuple1 > tuple2:
        return 1
 
    if suffix1 < suffix2:
        return -1
    elif suffix1 > suffix2:
        return 1
 
    return 0
 
def is_version_in_range(version, start_incl, end_incl, start_excl, end_excl):
    version_tuple, version_suffix = parse_version(version)
    start_incl_tuple, start_incl_suffix = parse_version(start_incl) if start_incl else (None, None)
    end_incl_tuple, end_incl_suffix = parse_version(end_incl) if end_incl else (None, None)
    start_excl_tuple, start_excl_suffix = parse_version(start_excl) if start_excl else (None, None)
    end_excl_tuple, end_excl_suffix = parse_version(end_excl) if end_excl else (None, None)
 
    if version_tuple is None:
        return False
 
    if start_excl_tuple and (compare_versions(version, start_excl) <= 0):
        return False
 
    if end_excl_tuple and (compare_versions(version, end_excl) >= 0):
        return False
 
    if start_incl_tuple and (compare_versions(version, start_incl) < 0):
        return False
 
    if end_incl_tuple and (compare_versions(version, end_incl) > 0):
        return False
 
    return True
 
def get_match_strings(package_name, version):
    print(f"Fetching match strings for package '{package_name}' and version '{version}'")
 
    match_strings = MatchString.objects.filter(criteria__icontains=f':{package_name}:')
 
    def get_criteria_segments(criteria):
        segments = criteria.split(':')
        if len(segments) > 6:
            return segments[5]
        return None, None
 
    vendor_match_criteria = []
 
    for match in match_strings:
        criteria_version_field = get_criteria_segments(match.criteria)
 
 
        if criteria_version_field == version:
            vendor_match_criteria.append(str(match.match_criteria_id).upper())
        elif criteria_version_field == '*':
            start_incl = match.version_start_including
            end_incl = match.version_end_including
            start_excl = match.version_start_excluding
            end_excl = match.version_end_excluding
           
            if is_version_in_range(version, start_incl, end_incl, start_excl, end_excl):
                vendor_match_criteria.append(str(match.match_criteria_id).upper())
 
    return vendor_match_criteria
 
def find_cve_id_by_match_criteria_id(match_criteria_id):
    cve_ids = set()
 
    try:
        match_criteria_uuid = UUID(match_criteria_id)
 
        cpe_matches = CPEMatch.objects.select_related('configuration__cve').filter(match_criteria_id=match_criteria_uuid)
        for cpe_match in cpe_matches:
            cve_id = cpe_match.configuration.cve.id
            if cpe_match_in_node.vulnerable:
               cve_ids.add(cve_id)

 
        cpe_match_in_nodes = CPEMatchInNode.objects.select_related('node__configuration__cve').filter(match_criteria_id=match_criteria_uuid)
        for cpe_match_in_node in cpe_match_in_nodes:
            cve_id = cpe_match_in_node.node.configuration.cve.id
            if cpe_match_in_node.vulnerable:
                cve_ids.add(cve_id)
            
 
        result = list(cve_ids)
        print(f"Final CVE IDs and their status: {result}")
        return result if result else None
 
    except ValueError:
        logger.error("Invalid match_criteria_id format")
        print("Invalid match_criteria_id format")
        return None
 
def load_package_dictionary(csv_file_path):
    """
    Load package dictionary from a CSV file.
   
    :param csv_file_path: Path to the CSV file.
    :return: Dictionary where key is a package name and value is a list of associated package names.
    """
    dictionary = {}
    with open(csv_file_path, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row:
                key = row[0].strip()
                values = [v.strip() for v in row]
                dictionary[key] = values
    return dictionary
 
def search_alternate_package_names(original_package_name, dictionary):
    """
    Search for alternate package names in the dictionary and return all relevant package names.
   
    :param original_package_name: The original package name to look up.
    :param dictionary: The dictionary of package names.
    :return: A list of package names to search for.
    """
    related_packages = []
    for key, packages in dictionary.items():
        if original_package_name in packages:
            related_packages.extend(packages)
   
    # Remove duplicates
    return list(set(related_packages))
 
def load_manifest(csv_file_path):
    """
    Load manifest file with package names and versions.
   
    :param csv_file_path: Path to the CSV file.
    :return: List of tuples with package names and versions.
    """
    manifests = []
    with open(csv_file_path, mode='r') as file:
        reader = csv.reader(file, delimiter=' ')
        for row in reader:
            if len(row) >= 3:  # Ensure that there are at least 3 columns
                package_name = row[0].strip()
                version = row[2].strip()
                manifests.append((package_name, version))
            else:
                print(f"Skipping invalid row: {row}")
    return manifests
# #######################################################################################################

def accumulate_cve_ids_manifest(manifest_entries, dictionary_path):
    """
    Accumulate all CVE IDs for each kernel version found in the given manifest entries using the package dictionary.

    :param manifest_entries: List of tuples containing package names and versions.
    :param dictionary_path: Path to the CSV file containing the package dictionary.
    :return: A list of unique CVE IDs found across all kernel versions.
    """
    # Load dictionary from CSV
    package_dictionary = load_package_dictionary(dictionary_path)

    # Set to accumulate unique CVE IDs
    all_cve_ids = set()

    # Fetch all alternate package names for 'kernel'
    alternate_kernel_names = search_alternate_package_names('kernel', package_dictionary)

    # Track processed kernel versions to avoid redundant processing
    processed_kernel_versions = set()

    # Process manifest entries
    for manifest_package_name, manifest_version in manifest_entries:
        # Check if manifest package name matches 'kernel' or any of its alternate names
        if (manifest_package_name.lower().startswith('kernel') or manifest_package_name in alternate_kernel_names):
            # Skip redundant kernel versions
            if manifest_version in processed_kernel_versions:
                print(f"Skipping redundant kernel package: {manifest_package_name}, version: {manifest_version}")
                continue

            # Mark this kernel version as processed
            processed_kernel_versions.add(manifest_version)

            package_name = 'kernel'
            version = manifest_version
            print(f"Matched package: {package_name}, version: {version}")

            # Fetch CVE IDs for this specific kernel version
            alternate_package_names = search_alternate_package_names(package_name, package_dictionary)
            all_package_names = [package_name] + alternate_package_names

            # Accumulate CVE IDs for each match
            for name in all_package_names:
                match_strings = get_match_strings(name, version)
                for match_criteria_id in match_strings:
                    cve_ids = find_cve_id_by_match_criteria_id(match_criteria_id)
                    if cve_ids:
                        all_cve_ids.update(cve_ids)

    # Log if no kernel versions were found in the manifest
    if not all_cve_ids:
        print("No kernel match found in the manifest.")
        logger.error("No kernel package name found in manifest")

    return list(all_cve_ids)


#######################################################################################################

def accumulate_cve_ids(manifest_entries, dictionary_path):
    """
    Accumulate all CVE IDs for the given manifest entries using the package dictionary.

    :param manifest_entries: List of tuples containing package names and versions.
    :param dictionary_path: Path to the CSV file containing the package dictionary.
    :return: A list of unique CVE IDs found across all kernel versions.
    """
    # Load dictionary from CSV
    package_dictionary = load_package_dictionary(dictionary_path)

    # Set to accumulate unique CVE IDs
    all_cve_ids = set()

    for package_name, version in manifest_entries:
        print(f"Processing package: {package_name}, version: {version}")

        alternate_package_names = search_alternate_package_names(package_name, package_dictionary)
        all_package_names = [package_name] + alternate_package_names

        for name in all_package_names:
            match_strings = get_match_strings(name, version)
            for match_criteria_id in match_strings:
                cve_ids = find_cve_id_by_match_criteria_id(match_criteria_id)
                if cve_ids:
                    all_cve_ids.update(cve_ids)

    # Convert set to list
    return list(all_cve_ids)

##############################################################################################################
def is_repo_clean(repo: Repo) -> bool:
    """
    Check if the repository is clean (no uncommitted changes).
    """
    try:
        # Check for uncommitted changes in the working directory
        if repo.is_dirty(untracked_files=True):
            logger.info("Repository has uncommitted changes.")
            print("Repository has uncommitted changes.")
            return False
        
        # Check if there are changes staged for commit
        if repo.index.diff("HEAD"):
            logger.info("There are changes staged for commit.")
            print("There are changes staged for commit.")
            return False
        
        logger.info("Repository is clean.")
        print("Repository is clean.")
        return True
    except exc.GitCommandError as e:
        logger.error(f"Error checking repository status: {e}")
        print(f"Error checking repository status: {e}")
        return False
    

#######################################################################################################
# create and update log file with commit id and commit messages
    
def update_log_file(branch_path: str, log_file_path: str):
    """
    Update the log file with only new commits and commit messages from the specified branch.
    """
    try:
        # Ensure the log file exists and read the last commit ID if present
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r', encoding='utf-8') as log_file:
                lines = log_file.readlines()
                if lines:
                    last_commit_id = lines[0].split()[0]  # Get the last commit ID
                else:
                    last_commit_id = None
        else:
            last_commit_id = None
        
        # Get the list of new commits since the last recorded commit
        if last_commit_id:
            log_command = f'git log {last_commit_id}..HEAD --pretty=format:"%H %s"'
        else:
            log_command = 'git log --pretty=format:"%H %s"'
        
        commits = subprocess.check_output(log_command, shell=True, cwd=branch_path)

        # Decode with error handling 
        commits = commits.decode('utf-8', errors='replace')  # Replace undecodable bytes
        
        # Append the new commits to the log file
        if commits:
            with open(log_file_path, 'a', encoding='utf-8', errors='replace') as log_file:
                log_file.write(commits + '\n')
            logger.info(f"Log file updated: {log_file_path}")
            print(f"Log file updated: {log_file_path}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error retrieving commit logs: {e}")
        print(f"Error retrieving commit logs: {e}")
    except IOError as e:
        logger.error(f"Error writing to log file: {e}")
        print(f"Error writing to log file: {e}")


#######################################################################################################
# clones a branch git repository and switch to desired branch

def branch_clone_and_checkout(USER_KERNEL_REPO_URL: str, USER_KERNEL_BRANCH_NAME: str, repo_dir_name: str, targetfolder: str, upload_path: str, download_path: str):
    """
    Clone the repository into a repo-specific directory if it doesn't exist;
    if it exists, reset the repo, switch to the specified branch, and update the log file.
    """
    # Define paths
    kernel_path = os.path.join(download_path, targetfolder)
    os.makedirs(kernel_path, exist_ok=True)

    kernel_log_path = os.path.join(download_path, 'userkernel_logs')
    os.makedirs(kernel_log_path, exist_ok=True)

    userkernel_logs_path = os.path.join(kernel_log_path, f"{repo_dir_name}_logs")
    repo_path = os.path.join(kernel_path, repo_dir_name)  # Path for the repo
    log_file_path = os.path.join(userkernel_logs_path, f"{USER_KERNEL_BRANCH_NAME}.log")  # Log file path
 
    # Ensure the parent directories exist
    os.makedirs(userkernel_logs_path, exist_ok=True)
 
    # Check if the repository directory already exists
    if os.path.exists(repo_path):
        logger.info(f"Repository directory already exists at {repo_path}. Resetting and switching branch...")
        print(f"Repository directory already exists at {repo_path}. Resetting and switching branch...")
        try:
            # Reset the repository to discard any local changes
            reset_command = 'git reset --hard'
            subprocess.run(reset_command, shell=True, cwd=repo_path, check=True)
            print("Reset the repository to discard any local changes.")

            # Switch to the specified branch
            switch_command = f'git switch {USER_KERNEL_BRANCH_NAME}'
            subprocess.run(switch_command, shell=True, cwd=repo_path, check=True)
            logger.info(f"Switched to branch {USER_KERNEL_BRANCH_NAME}.")
            print(f"Switched to branch {USER_KERNEL_BRANCH_NAME}.")
 
            # Ensure the log directory exists before writing
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
 
            # Update the log file with commits
            update_log_file(repo_path, log_file_path)
        except subprocess.CalledProcessError as e:
            print(f"Error resetting or switching branch: {e}")
            logger.error(f"Error resetting or switching branch: {e}")
            return None,None
    else:
        logger.info(f"Cloning repository from {USER_KERNEL_REPO_URL} into {repo_path}...")
        print(f"Cloning repository from {USER_KERNEL_REPO_URL} into {repo_path}...")
        try:
            # Clone the repository and checkout the specified branch
            clone_command = f'GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone {USER_KERNEL_REPO_URL} {repo_path} --branch {USER_KERNEL_BRANCH_NAME}'
            subprocess.run(clone_command, shell=True, check=True)
            logger.info(f"Repository cloned successfully and checked out branch {USER_KERNEL_BRANCH_NAME}.")
            print(f"Repository cloned successfully and checked out branch {USER_KERNEL_BRANCH_NAME}.")
 
            # Ensure the log directory exists before writing
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
 
            # Update the log file with commits
            update_log_file(repo_path, log_file_path)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error cloning repository, project link or project branch name is invalid")
            print(f"Error cloning repository: {e} , project link or project branch name is invalid")
            return None,None
 
    return repo_path, log_file_path  # Return the repository path and log file path



#######################################################################################################
# clones a git repository and checkout in a particular folder

def clone_and_checkout(USER_KERNEL_REPO_URL: str, USER_KERNEL_BRANCH_NAME: str, repo_dir_name: str, targetfolder: str, logs_dir_name: str,upload_path: str, download_path: str):
    """
    Clone the repository if it doesn't exist; if it exists, fetch updates and checkout to the specified branch.
    """
    # Configure Git settings
    subprocess.run('git config --global http.postBuffer 524288000', shell=True, check=True)
    subprocess.run('git config --global http.maxRequestBuffer 524288000', shell=True, check=True)
    subprocess.run('git config --global core.compression 0', shell=True, check=True)

    # Define paths
    log_file_path = os.path.join(download_path, logs_dir_name, f"{USER_KERNEL_BRANCH_NAME}.log")
    repo_path = os.path.join(download_path, targetfolder, repo_dir_name)  # Full path to the repository directory

    # Ensure the parent directory for the repository exists
    if not os.path.exists(os.path.join(download_path, targetfolder)):
        os.makedirs(os.path.join(download_path, targetfolder))

    # Ensure the log directory exists
    log_dir = os.path.dirname(log_file_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)



    # Check if the repository directory already exists
    if os.path.exists(repo_path):
        logger.info(f"Repository already exists at {repo_path}. Performing git fetch and checkout.")
        print(f"Repository already exists at {repo_path}. Performing git fetch and checkout.")
        try:
        # Fetch all updates from the remote repository
            fetch_command = 'git fetch --all'
            subprocess.run(fetch_command, shell=True, cwd=repo_path, check=True)
            logger.info("Fetched all updates from the remote repository.")
            print("Fetched all updates from the remote repository.")
            
            # Checkout to the specified branch
            checkout_command = f'GIT_TERMINAL_PROMPT=0 git checkout {USER_KERNEL_BRANCH_NAME}'
            subprocess.run(checkout_command, shell=True, cwd=repo_path, check=True)
            logger.info(f"Checked out to branch {USER_KERNEL_BRANCH_NAME}.")
            print(f"Checked out to branch {USER_KERNEL_BRANCH_NAME}.")

            # Ensure the log directory exists before writing
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

            # Update the log file with commits
            update_log_file(repo_path, log_file_path)

        except subprocess.CalledProcessError as e:
            logger.error(f"Error fetching updates or checking out branch: {e}")
            print(f"Error fetching updates or checking out branch: {e}")            
            return None,None
    else:
        logger.info(f"Cloning repository from {USER_KERNEL_REPO_URL} to {repo_path}...")
        print(f"Cloning repository from {USER_KERNEL_REPO_URL} to {repo_path}...")
        try:
            # Clone the repository
            clone_command = f'GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone {USER_KERNEL_REPO_URL} {repo_path}'
            subprocess.run(clone_command, shell=True, check=True)
            logger.info("Repository cloned successfully.")
            print("Repository cloned successfully.")
            
            # Checkout to the specified branch
            checkout_command = f'GIT_TERMINAL_PROMPT=0 git checkout {USER_KERNEL_BRANCH_NAME}'
            subprocess.run(checkout_command, shell=True, cwd=repo_path, check=True)
            logger.info(f"Checked out to branch {USER_KERNEL_BRANCH_NAME}.")
            print(f"Checked out to branch {USER_KERNEL_BRANCH_NAME}.")

            # Ensure the log directory exists before writing
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

            # Update the log file with commits
            update_log_file(repo_path, log_file_path)

        except subprocess.CalledProcessError as e:
            logger.error(f"Error fetching updates or checking out branch: {e}")
            print(f"Error cloning repository or checking out branch: {e}, branch name is invalid")            
            return None,None

    return repo_path, log_file_path  # Return the repository path and log file path



#######################################################################################################
# List out the references which has valid url

def get_filtered_references(cve_id: str):
    """
    Fetch and filter CVE references based on the provided CVE ID.
    """
    references = CVEReference.objects.filter(cve_id=cve_id)
    filtered_references = []

    for ref in references:
        url = ref.url
        tags = ref.tags or []
        if "https://git.kernel.org" in url:
            filtered_references.append((url, "kernel.org"))
        elif "https://github.com/torvalds" in url:
                filtered_references.append((url, "github.com/torvalds"))
    
    if not filtered_references:
        print(f"No relevant references found for CVE ID {cve_id}.")
    
    return filtered_references



#######################################################################################################
# extract commid id from the valid url

def extract_commit_id_from_url(url: str):
    """
    Extract commit ID from the given URL.
    Supports GitHub, git.kernel.org, and other common commit URL formats.
    """
    commit_id_patterns = [
        r'/commit/([a-f0-9]+)',            # General pattern for GitHub
        r'id=([a-f0-9]+)',                # Specific pattern with 'id' parameter
        r'/c/([a-f0-9]+)',                # Pattern for kernel.org commit URLs
        r'([a-f0-9]+)$'                   # Pattern for plain commit ID at the end of the URL
    ]
    for pattern in commit_id_patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    print(f"Commit ID not found in URL: {url}")
    return None



def read_result_file(result_file_path):
    """
    Reads the result file and creates a mapping of commit IDs to patch filenames.
    """
    mapping = {}
    try:
        with open(result_file_path, 'r') as file:
            for line in file:
                if '->' in line:
                    commit_id, patch_filename = line.strip().split(' -> ')
                    mapping[commit_id] = patch_filename
    except IOError as e:
        logger.error(f"Error reading result file {result_file_path}: {e}")
        print(f"Error reading result file {result_file_path}: {e}")
    
    return mapping



#######################################################################################################
# extract commit messages from the patch files

def extract_commit_msg(patch_content):
    """
    Extracts the commit message from the patch file content, including cases where the
    message spans multiple lines. It continues extracting until an empty line is encountered.
    The 'Subject: ' prefix is removed from the extracted message.
    """
    match = re.search(r'^Subject:\s*(.*)', patch_content, re.MULTILINE)
    if match:
        start_index = match.start()
        # Extract the content from the subject line till an empty line
        commit_msg_lines = []
        first_line = True
        for line in patch_content[start_index:].splitlines():
            if line.strip():  # Stop at the first empty line
                if first_line:
                    # Remove 'Subject: ' from the first line
                    commit_msg_lines.append(line.replace('Subject:', '').strip())
                    first_line = False
                else:
                    commit_msg_lines.append(line.strip())
            else:
                break
        # Join the lines into a single commit message
        commit_msg = ' '.join(commit_msg_lines)
        return commit_msg
    return "No commit message found"



#######################################################################################################
# Extract patch content from the patch file

def extract_patch_code(patch_content):
    """
    Extracts the patch code (changes) from the patch content.
    """
    # Define the pattern to match the diff block
    pattern = re.compile(r'^\+\+\+ \S+.*?\n---\n(?s:.*?)(?=^(\+\+\+|\Z))', re.MULTILINE)
    matches = pattern.findall(patch_content)
    return "\n".join(matches).strip()



#######################################################################################################
# extrat changed files in patch


def extract_changed_files(patch_content):
    """
    Extracts the .c and .h filenames changed in a patch file from its content.
    Returns a tuple containing two lists: one for .c files and one for .h files.
    """
    # Regular expression to match .c files and .h files
    c_file_pattern = re.compile(r'^\+\+\+ b/(\S+\.c)$', re.MULTILINE)
    h_file_pattern = re.compile(r'^\+\+\+ b/(\S+\.h)$', re.MULTILINE)
   
    # Find all matches for .c and .h files
    c_files = c_file_pattern.findall(patch_content)
    h_files = h_file_pattern.findall(patch_content)
 
    return c_files, h_files 



#################################################################################################
# Read file content 

def read_file_content(file_path):
    """
    Reads the content of a file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            return file.read()
    except UnicodeDecodeError as e:
        logger.error(f"Error decoding file {file_path}: {e}")
        print(f"Error decoding file {file_path}: {e}")
        try:
            with open(file_path, 'rb') as file:
                return file.read().decode(errors='replace')
        except IOError as e:
            logger.error(f"Error reading file {file_path}: {e}")
            print(f"Error reading file {file_path}: {e}")
        return ""
    except IOError as e:
        logger.error(f"Error reading file {file_path}: {e}")
        print(f"Error reading file {file_path}: {e}")
        return ""



#######################################################################################################
# Function to check whether patch is applied or not by code matching




def check_patch_status(repo_path, patch_file):
    print("Control in check_patch_status function")
    # Check if paths exist
    if not os.path.exists(repo_path):
        print(f"Repository path does not exist: {repo_path}")
        return "ERROR"
    if not os.path.exists(patch_file):
        print(f"Patch file does not exist: {patch_file}")
        return "ERROR"

    # Change to the repository directory
    original_dir = os.getcwd()
    os.chdir(repo_path)

    try:
        # Define patch command for reverse dry-run
        command = f"patch -p1 -t --dry-run < {patch_file}"
        print(f"Running patch command: {command}")
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        print(f"Return code: {result.returncode}")
        output = result.stdout + result.stderr
        

        # Run the patch command using subprocess
 
        
        # Pass the patch content to the process and capture stdout and stderr
 
        print(f"Patch output:\n{output}")

        # Change back to the original directory
        os.chdir(original_dir)

        # If there's no output, something went wrong
        if not output.strip():
            print("No output captured. This might indicate an issue with the patch command or file paths.")
            return "ERROR"

        # Initialize hunk counters
        failed_hunks = 0
        succeeded_hunks = 0
        total_hunks = 0
        reversed_patch = False
        all_reversed_succeeded = True
        
        # Parse the output to count hunks and check their status
        for line in output.splitlines():
            if "Reversed (or previously applied) patch detected!" in line:
                reversed_patch = True
            elif "FAILED" in line and "Hunk" in line:
                failed_hunks += 1
                total_hunks += 1
            elif "succeeded" in line and "Hunk" in line:
                succeeded_hunks += 1
                total_hunks += 1

        # Determine the patch status based on hunks
        if total_hunks == 0:
            return "UNKNOWN"
        elif failed_hunks == total_hunks:
            return "NOT FIXED"  # All hunks failed.
        elif failed_hunks > 0:
            return "PARTIALLY FIXED"  # Some hunks failed, others succeeded.
        elif succeeded_hunks == total_hunks and reversed_patch:
            return "FIXED"  # Patch was reversed and all hunks succeeded, indicating it's already applied.
        elif succeeded_hunks == total_hunks:
            return "OPEN"  # All hunks succeeded, patch can be applied.


    except Exception as e:
        print(f"An error occurred: {e}")
        os.chdir(original_dir)
        return "ERROR"




#######################################################################################################
# process each reference to list out corresponding status


def process_references(user_log_path: str, stable_log_path: str, upstream_log_path: str, user_kernel_repo_path:str, upstream_repo_path:str, references: list, cve_id, build_file_path, patch_files_path,result_file_path):
    """
    Process each reference to check if the patch has been applied in either repository
    by looking up commit IDs and messages in the provided log files.
    """
    
    # Read the logs into memory
    def read_log(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as log_file:
                return log_file.read()
        except IOError as e:
            print(f"Error reading log file {log_path}: {e}")
            return ""

    user_log_content = read_log(user_log_path)


    # Read the result file to get the commit ID to patch filename mapping
    result_mapping = read_result_file(result_file_path)
 

    status= "CHECK-MANUALLY   (No Patch File Found in Linux Stable Repo)"
    for reference in references:
        url, source = reference  # Unpack the tuple to get the URL and its source
        print(f"\nProcessing URL: {url} (Source: {source})")

        commit_id = extract_commit_id_from_url(url)
        if not commit_id:
            print("Skipping due to missing commit ID.")
            
            continue
        if commit_id in user_log_content:
            print(f"Patch from commit ID {commit_id} with CVE {cve_id} found in user kernel log.")
            found = True
            status = "FIXED   (Patch found and applied by Commit ID)"
            break
        elif commit_id in result_mapping:
            print(f"Found commit ID {commit_id}  in commit_patchfile_map file.")
            patch_file_name = result_mapping[commit_id]
            patch_file_path = os.path.join(patch_files_path, patch_file_name)
            
            print(f"Reading patch file content in {patch_file_path} for cve_id {cve_id}\n")
            patch_content = read_file_content(patch_file_path)

            if not patch_content:
                print("No patch content in patch file")
                continue
            # Extract commit message and patch code
            commit_msg = extract_commit_msg(patch_content)
            
            print(f"Commit Message for {patch_file_name}:")
            print(commit_msg)
            print(f"searching in user_log.....")

             # Use regex to search for commit message in user kernel log
            commit_msg_search = re.search(re.escape(commit_msg), user_log_content)
            print(f"commit_msg_search:  {commit_msg_search}")

            print(f"repo path is : {user_kernel_repo_path}")
            print(f"patch file path is: {patch_file_path}")
            if commit_msg_search:
                    print(f"Patch matching commit message found in user kernel log with commit ID {commit_id}.")
                    found = True
                    status = "FIXED   (Patch found and applied by summary search)"
                    break
            

            elif check_patch_status(user_kernel_repo_path, patch_file_path) in ["FIXED", "OPEN"]:
                patch_status = check_patch_status(user_kernel_repo_path, patch_file_path)
                print(f"Patch {patch_file_name} status in the user kernel repository: {patch_status}")
                found = True
                status = f"{patch_status}   (Patch found and checked by Code match)"
                break   
            else:
                patch_content = read_file_content(patch_file_path)
                if not patch_content:
                    continue
                c_files, h_files = extract_changed_files(patch_content)
 
                #If there are no .c files and only .h files
 
                if not c_files and h_files:
                    status = "OPEN   (No object files exist for header files)"
                else:
                    #Proceed with only .c files
                    modified_files = c_files
                    with open(build_file_path, 'r') as file:
                        kernel_files = file.read().splitlines()
 
                    kernel_files = [os.path.normpath(file).replace('\\', '/') for file in kernel_files]
                    modified_files_normalized = [os.path.normpath(file).replace('\\', '/') for file in modified_files]
 
                    modified_object_files = {
                        os.path.splitext(file)[0] + '.o' for file in modified_files_normalized
                    }    
 
                    found_files = [file for file in kernel_files if file in modified_object_files]
                    #Classify the CVE
                    if len(found_files)==len(modified_files):
                        status = "OPEN   (All object files exist in Build File)"
                        break
                    elif found_files:
                        status = "CHECK-MANUALLY   (Partial object files exist in Build File)"
                    else:
                        status = "UNUSED   (No object files exist in Build File)"
        


    return status

def list_commit_ids(references,commit_ids):
    for reference in references:
        url, source = reference  # Unpack the tuple to get the URL and its source
        print(f"\nProcessing URL: {url} (Source: {source})")

        commit_id = extract_commit_id_from_url(url)
        commit_ids.append(commit_id)



#######################################################################################################
# Generate patch files which is not downloaded from stable API and saved in patch_files directory 

def generate_patch_in_upstream(repo_path, commit_id, cve_id, output_dir, result_file):
    """
    Generate a patch file for the given commit ID and save it to the specified output directory.
    Return the commit ID and the corresponding generated patch filename.
    """
    # Ensure the output directory exists in the current working directory
    output_dir = os.path.join(os.getcwd(), output_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Change directory to the repository path
    original_dir = os.getcwd()
    
    if commit_id is None:
        print("Encountered None as commit_id. Skipping.")
        return
        
    # Validate commit_id
    if not isinstance(commit_id, str) or len(commit_id) < 10:
        print(f"Invalid commit_id {commit_id}. Skipping.")
        return
    
    # Construct the expected patch file name
    patch_filename = f"{cve_id}_{commit_id[:10]}.patch"
    patch_file_path = os.path.join(output_dir, patch_filename)
    
    if os.path.exists(patch_file_path):
        # If the patch file already exists, skip generating it
        print(f"Patch file for commit {commit_id} already exists: {patch_file_path}")
        with open(result_file, 'a') as f:
            f.write(f"{commit_id} -> {patch_filename}\n")
        return
    
    # Navigate to the repository directory
    os.chdir(repo_path)
    
    # Run the git format-patch command
    try:
        result = subprocess.run(
            ['git', 'format-patch', '-1', commit_id],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error generating patch for commit {commit_id}: {e}")
        os.chdir(original_dir)  # Restore the original working directory
        return
    
    # Extract the filename of the generated patch file from stdout
    output_lines = result.stdout.splitlines()
    generated_patch_filename = None
    for line in output_lines:
        if line.endswith('.patch'):
            generated_patch_filename = line.strip()
            break
    
    # If no filename was found, return
    if not generated_patch_filename:
        print(f"No patch file generated for commit {commit_id}.")
        os.chdir(original_dir)  # Restore the original working directory
        return
    
    # Check if the generated patch file exists
    if not os.path.isfile(generated_patch_filename):
        print(f"Generated patch file {generated_patch_filename} does not exist.")
        os.chdir(original_dir)  # Restore the original working directory
        return
    
    # Prepare the new patch file path
    new_patch_file_path = os.path.join(output_dir, patch_filename)
    
    # Move the file to the output directory and rename it
    try:
        os.rename(generated_patch_filename, new_patch_file_path)
        print(f"Patch file for commit {commit_id} moved to {new_patch_file_path}")
        
        # Save the mapping to a text file
        with open(result_file, 'a') as f:
            f.write(f"{commit_id} -> {patch_filename}\n")
    except FileNotFoundError as e:
        print(f"File move failed: {e}")
    except OSError as e:
        print(f"OS error during move: {e}")
    
    # Restore the original working directory
    os.chdir(original_dir)



#######################################################################################################
# Function to generate patch files

def generate_patch_files(repo_path, commit_id,cve_id, output_dir,result_file):
    """
    Generate patch files for a list of commit IDs by downloading them from the URL
    and saving them to the specified output directory.
    """
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # List to store commit ID and corresponding patch file name as tuples
    patch_files = []
    
    
    if commit_id is None:
        print("Encountered None as commit_id. Skipping.")
        return
        
    # Validate commit_id
    elif len(commit_id) < 10:
        print(f"Invalid commit_id {commit_id}. Skipping.")
        return
        
    # Construct the expected patch file name
    patch_filename = f"{cve_id}_{commit_id[:10]}.patch"  # Simplified naming for this example
    patch_file_path = os.path.join(output_dir, patch_filename)
        
    if os.path.exists(patch_file_path):
        # If the patch file already exists, skip downloading it
        print(f"Patch file for commit {commit_id} already exists: {patch_file_path}")
        append_to_result_file(result_file, commit_id, patch_filename)
        return
        
    # Construct the URL to download the patch file
    commit_url = f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_id}"
        
    try:
        # Make a GET request to fetch the patch
        response = requests.get(commit_url)
            
        # Check if the request was successful
        if response.status_code == 200:
            # Write the response content to the output file
            with open(patch_file_path, 'wb') as file:
                file.write(response.content)
            print(f"Patch file for commit {commit_id} downloaded and saved to {patch_file_path}")
            # Save the mapping to a text file
            append_to_result_file(result_file, commit_id, patch_filename)
        else:
            print(f"Failed to download patch file for commit {commit_id}. Status code: {response.status_code}\n")
            print("trying to fetch patch file from upstream")
            generate_patch_in_upstream(repo_path, commit_id, cve_id, output_dir, result_file)
    except requests.RequestException as e:
        print(f"An error occurred while downloading patch file for commit {commit_id}: {e}")
    
#######################################################################################################
# Function to map the patch file to corresponding commit id


def append_to_result_file(result_file, commit_id, patch_filename):
    """Append the commit ID and patch filename to the result file, creating it if necessary."""
    # Ensure the directory for the result file exists
    result_dir = os.path.dirname(result_file)
    
    if result_dir:  # Only create the directory if result_dir is not empty
        if not os.path.exists(result_dir):
            os.makedirs(result_dir, exist_ok=True)  # Create the directory if it doesn't exist

    # Create the result file if it doesn't exist
    if not os.path.exists(result_file):
        with open(result_file, 'w') as f:
            f.write("Commit ID -> Patch Filename\n")  # Optional header

    # Append the mapping
    with open(result_file, 'a') as f:
        f.write(f"{commit_id} -> {patch_filename}\n")





#######################################################################################################
# Save commit Id corresponding to patch file in log

def save_patch_files_mapping(patch_files, result_file):
    # Ensure the result file has a .txt extension
    if not result_file.endswith('.txt'):
        result_file += '.txt'
    
    # Save the mapping to a text file
    with open(result_file, 'w') as f:
        for commit_id, patch_filename in patch_files:
            f.write(f"{commit_id} -> {patch_filename}\n")
    
    print(f"Patch files mapping saved to: {result_file}")

#Generate the report
def generate_report(report_path, results):
    # Sort results by CVE ID
    sorted_results = sorted(results, key=lambda x: x[0])
    
    with open(report_path, 'w') as report_file:
        for cve_id, status in sorted_results:
            report_file.write(f"{cve_id}    {status}\n")

#######################################################################################################
#Write Patch File URL with CVE IDs

def write_patch_urls_to_results(results_file, commit_map_file):
    """
    Append the patch file URLs for CVE IDs to the existing results file.
    
    :param results_file: Path to the results file containing CVE IDs and statuses.
    :param commit_map_file: Path to the commit map file containing commit IDs and patch filenames.
    """
    # Read the commit map file and create a mapping of CVE IDs to their first commit ID
    cve_commit_map = {}
    with open(commit_map_file, 'r') as file:
        for line in file:
            commit_id, patch_filename = line.strip().split(' -> ')
            cve_id = patch_filename.split('_')[0]  # Extract CVE ID from the patch filename
            if cve_id not in cve_commit_map:  # Only keep the first commit ID
                cve_commit_map[cve_id] = commit_id

    # Read the existing results and append the patch URLs
    with open(results_file, 'r') as file:
        lines = file.readlines()

    # Prepare to write back to the results file
    with open(results_file, 'w') as file:
        for line in lines:
            line = line.strip()
            if line:  # Ensure the line is not empty
                cve_id, status = line.split('    ', 1)  # Split CVE ID and status
                commit_id = cve_commit_map.get(cve_id)  # Get the first commit ID for the CVE ID
                if commit_id:
                    patch_url = f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_id}"
                    file.write(f"{line}    {patch_url}\n")  # Append the patch URL to the existing line
                else:
                    file.write(f"{line}\n")  # Write the line without a patch URL if not found               

##################################################################################################################

def check_ssh_agent():
    """Ensure the SSH agent is running and add the SSH key."""
    try:
        output = subprocess.run(['ssh-add', '-L'], capture_output=True, text=True)
        if output.returncode != 0:
            print("Starting SSH agent...")
            os.system('eval $(ssh-agent)')
            os.system('ssh-add /root/.ssh/id_rsa')
    except Exception as e:
        logger.error(f"Error checking SSH agent: {e}")
        print(f"Error checking SSH agent: {e}")


def main():

    check_ssh_agent()
    parser = argparse.ArgumentParser(description="Kernel CVE Check Tool")

    # Repository and branch arguments
    parser.add_argument('-gk', '--githubkernel', help='GitHub link to user kernel repository', required=False)
    parser.add_argument('-gb', '--githubbranch', help='Branch for the GitHub user kernel repository', required=False)
    parser.add_argument('-db', '--dotbranch', help='Upstream dot kernel branch', required=False)
    parser.add_argument('-u', '--user', help='original user name', required=False)
    parser.add_argument("--username", help="The username from request.user.username", default="default_username")
    parser.add_argument("--scan_id", help="Scan Id of Project", default="scan_id")
    parser.add_argument('-pname', '--projectname', help='project name', required=False)
    parser.add_argument('-ub', '--upstreambranch', help='upstream kernel branch', required=False)
    parser.add_argument('-build', '--buildpath', help='Build file ', required=True)
    parser.add_argument("-p", "--package_name", help="The name of the package to search.",required=False)
    parser.add_argument("-v", "--version", help="The version of the package to search.",required=False)
    parser.add_argument("-m", "--manifest_filename", help="The filename of the manifest located in the 'sample_manifest' folder.")


    print('\n')
    args = parser.parse_args()

    username = args.username
    scan_id = args.scan_id

    setup_logging(scan_id)

    # Ensure required parameters are provided
    if not args.buildpath:
        logger.error("Error: The build path is required.")
        exit(1)
        

    # Load paths from config.json
    config_data = load_paths_from_config()

    if config_data:
        # Access specific paths stored in the config file
        download_path = config_data.get('download_dir', None)
        upload_path = config_data.get('upload_dir', None)
        working_dir = config_data.get('working_dir',None)


        # Check if the paths exist and display the result
        if download_path:
            check_path_exists(download_path, "Absolute Path 1")
        else:
            print("Download Path is not defined in config.json.")
            logger.error("Download Path is not defined in config.json.")
            exit(1)

        if upload_path:
            check_path_exists(upload_path, "Absolute Path 2")
        else:
            print("Upload Path is not defined in config.json.")
            logger.error("Upload Path is not defined in config.json.")
            exit(1)
        if working_dir:
            check_path_exists(working_dir, "Absolute Path 3")
        else:
            print("working directory is not defined in config.json.")
            logger.error("Working Path is not defined in config.json.")
            exit(1)

    else:
        print("No paths available in config.json. Please first write the path for temporary files")
        logger.error("No paths available in config.json. Please first write the path for temporary files")
        exit(1)
    
    user_project_dir=None
    # Create the directory with the user name and project name under the download path
    if args.user and args.projectname and download_path:
        user_project_dir = os.path.join(download_path, args.user, args.projectname)
        
        # Check if the directory exists; if not, create it
        if not os.path.exists(user_project_dir):
            os.makedirs(user_project_dir)
            print(f"Directory '{user_project_dir}' created successfully.")
        else:
            print(f"Directory '{user_project_dir}' already exists.")
    else:
        print("Download path, user, or project name is not defined.")
        logger.error("No paths available in config.json. Please first write the path for temporary files")
        exit(1)    


    download_path = config_data.get('download_dir', None)
    upload_path = config_data.get('upload_dir', None)
    working_dir = config_data.get('working_dir',None)



    build_file_path = args.buildpath

    # Use the provided arguments or fall back to default configuration
    USER_KERNEL_REPO_URL = args.githubkernel 
    USER_KERNEL_BRANCH_NAME = args.githubbranch 
    STABLE_USER_KERNEL_REPO_URL= 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git'
    UPSTREAM_REPO_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
    UPSTREAM_BRANCH_NAME = args.upstreambranch or "master"
    STABLE_USER_KERNEL_BRANCH_NAME= args.dotbranch
    


    user_kernel_repo_path = None
    # Step 1: Clone and checkout
    if USER_KERNEL_REPO_URL and USER_KERNEL_BRANCH_NAME:
        repo_dir_name = os.path.splitext(os.path.basename(USER_KERNEL_REPO_URL))[0]
        target_folder = 'userkernel'
        user_kernel_repo_path, user_log_path = branch_clone_and_checkout(USER_KERNEL_REPO_URL, USER_KERNEL_BRANCH_NAME, repo_dir_name, target_folder,upload_path,user_project_dir)
        if not user_kernel_repo_path:
            print("Failed to prepare local repository. Exiting. Project link or project branch name is invalid")
            logger.error("Failed to prepare local repository. Exiting. Project link or project branch name is invalid ")
            exit(1)
    stable_repo_path = None


    if STABLE_USER_KERNEL_BRANCH_NAME and STABLE_USER_KERNEL_REPO_URL:
        repo_dir_name = 'dot-stable-kernel'
        target_folder = 'linux-stable'
        logs_dir_name = "stable-logs"
        stable_repo_path, stable_log_path = clone_and_checkout(STABLE_USER_KERNEL_REPO_URL,STABLE_USER_KERNEL_BRANCH_NAME, repo_dir_name, target_folder, logs_dir_name,upload_path,download_path)
        if not stable_repo_path:
            print("Failed to clone stable repo")
            logger.error("Failed to clone stable repo")
            exit(1)

    upstream_repo_path=None

    if UPSTREAM_REPO_URL and UPSTREAM_BRANCH_NAME:
        repo_dir_name = "upstream_kernel"
        target_folder = 'mainline'
        logs_dir_name = "upstream-logs"
        upstream_repo_path, upstream_log_path = clone_and_checkout(UPSTREAM_REPO_URL,UPSTREAM_BRANCH_NAME, repo_dir_name, target_folder, logs_dir_name,upload_path,download_path)
        if not upstream_repo_path:
            print("Failed to clone stable repo")
            logger.error("Failed to clone linux mainline repo")
            exit(1)

    pack=args.package_name or 'kernel'

    if pack and args.version:
        # Strip any leading or trailing spaces from the package name and version
        package_name = args.package_name or 'kernel'
        version = args.version

        # Search directly using the provided package name and version
        manifest_entries = [(package_name, version)]

    elif args.manifest_filename:
        # Load manifest from the provided filename
        manifest_file_path =  args.manifest_filename
        manifest_entries = load_manifest(manifest_file_path)
           

    else:
        # No arguments provided, display warning and exit
        print("Warning: Please provide either a manifest file name or both a package name and version.")
        logger.warning("Warning: Please provide either a manifest file name or both a package name and version.")
        exit(1)

    # Path to the CSV file containing the package dictionary
    csv_dict_file_path = os.path.join(DICTIONARY_PATH)

    cve_ids=[]

    if args.manifest_filename:
        cve_ids= accumulate_cve_ids_manifest(manifest_entries,csv_dict_file_path)
        if len(cve_ids)==0:
            logger.error("No kernel package name found in manifest")
    if args.version: 
        cve_ids = accumulate_cve_ids(manifest_entries, csv_dict_file_path)


    results = []
    output_dir = "patch_files"

    result_file = "commit_map_patch_result.txt"

    output_dir = os.path.join(download_path,"patch_files")
    os.makedirs(output_dir, exist_ok=True)

    result_file = os.path.join(working_dir,"commit_map_patch_result.txt")
    

    for cve_id in cve_ids:
        references = get_filtered_references(cve_id)
        if references:
            for reference in references:
                url, source = reference  # Unpack the tuple to get the URL and its source
                print(f"\nProcessing URL: {url} (Source: {source})")
                commit_id = extract_commit_id_from_url(url)
                # Generate patch file and Save the results to a text file
                
                generate_patch_files(upstream_repo_path, commit_id,cve_id, output_dir, result_file)
    


    base_dir = os.getcwd()  # Get the current working directory


    # Define the directory for patch files and the result file path
    patch_files_path = os.path.join(download_path, 'patch_files')
    result_file_path = os.path.join(working_dir, 'commit_map_patch_result.txt')

    # Step 2: Get filtered references
    for cve_id in cve_ids:
        references = get_filtered_references(cve_id)
        if not references:
           status = "CHECK-MANUALLY   (No Patch URL Available)"
           print(f"{cve_id}    No Patch url available in NVD data")
        
        else:
            # Step 3: Process each reference
            status = process_references(user_log_path, stable_log_path, upstream_log_path, user_kernel_repo_path, upstream_repo_path, references,cve_id,build_file_path,patch_files_path,result_file_path)
            print(f"{cve_id}    {status}")
        results.append((cve_id, status))


    # Ensure the report directory exists
    if not os.path.exists(PKCT_REPORT_PATH):
        os.makedirs(PKCT_REPORT_PATH)
        print(f"Directory '{PKCT_REPORT_PATH}' created.")
 
    # Generate a timestamped filename for the results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_path = os.path.join(PKCT_REPORT_PATH, f'results_{timestamp}.txt')
    
    #Generate the Report
    generate_report(output_file_path, results)

    # Write the patch file URLs for CVE IDs into the results file
    write_patch_urls_to_results(output_file_path, result_file_path)
    logger.info(f"Results have been written to {output_file_path}")
    
    print(f"Results have been written to {output_file_path}")
    return output_file_path

if __name__ == "__main__":
    main()





