"""
====================
cve_search_manifest.py
Searches CVEs for Package Name And Version Using Manifest File
author: Chandramani Kumar
modified by : Shubham
===================
"""

import os
import django
from uuid import UUID
import re
import csv
import settings
from datetime import datetime
import argparse
import logging
import pandas as pd

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

# Initialize Django
django.setup()
from serverapp.models import MatchString, CPEMatch, CVEConfiguration, CVE, CPEMatchInNode

LOGS_DIR = os.path.join(settings.PROJECT_DIR,'hmi','CVEHMI','hmiapp','media','logs')
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logging
def setup_logging(scan_id):
    log_file_path = os.path.join(LOGS_DIR, f"{scan_id}_scan.log")
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

# Create a logger instance
logger = logging.getLogger(__name__)  # Create a logger for this module


DICTIONARY_PATH = settings.DICTIONARY_PATH
REPORT_PATH = settings.REPORT_PATH

def parse_version(version):
    match = re.match(r"([\d\.]+)([a-zA-Z]*)", version)
    if match:
        version_str = match.group(1)
        suffix = match.group(2)
        try:
            version_tuple = tuple(map(int, version_str.split('.')))
            return version_tuple, suffix
        except ValueError:
            logger.error(f"Invalid version format: {version}")
            print(f"Invalid version format: {version}")
            return None, None
    else:
        logger.error(f"Invalid version format: {version}")
        print(f"Invalid version format: {version}")
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
            return segments[3], segments[5]
        return None, None

    vendor_match_criteria = {}

    for match in match_strings:
        vendor_name, criteria_version_field = get_criteria_segments(match.criteria)

        if vendor_name is None:
            continue

        if criteria_version_field == version:
            if vendor_name not in vendor_match_criteria:
                vendor_match_criteria[vendor_name] = []
            vendor_match_criteria[vendor_name].append(str(match.match_criteria_id).upper())
        elif criteria_version_field == '*':
            start_incl = match.version_start_including
            end_incl = match.version_end_including
            start_excl = match.version_start_excluding
            end_excl = match.version_end_excluding
            
            if is_version_in_range(version, start_incl, end_incl, start_excl, end_excl):
                if vendor_name not in vendor_match_criteria:
                    vendor_match_criteria[vendor_name] = []
                vendor_match_criteria[vendor_name].append(str(match.match_criteria_id).upper())

    print(f"Match criteria IDs categorized by vendor: {vendor_match_criteria}")
    return vendor_match_criteria

def find_cve_id_by_match_criteria_id(match_criteria_id):
    cve_ids = set()
    cve_status = {}

    try:
        match_criteria_uuid = UUID(match_criteria_id)
        print(f"Searching for CVEs with match_criteria_id: {match_criteria_id}")

        cpe_matches = CPEMatch.objects.select_related('configuration__cve').filter(match_criteria_id=match_criteria_uuid)
        for cpe_match in cpe_matches:
            cve_id = cpe_match.configuration.cve.id
            cve_ids.add(cve_id)
            cve_status[cve_id] = cpe_match.vulnerable
            print(f"Found CVE ID '{cve_id}' from CPEMatch with vulnerability status: {cpe_match.vulnerable}")

        cpe_match_in_nodes = CPEMatchInNode.objects.select_related('node__configuration__cve').filter(match_criteria_id=match_criteria_uuid)
        for cpe_match_in_node in cpe_match_in_nodes:
            cve_id = cpe_match_in_node.node.configuration.cve.id
            cve_ids.add(cve_id)
            cve_status[cve_id] = cpe_match_in_node.vulnerable
            print(f"Found CVE ID '{cve_id}' from CPEMatchInNode with vulnerability status: {cpe_match_in_node.vulnerable}")

        result = {cve_id: cve_status[cve_id] for cve_id in cve_ids}
        print(f"Final CVE IDs and their status: {result}")
        return result if result else None

    except ValueError:
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

def write_results_to_file(results, file_path):
    """
    Write the results to a text file with sorted CVE IDs.
    
    :param results: List of tuples containing package names, versions, and CVE data.
    :param file_path: Path to the output text file.
    """
    with open(file_path, 'w') as file:
        for package_name, version, cve_data in results:
            file.write(f"Package Name : {package_name}\n")
            file.write(f"Version : {version}\n")
            file.write("\nAll CVE IDs and Vulnerability Status by Vendor:\n\n")

            for vendor, cve_data_by_vendor in cve_data.items():
                file.write(f"Vendor: {vendor}\n")
                # Sort CVE data by CVE ID
                sorted_cve_data = sorted(cve_data_by_vendor.items(), key=lambda item: item[0])
                for cve_id, vulnerable in sorted_cve_data:
                    if vulnerable:
                        file.write(f"CVE ID: {cve_id}, Vulnerable: {vulnerable}\n")
                file.write("\n")

def load_blacklist(file_path,scan_id):
    """
    Load CVE IDs from a blacklist file.
    
    :param file_path: Path to the blacklist file (Excel or CSV).
    :return: Set of CVE IDs to be excluded.
    """
    setup_logging(scan_id)
    blacklist = set()
    if file_path.endswith('.xlsx'):
        df = pd.read_excel(file_path, header=None)  # Specify no header
        blacklist = set(df.iloc[:, 0].dropna().astype(str).str.strip().str.upper().tolist())
    elif file_path.endswith('.csv'):
        df = pd.read_csv(file_path, header=None)  # Specify no header
        blacklist = set(df.iloc[:, 0].dropna().astype(str).str.strip().str.upper().tolist())
    else:
        logger.error("Unsupported file format. Please provide an Excel or CSV file.")
    
    return blacklist 

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Search CVEs for package names and versions using a manifest file or direct input.")
    parser.add_argument("-m", "--manifest_filename", help="The filename of the manifest located in the 'sample_manifest' folder.")
    parser.add_argument("-p", "--package_name", help="The name of the package to search.")
    parser.add_argument("-v", "--version", help="The version of the package to search.")
    parser.add_argument("--username", help="The username from request.user.username", default="default_username")
    parser.add_argument("--scan_id", help="Scan Id of the Project", default="scan_id")
    parser.add_argument("--blacklist", help="The path to blacklist file")

    # Parse the arguments
    args = parser.parse_args()

    username = args.username
    scan_id = args.scan_id
    setup_logging(scan_id)

    if args.manifest_filename:
        # Load manifest from the provided filename
        manifest_file_path = args.manifest_filename
        manifest_entries = load_manifest(manifest_file_path)
    elif args.package_name and args.version:
        # Search directly using the provided package name and version
        manifest_entries = [(args.package_name, args.version)]
    else:
        # No arguments provided, display warning and exit
        logger.warning("Warning: Please provide either a manifest file name or both a package name and version.")
        print("Warning: Please provide either a manifest file name or both a package name and version.")
        exit(1)

    # Load dictionary from CSV
    csv_dict_file_path = os.path.join(DICTIONARY_PATH)
    package_dictionary = load_package_dictionary(csv_dict_file_path)

    # Load the blacklist if provided
    blacklist = set()
    if args.blacklist:
        blacklist = load_blacklist(args.blacklist, args.scan_id)

    # Dictionary to accumulate CVE data by vendor
    results = []
    
    # Set to keep track of processed kernel versions
    processed_kernel_versions = set()

    # Inside the loop that processes each package entry
    for package_name, version in manifest_entries:
        logger.info(f"Processing package: {package_name}, version: {version}")

        # Skip if this is a redundant kernel package version
        if package_name.lower().startswith('kernel') and version in processed_kernel_versions:
            print(f"Skipping redundant processing for kernel version {version}")
            continue  # Move to the next package

        # Mark this kernel version as processed
        if package_name.lower().startswith('kernel'):
            processed_kernel_versions.add(version)

        # Proceed with the rest of the processing logic for this package
        if package_name.lower().startswith('kernel'):
            package_name = 'kernel'
            
        alternate_package_names = search_alternate_package_names(package_name, package_dictionary)
        all_package_names = [package_name] + alternate_package_names

        # Existing logic to gather CVE data
        all_cve_data = {}

        for name in all_package_names:
            vendor_match_strings = get_match_strings(name, version)
            
            for vendor_name, match_criteria_ids in vendor_match_strings.items():
                for match_criteria_id in match_criteria_ids:
                    cve_data = find_cve_id_by_match_criteria_id(match_criteria_id)
                    if cve_data:
                        # Exclude blacklisted CVE IDs
                        cve_data = {k: v for k, v in cve_data.items() if k not in blacklist}                        
                        if cve_data:
                            if vendor_name not in all_cve_data:
                                all_cve_data[vendor_name] = {}
                            all_cve_data[vendor_name].update(cve_data)

        results.append((package_name, version, all_cve_data))

    # Generate a timestamped filename for the results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_path = os.path.join(REPORT_PATH, f'results_{timestamp}.txt')

    # Write results to the file
    write_results_to_file(results, output_file_path)
    
    print(f"Results have been written to {output_file_path}")
    return output_file_path

if __name__ == "__main__":
    main()