"""
====================
cvechecker_report.py
Report Generation For CVEHMI Tool
author: Shubham

===================
"""

import os
import sys
import django
from uuid import UUID
import re
import csv
import settings
from datetime import datetime
import argparse
import pandas as pd
import logging
from django.utils.timezone import make_naive
import argparse
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from cve_search_manifest import *
from hmi.CVEHMI.cve_report_functions import *


# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

# Initialize Django
django.setup()

from serverapp.models import CVE, CVEDescription, CVSSMetricV2, CVSSMetricV31, CVEWeakness, CVEReference, MatchString, CPEMatch, CVEConfiguration, CPEMatchInNode


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

def read_data_from_file(file_path):
    package_data = {}
    current_package = None
    current_version = None
    current_vendor = None
   
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()
            if line.startswith("Package Name :"):
                current_package = line.split(":")[1].strip()
                logging.info(f"Processing package: {current_package}")
                if current_package not in package_data:
                    package_data[current_package] = {}
            elif line.startswith("Version :"):
                current_version = line.split(":")[1].strip()
                logging.info(f"Processing version: {current_version}")
                if current_version not in package_data[current_package]:
                    package_data[current_package][current_version] = {'cve_entries': []}
            elif line.startswith("Vendor:"):
                current_vendor = line.split(":")[1].strip()
            elif line.startswith("CVE ID:"):
                parts = line.split(", ")
                cve_id = parts[0].split(":")[1].strip()
                vulnerable = parts[1].split(":")[1].strip()
                package_data[current_package][current_version]['cve_entries'].append((cve_id, vulnerable, current_vendor))
   
    return package_data

def fetch_cve_details(cve_ids, include_sections):
    cve_details = {}
   
    for cve_id, vendor_name in cve_ids:
        try:
            cve = CVE.objects.get(id=cve_id)
            published_date = make_naive(cve.published).date()
            cve_details[cve_id] = {
                'CVE ID': cve.id,
                'Source Identifier': cve.source_identifier,
                'Published': make_naive(cve.published),
                'Published Date': published_date,
                'Last Modified': make_naive(cve.last_modified),
                'Vulnerability Status': cve.vuln_status,
                'Vendor Name': vendor_name
            }

            if 'Description' in include_sections:
                descriptions = CVEDescription.objects.filter(cve=cve).values('lang', 'value')
                
                cve_details[cve_id]['Description'] = []
                for desc in descriptions:
                    if desc['lang'] != 'es':  # Exclude descriptions in Spanish
                        
                        cve_details[cve_id]['Description'].append(desc['value'])
            if 'CVSSV2' in include_sections:
                metrics_v2 = CVSSMetricV2.objects.filter(cve=cve).values(
                    'source', 'version', 'vector_string', 'access_vector',
                    'base_score', 'exploitability_score', 'impact_score'
                )
                cve_details[cve_id]['CVSS V2'] = list(metrics_v2)

            if 'CVSSV3.1' in include_sections:
                metrics_v31 = CVSSMetricV31.objects.filter(cve=cve).values(
                    'source', 'version', 'vector_string', 'attack_vector',
                    'privileges_required', 'base_score', 'exploitability_score', 'impact_score'
                )
                cve_details[cve_id]['CVSS V3.1'] = list(metrics_v31)

            if 'Weaknesses' in include_sections:
                weaknesses = CVEWeakness.objects.filter(cve=cve).values('source', 'type', 'description')
                cve_details[cve_id]['Weaknesses'] = [
                    f"Source: {w['source']}, Type: {w['type']}, Description: {w['description']}"
                    for w in weaknesses
                ]
            if 'References' in include_sections:
                references = CVEReference.objects.filter(cve=cve).values('url', 'source', 'tags')
                cve_details[cve_id]['References'] = [
                    f"URL: {r['url']}, Source: {r['source']}, Tags: {r['tags']}"
                    for r in references
                ]

        except CVE.DoesNotExist:
            logger.error(f"CVE ID {cve_id} not found in the database.")

    # Convert aggregated data into a list of dictionaries
    aggregated_details = []
    for cve_id, details in cve_details.items():
        entry = {
            'CVE ID': details['CVE ID'],
            'Package Name': '',
            'Version': '',
            'Vendor Name': details['Vendor Name'],
            'Vulnerability Status': details['Vulnerability Status'],
            'Source Identifier': details['Source Identifier'],
            'Published': details['Published'],
            'Published Date': details['Published Date'],
            'Last Modified': details['Last Modified'],
        }

        if 'Description' in include_sections:
            entry.update({
                
                'Description': ' | '.join(details.get('Description', [])),
            })
        if 'CVSSV2' in include_sections:
            entry.update({
                'CVSS V2 Source': ', '.join([metric['source'] for metric in details.get('CVSS V2', [])]),
                'CVSS V2 Version': ', '.join([metric['version'] for metric in details.get('CVSS V2', [])]),
                'CVSS V2 Vector String': ', '.join([metric['vector_string'] for metric in details.get('CVSS V2', [])]),
                'CVSS V2 Access Vector': ', '.join([metric['access_vector'] for metric in details.get('CVSS V2', [])]),
                'CVSS V2 Base Score': ', '.join([str(metric['base_score']) for metric in details.get('CVSS V2', [])]),
                'CVSS V2 Exploitability Score': ', '.join([str(metric['exploitability_score']) for metric in details.get('CVSS V2', [])]),
                'CVSS V2 Impact Score': ', '.join([str(metric['impact_score']) for metric in details.get('CVSS V2', [])])
            })

        if 'CVSSV3.1' in include_sections:
            entry.update({
                'CVSS V3.1 Source': ', '.join([metric['source'] for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Version': ', '.join([metric['version'] for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Vector String': ', '.join([metric['vector_string'] for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Attack Vector': ', '.join([metric['attack_vector'] for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Privileges Required': ', '.join([metric['privileges_required'] for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Base Score': ', '.join([str(metric['base_score']) for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Exploitability Score': ', '.join([str(metric['exploitability_score']) for metric in details.get('CVSS V3.1', [])]),
                'CVSS V3.1 Impact Score': ', '.join([str(metric['impact_score']) for metric in details.get('CVSS V3.1', [])])
            })
        if 'Weaknesses' in include_sections:
            entry['Weakness Details'] = ' | '.join(details.get('Weaknesses', []))

        if 'References' in include_sections:
            entry['Reference Details'] = ' | '.join(details.get('References', []))

        aggregated_details.append(entry)
   
    return aggregated_details

def prepare_data_for_excel(package_data, include_sections, filters, scan_id):
    sheets = {}
    setup_logging(scan_id)
    for package, versions in package_data.items():
        for version, data in versions.items():
            cve_entries = data['cve_entries']
            cve_ids_with_vendor = [(entry[0], entry[2]) for entry in cve_entries]
           
            cve_details = fetch_cve_details(cve_ids_with_vendor, include_sections)

            # Create a DataFrame from the CVE details
            df = pd.DataFrame(cve_details)

            # Ensure CVSS columns are present
            cvss_columns = ['CVSS V2 Base Score', 'CVSS V2 Exploitability Score', 'CVSS V2 Impact Score',
                            'CVSS V3.1 Base Score', 'CVSS V3.1 Exploitability Score', 'CVSS V3.1 Impact Score']
            for col in cvss_columns:
                if col not in df.columns:
                    df[col] = None  # Add the column with None values if it doesn't exist

            if df.empty:
                logger.error(f"No data available for package {package}, version {version}")
                continue

            # Handle 'Published' and 'Published Date' columns
            if 'Published' in df.columns:
                df['Published'] = pd.to_datetime(df['Published'])
                df['Published Date'] = df['Published'].dt.date
            elif 'Published Date' in df.columns:
                df['Published Date'] = pd.to_datetime(df['Published Date']).dt.date
            else:
                logger.error(f"Neither 'Published' nor 'Published Date' column found for package {package}, version {version}")

            # Apply filters
            if 'PublishedDate' in filters and 'Published Date' in df.columns:
                df['Published Date'] = pd.to_datetime(df['Published Date']).dt.date
                df = df[df['Published Date'] >= filters['PublishedDate']]

            df['Published Date'] = df['Published Date'].astype(str).str.split(' ').str[0]
            df['Last Modified'] = df['Last Modified'].astype(str).str.split(' ').str[0]
            
            # Function to check if any score in a comma-separated string meets the criteria
            def check_scores(scores, threshold):
                if pd.isna(scores):
                    return False
                return any(float(score.strip()) >= threshold for score in str(scores).split(',') if score.strip())

            # Apply CVSS filters
            cvss_columns_dict = {
                'CVSSV2Base': 'CVSS V2 Base Score',
                'CVSSV2Exploitability': 'CVSS V2 Exploitability Score',
                'CVSSV2Impact': 'CVSS V2 Impact Score',
                'CVSSV3.1Base': 'CVSS V3.1 Base Score',
                'CVSSV3.1Exploitability': 'CVSS V3.1 Exploitability Score',
                'CVSSV3.1Impact': 'CVSS V3.1 Impact Score'
            }

            for filter_key, column_name in cvss_columns_dict.items():
                if filter_key in filters:
                    if column_name in df.columns:
                        df = df[df[column_name].apply(lambda x: check_scores(x, filters[filter_key]))]
                    else:
                        logger.warning(f"Column '{column_name}' not found in the data. Skipping this filter.")

            if not df.empty and 'CVE ID' in df.columns:
                # Add 'Package Name' and 'Version' as new columns
                df['Package Name'] = package
                df['Version'] = version

                # Select only the specified sections
                columns_to_include = ['CVE ID', 'Package Name', 'Version', 'Vendor Name', 'Vulnerability Status', 'Published Date', 'Last Modified']
                if 'Description' in include_sections:
                    columns_to_include.extend(['Description'])
                if 'CVSSV2' in include_sections:
                    columns_to_include.extend(['CVSS V2 Source', 'CVSS V2 Version', 'CVSS V2 Vector String', 'CVSS V2 Access Vector', 'CVSS V2 Base Score', 'CVSS V2 Exploitability Score', 'CVSS V2 Impact Score'])
                if 'CVSSV3.1' in include_sections:
                    columns_to_include.extend(['CVSS V3.1 Source', 'CVSS V3.1 Version', 'CVSS V3.1 Vector String', 'CVSS V3.1 Attack Vector', 'CVSS V3.1 Privileges Required', 'CVSS V3.1 Base Score', 'CVSS V3.1 Exploitability Score', 'CVSS V3.1 Impact Score'])
                if 'Weaknesses' in include_sections:
                    columns_to_include.append('Weakness Details')
                if 'References' in include_sections:
                    columns_to_include.append('Reference Details')

                # Only include columns that exist in the DataFrame
                columns_to_include = [col for col in columns_to_include if col in df.columns]

                df = df[columns_to_include]

                # Sort DataFrame by 'CVE ID'
                df = df.sort_values(by='CVE ID')

                # Create a unique sheet name (20 chars of package + 8 chars of version)
                short_package = package[:20]
                short_version = version[:8]
                sheet_name = f"{short_package}_{short_version}"
               
                # Ensure unique sheet names by appending a counter if necessary
                counter = 1
                original_sheet_name = sheet_name
                while sheet_name in sheets:
                    sheet_name = f"{original_sheet_name}_{counter}"
                    counter += 1
               
                sheets[sheet_name] = df
            else:
                logger.warning(f"No data available for package {package}, version {version} after applying filters.")
   
    return sheets


def write_to_excel(sheets, file_path):
    with pd.ExcelWriter(file_path, engine='xlsxwriter') as writer:
        for sheet_name, df in sheets.items():
            df.to_excel(writer, sheet_name=sheet_name, index=False)
            worksheet = writer.sheets[sheet_name]
           
            # Adjust column width based on the length of the content
            for col in df.columns:
                max_length = df[col].astype(str).map(len).max()  # Find max length of content in each column
                adjusted_width = max_length + 2  # Add some extra space
                col_idx = df.columns.get_loc(col)  # Get column index
                worksheet.set_column(col_idx, col_idx, adjusted_width)


def read_excel(file_path):
    # Read the Excel file
    excel_data = pd.ExcelFile(file_path)
   
    # Create a dictionary to store data
    data = {}
   
    for sheet_name in excel_data.sheet_names:
        df = pd.read_excel(file_path, sheet_name=sheet_name)
       
        # Extract package and version from sheet name
        package, version = sheet_name.rsplit('_', 1)
       
        # Create a unique key for each package-version combination
        key = f"{package}_{version}"
       
        # Ensure CVSS columns are present
        cvss_columns = ['CVSS V2 Base Score', 'CVSS V2 Exploitability Score', 'CVSS V2 Impact Score',
                        'CVSS V3.1 Base Score', 'CVSS V3.1 Exploitability Score', 'CVSS V3.1 Impact Score']
        for col in cvss_columns:
            if col not in df.columns:
                df[col] = None  # Add the column with None values if it doesn't exist

        # Convert relevant columns to numeric, handling multiple scores
        for col in cvss_columns:
            df[col] = df[col].apply(lambda x: ', '.join([str(score) for score in pd.to_numeric(x.split(','), errors='coerce') if pd.notna(score)]) if isinstance(x, str) else x)

        # Add data to dictionary
        data[key] = df
   
    return data

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Search CVEs for package names and versions using a manifest file or direct input.")
    parser.add_argument("-m", "--manifest_filename", help="The filename of the manifest located in the 'sample_manifest' folder.")
    parser.add_argument("-p", "--package_name", help="The name of the package to search.")
    parser.add_argument("-v", "--version", help="The version of the package to search.")
    parser.add_argument('-s','--sections', nargs='+', choices=['Description', 'CVSSV2', 'CVSSV3.1', 'Weaknesses', 'References'],
                        default=['Description', 'CVSSV2', 'CVSSV3.1', 'Weaknesses', 'References'],
                        help='Specify which sections to include in the report')
    parser.add_argument('-f', '--filter', nargs='+', action='append',
                        help='Filter CVEs by field and value (format: FIELD VALUE, e.g., PublishedDate 20-05-2022 CVSSV2Base 2.5 CVSSV2Exploitability 1.5 CVSSV2Impact 1.5 CVSSV3.1Base 3.2 CVSSV3.1Exploitability 1.7 CVSSV3.1Impact 2.2)')
    parser.add_argument('--username', help='The username of the person running the scan', default="default_username")
    parser.add_argument('--project_id', help='The ID of the project being scanned', default="project_id")
    parser.add_argument('--scan_id', help='The scan ID for this specific scan',default="scan_id")
    parser.add_argument("--blacklist", help="Path to the Excel or CSV file containing CVE IDs to exclude.")
    parser.add_argument('--report_name', help='The name of the report to generate')

    # Parse the arguments
    args = parser.parse_args()

    username = args.username
    project_id = args.project_id
    scan_id = args.scan_id

    setup_logging(scan_id)

    
    if args.manifest_filename:
        # Construct the manifest file path
        manifest_filename = args.manifest_filename
        manifest_file_path = os.path.join('sample_manfest_files', manifest_filename)
    
        # Check if the manifest file exists
        if not os.path.isfile(manifest_file_path):
            logging.error(f"Error: The file '{manifest_filename}' does not exist in the 'sample_manfest_files' folder.")
            exit(1)  # Exit the script with a non-zero status to indicate an error
    
        # Load manifest from the provided filename
        manifest_entries = load_manifest(manifest_file_path)

    elif args.package_name and args.version:
        # Strip any leading or trailing spaces from the package name and version
        package_name = args.package_name.strip()
        version = args.version.strip()

        # Search directly using the provided package name and version
        manifest_entries = [(package_name, version)]

    else:
        # No arguments provided, display warning and exit
        logger.warning("Warning: Please provide either a manifest file name or both a package name and version.")
        exit(1)

    # Load dictionary from CSV
    csv_dict_file_path = os.path.join(DICTIONARY_PATH)
    package_dictionary = load_package_dictionary(csv_dict_file_path)

    # Load the blacklist if provided
    blacklist = set()
    if args.blacklist:
        blacklist = load_blacklist(args.blacklist, scan_id)
        logger.info(f"Loaded blacklist with {len(blacklist)} CVE IDs: {blacklist}") 

    # Dictionary to accumulate CVE data by vendor
    results = []

    # Set to keep track of processed kernel versions
    processed_kernel_versions = set()

    # Inside the loop that processes each package entry
    for package_name, version in manifest_entries:
        print(f"Processing package: {package_name}, version: {version}")
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
    report_date = datetime.now().strftime("%d-%m-%Y")
    output_file_path = os.path.join(REPORT_PATH, f'results_{timestamp}.txt')

    # Write results to the file
    write_results_to_file(results, output_file_path)
    
    logger.info(f"Results have been written to {output_file_path}")

    include_sections = args.sections
    filters = {}

    if args.filter:
        for filter_group in args.filter:
            if len(filter_group) >= 2:
                for i in range(0, len(filter_group), 2):
                    field, value = filter_group[i], filter_group[i+1]
                    if field == 'PublishedDate':
                        filters[field] = datetime.strptime(value, '%d-%m-%Y').date()
                    elif field in ['CVSSV2Base', 'CVSSV2Exploitability', 'CVSSV2Impact', 'CVSSV3.1Base', 'CVSSV3.1Exploitability', 'CVSSV3.1Impact']:
                        filters[field] = float(value)
                    else:
                        logger.error(f"Unsupported filter field: {field}. Supported fields are 'PublishedDate', 'CVSSV2Base', 'CVSSV2Exploitability', 'CVSSV2Impact', 'CVSSV3.1Base', 'CVSSV3.1Exploitability', 'CVSSV3.1Impact'.")
                        return
            else:
                logger.error(f"Invalid filter format: {filter_group}. Use 'FIELD VALUE' format.")
                return     
            

    output_excel_path = os.path.join(REPORT_PATH, f'cve_report_{timestamp}.xlsx')
    output_html_path = os.path.join(REPORT_PATH, f'cve_report_{timestamp}.html')

    input_txt_path = output_file_path    

    hmi_path = settings.HMI_REPORT
    hmi_report_path = os.path.join(settings.PROJECT_DIR, 'hmi', 'CVEHMI', 'hmiapp', 'media', 'reports', username, project_id, scan_id)
    if not os.path.exists(hmi_report_path):
        os.makedirs(hmi_report_path)

    if args.report_name:
        report_name = args.report_name
    else:
        report_name = f'cve_report_{scan_id}'

    manifest_file = os.path.basename(args.manifest_filename)

    excel_report = os.path.join(hmi_report_path, f'{report_name}.xlsx')
    html_report =  os.path.join(hmi_report_path, f'{report_name}.html')

    package_data = read_data_from_file(input_txt_path)
    sheets = prepare_data_for_excel(package_data, include_sections,filters, scan_id)
    
    if sheets:
        write_to_excel(sheets, output_excel_path)
        write_to_excel(sheets, excel_report)

        data = read_excel(output_excel_path)

        # Convert 'Published' column to datetime and extract date
        for df in data.values():
            if 'Published' in df.columns:
                df['Published'] = pd.to_datetime(df['Published'])
                df['Published Date'] = df['Published'].dt.date
            elif 'Published Date' in df.columns:
                df['Published Date'] = pd.to_datetime(df['Published Date']).dt.date
            else:
                logger.warning("Warning: Neither 'Published' nor 'Published Date' column found in the data.")
        # Step 2: Generate HTML report with filters
                      
        generate_html_report(data, output_html_path, include_sections, filters, manifest_file, report_date)
        generate_html_report(data, html_report, include_sections, filters, manifest_file, report_date)     
        logger.info(f"Excel Report generated: {output_excel_path}")   
        logger.info(f"HTML Report generated: {output_html_path}")
        logger.info(f"Excel Report generated: {excel_report}")
        logger.info(f"HTML Report generated: {html_report}")
        logger.info(f"Sections included: {include_sections}")
        for field, value in filters.items():
            logger.info(f"Filtered by {field}: {value}")

    else:
        logger.info("No CVEs found matching the specified criteria. Empty report generated.")
        write_empty_excel(output_excel_path)
        write_empty_excel(excel_report)
        generate_empty_html_report(output_html_path, include_sections)
        generate_empty_html_report(html_report, include_sections)

    generate_download_html(scan_id, username, project_id, excel_report, html_report, hmi_path, hmi_report_path, manifest_file, report_date, report_name)

    
if __name__ == "__main__":
    main()

