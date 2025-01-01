import aiohttp
import asyncio
from uuid import uuid4
from asgiref.sync import sync_to_async
from django.utils.dateparse import parse_datetime
from datetime import timezone as dt_timezone
import logging
import os
import django

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Server.settings')

# Initialize Django
django.setup()

# Import Django models
from serverapp.models import MatchString, CPEName, MatchCriteriaResponse

# Your API Key
API_KEY = 'ea1631b1-0115-480e-8a5b-584ca41201e5'

# Semaphore for limiting the number of concurrent fetches
MAX_CONCURRENT_REQUESTS = 10
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

async def fetch_page(start_index, results_per_page, retries=10):
    """Fetch a specific page of CPE match data with retry logic."""
    base_url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    headers = {
        'apiKey': API_KEY,
        'User-Agent': 'Mozilla/5.0 (compatible; Python Script)'
    }

    async with semaphore:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, params=params, headers=headers) as response:
                    if response.status == 403:
                        logging.error(f"Error fetching data from NVD API: 403 Forbidden, URL: {response.url}")
                        if retries > 0:
                            await asyncio.sleep(2 ** (5 - retries))  # Exponential backoff
                            return await fetch_page(start_index, results_per_page, retries - 1)
                        else:
                            logging.error("Max retries reached. Skipping this request.")
                            return None
                    elif response.status == 404:
                        logging.error(f"Error fetching data from NVD API: 404 Not Found, URL: {response.url}")
                        return None
                    response.raise_for_status()  # Raise an exception for bad response status
                    return await response.json()
        except aiohttp.ClientError as e:
            logging.error(f"Error fetching data from NVD API: {e}")
            return None

async def save_match_strings(match_strings):
    """Save MatchString objects to the database and return a mapping of match_criteria_id to MatchString objects."""
    if not match_strings:
        return {}
    match_string_objs = await sync_to_async(MatchString.objects.bulk_create)(match_strings, ignore_conflicts=True)
    match_string_map = {obj.match_criteria_id: obj for obj in match_string_objs}
    logging.info(f"Bulk created {len(match_string_objs)} MatchString records")
    return match_string_map

async def create_cpe_names(cpe_names, match_string_map):
    """Create CPEName objects using the provided match_string_map."""
    if not cpe_names:
        return

    logging.debug(f"CPE Names to create: {cpe_names}")
    logging.debug(f"Match String Map: {match_string_map}")

    # Use sync_to_async for the creation operations
    for cpe_name_data in cpe_names:
        match_string = match_string_map.get(cpe_name_data['match_criteria_id'])
        if match_string:
            try:
                await sync_to_async(lambda data: CPEName.objects.create(
                    match_string=match_string,
                    cpe_name=data['cpe_name'],
                    cpe_name_id=data['cpe_name_id']
                ))(cpe_name_data)
            except Exception as e:
                logging.error(f"Error creating CPEName: {e}")
        else:
            logging.warning(f"No MatchString found for CPEName with match_criteria_id: {cpe_name_data['match_criteria_id']}")
    
    logging.info(f"Created {len(cpe_names)} CPEName records")

async def save_cpe_data(cpe_data, response_metadata):
    """Process and save CPE data."""
    if cpe_data is None:
        logging.info("No data to process")
        return 0

    # Save response metadata
    await sync_to_async(MatchCriteriaResponse.objects.update_or_create)(
        results_per_page=response_metadata.get('resultsPerPage', 0),
        start_index=response_metadata.get('startIndex', 0),
        total_results=response_metadata.get('totalResults', 0),
        format=response_metadata.get('format', ''),
        version=response_metadata.get('version', ''),
        timestamp=parse_datetime(response_metadata.get('timestamp', '')).replace(tzinfo=dt_timezone.utc),
    )

    # Collect data to be processed
    match_strings = []
    cpe_names = []

    for match_entry in cpe_data.get('matchStrings', []):
        match_string_data = match_entry.get('matchString', {})
        match_criteria_id = match_string_data.get('matchCriteriaId')
        criteria = match_string_data.get('criteria')
        last_modified = parse_datetime(match_string_data.get('lastModified')).replace(tzinfo=dt_timezone.utc)
        cpe_last_modified = parse_datetime(match_string_data.get('cpeLastModified')).replace(tzinfo=dt_timezone.utc)
        created_at = parse_datetime(match_string_data.get('created')).replace(tzinfo=dt_timezone.utc)
        status = match_string_data.get('status', 'Unknown')

        if not match_criteria_id or not criteria:
            logging.warning("Skipping CPE entry due to missing 'matchCriteriaId' or 'criteria'.")
            continue

        match_strings.append(
            MatchString(
                match_criteria_id=match_criteria_id,
                criteria=criteria,
                last_modified=last_modified,
                cpe_last_modified=cpe_last_modified,
                created=created_at,
                status=status,
                version_start_including=match_string_data.get('versionStartIncluding'),
                version_end_including=match_string_data.get('versionEndIncluding'),
                version_start_excluding=match_string_data.get('versionStartExcluding'),
                version_end_excluding=match_string_data.get('versionEndExcluding')
            )
        )

        # Only add to cpe_names if matches are present
        if 'matches' in match_string_data:
            for match in match_string_data['matches']:
                cpe_name = match.get('cpeName')
                cpe_name_id = match.get('cpeNameId')

                if not cpe_name or not cpe_name_id:
                    logging.warning("Skipping CPEName entry due to missing 'cpeName' or 'cpeNameId'.")
                    continue

                cpe_names.append({
                    'cpe_name': cpe_name,
                    'cpe_name_id': cpe_name_id,
                    'match_criteria_id': match_criteria_id
                })

    # Save MatchStrings
    match_string_map = await save_match_strings(match_strings)

    # Fetch MatchStrings from database to ensure they are committed
    match_criteria_ids = [m['match_criteria_id'] for m in cpe_names]
    match_string_objs = await sync_to_async(lambda: list(MatchString.objects.filter(match_criteria_id__in=match_criteria_ids)))() 
    match_string_map = {obj.match_criteria_id: obj for obj in match_string_objs}

    # Create CPENames
    await create_cpe_names(cpe_names, match_string_map)

    return len(match_strings)

async def fetch_cpe_data_and_save():
    """Fetch all CPE data and save it to the database."""
    start_index = 0
    results_per_page = 500
    total_results = 534307  # Update this as per the total results count
    while start_index < total_results:
        logging.info(f"Fetching data from index {start_index}")
        data = await fetch_page(start_index, results_per_page)
        if data:
            stored_count = await save_cpe_data(data, {
                'resultsPerPage': results_per_page,
                'startIndex': start_index,
                'totalResults': total_results,
                'format': data.get('format', ''),
                'version': data.get('version', ''),
                'timestamp': data.get('timestamp', '')
            })
            logging.info(f"Fetched and stored {stored_count} CPEs from index {start_index}")
        else:
            logging.error(f"Failed to fetch data from index {start_index}")
        start_index += results_per_page

if __name__ == "__main__":
    asyncio.run(fetch_cpe_data_and_save())
import os
import django
from django.utils import timezone
from uuid import UUID
from django.core.exceptions import ObjectDoesNotExist

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Server.settings')

# Initialize Django
django.setup()
from serverapp.models import MatchString,CPEMatch, CVEConfiguration, CVE, CPEMatchInNode

def get_match_strings(package_name, version):
    """
    Fetch MatchString objects based on package name and version.
    
    :param package_name: The name of the package to search for.
    :param version: The version of the package to match against.
    :return: A list of MatchString objects that match the criteria.
    """
    # Fetch all MatchString objects
    match_strings = MatchString.objects.all()

    # Fetch MatchString objects where the package name is in the criteria
    match_strings = MatchString.objects.filter(criteria__icontains=f':{package_name}:')

    def get_criteria_version_field(criteria):
        """
        Extracts the version field from the criteria.
        
        :param criteria: The criteria string.
        :return: The version field or None if it is a wildcard.
        """
        segments = criteria.split(':')
        # The version is expected to be the sixth segment (index 5)
        if len(segments) > 6:
            return segments[5]
        return None

    # Function to check if a version falls within the specified range
    def is_version_in_range(version, start_incl, end_incl, start_excl, end_excl):
        """
        Check if the given version is within the specified range.
        
        :param version: The version to check.
        :param start_incl: Start of inclusive range.
        :param end_incl: End of inclusive range.
        :param start_excl: Start of exclusive range.
        :param end_excl: End of exclusive range.
        :return: True if the version is within the range, False otherwise.
        """
        if start_excl and version <= start_excl:
            return False
        if end_excl and version >= end_excl:
            return False
        if start_incl and version < start_incl:
            return False
        if end_incl and version > end_incl:
            return False
        return True

    exact_match = []

    for match in match_strings:
        criteria_version_field = get_criteria_version_field(match.criteria)

        if criteria_version_field == version:
            # Exact match found
            exact_match.append(str(match.match_criteria_id).upper())
            # return exact_match
        elif criteria_version_field == '*':
            # Check version ranges if criteria version field is a wildcard
            start_incl = match.version_start_including
            end_incl = match.version_end_including
            start_excl = match.version_start_excluding
            end_excl = match.version_end_excluding
            
            if is_version_in_range(version, start_incl, end_incl, start_excl, end_excl):
                exact_match.append(str(match.match_criteria_id).upper())

    return exact_match

# def get_cve_ids_from_match_criteria_ids(match_criteria_ids):
#     """
#     Fetch CVE IDs based on match_criteria_ids.
    
#     :param match_criteria_ids: List of match_criteria_id to search for.
#     :return: A list of CVE IDs that match the criteria.
#     """
#     cve_ids = set()  # Use a set to avoid duplicate CVE IDs

#     for match_criteria_id in match_criteria_ids:
#         # Fetch CPEMatch objects with the given match_criteria_id
#         cpe_matches = CPEMatch.objects.filter(match_criteria_id=match_criteria_id)

#         for cpe_match in cpe_matches:
#             # Find CVEConfigurations associated with the CPEMatch
#             configurations = CVEConfiguration.objects.filter(cpe_matches=cpe_match)

#             for configuration in configurations:
#                 # Find CVEs associated with the CVEConfiguration
#                 cves = CVE.objects.filter(configurations=configuration)

#                 for cve in cves:
#                     cve_ids.add(cve.id)

#     return list(cve_ids)

def find_cve_id_by_match_criteria_id(match_criteria_id):
    """
    Finds CVE IDs associated with the given match_criteria_id.
    
    Args:
        match_criteria_id (str): The match_criteria_id value to search for.
        
    Returns:
        Optional[list[str]]: List of CVE IDs associated with the match_criteria_id,
                             or None if no matching CVE IDs are found.
    """
    cve_ids = set()  # Set to hold unique CVE IDs
    cve_status = {}  # Dictionary to hold CVE IDs and their associated vulnerability status

    try:
        # Convert the match_criteria_id to UUID
        match_criteria_uuid = UUID(match_criteria_id)
        
        # Check in CPEMatch
        cpe_matches = CPEMatch.objects.select_related('configuration__cve').filter(match_criteria_id=match_criteria_uuid)
        for cpe_match in cpe_matches:
            cve_id = cpe_match.configuration.cve.id
            cve_ids.add(cve_id)
            cve_status[cve_id] = cpe_match.vulnerable
        
        # Check in CPEMatchInNode
        cpe_match_in_nodes = CPEMatchInNode.objects.select_related('node__configuration__cve').filter(match_criteria_id=match_criteria_uuid)
        for cpe_match_in_node in cpe_match_in_nodes:
            cve_id = cpe_match_in_node.node.configuration.cve.id
            cve_ids.add(cve_id)
            cve_status[cve_id] = cpe_match_in_node.vulnerable
        
        # Prepare the final result
        result = {cve_id: cve_status[cve_id] for cve_id in cve_ids}
        return result if result else None

    except ValueError:
        # Handle the case where the match_criteria_id is not a valid UUID
        print("Invalid match_criteria_id format")
        return None
 



# Example usage
package_name = 'openssl'
version = '1.1.1s'
matches = get_match_strings(package_name, version)
for match in matches:
    print(match)

# cve_ids=get_cve_ids_from_match_criteria_ids(matches)
print("CVE IDs and Vulnerability Status:")
for match in matches:
    cve_data = find_cve_id_by_match_criteria_id(match)
    if cve_data is not None:
        for cve_id, vulnerable in cve_data.items():
            print(f"CVE ID: {cve_id}, Vulnerable: {vulnerable}")
    else:
        print(f"No CVE IDs found for the given match_criteria_id: {match}")
   
