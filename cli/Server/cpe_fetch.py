"""
====================
cpe_fetch.py
Fetch CPEMatch response and store it into local database
author: Chandramani Kumar, Shubham
===================
"""
import os
import django
import logging
import argparse
import requests  # Using requests instead of aiohttp for simplicity
import time
from datetime import datetime
from django.utils import timezone
import logging.config
import json
import settings
from uuid import uuid4
from dateutil.parser import parse as dateutil_parse

# Set up logging
LOG_DIR_PATH = settings.LOG_DIR_PATH
LOG_FILE_NAME = 'cpematchstring.log'
LOG_FILE_PATH = os.path.join(LOG_DIR_PATH, LOG_FILE_NAME)
LOG_LEVEL = settings.LOG_LEVEL

# Ensure the log directory exists
if not os.path.exists(LOG_DIR_PATH):
    os.makedirs(LOG_DIR_PATH)

# Define the logging configuration
logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(levelname)s - %(message)s',
        },
    },
    'handlers': {
        'file': {
            'level': LOG_LEVEL,
            'class': 'logging.FileHandler',
            'filename': LOG_FILE_PATH,
            'formatter': 'standard',
        },
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': LOG_LEVEL,
            'propagate': True,
        },
    },
}

# Apply the logging configuration
logging.config.dictConfig(logging_config)

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

# Initialize Django
django.setup()

# Now import your Django models
from serverapp.models import MatchString

def parse_datetime(dt_str):
    if dt_str is None:
        return None
    try:
        if dt_str.endswith('Z'):
            return timezone.make_aware(datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%fZ"))
        else:
            return timezone.make_aware(datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%f"))
    except ValueError as e:
        logging.error(f"Error parsing datetime: {e}")
        return None
    

def check_if_data_exists():
    try:
        # Check if any data exists in the MatchString model
        cve_exists = MatchString.objects.exists()
        if cve_exists:
            logging.info("Data already exists in the database. Exiting.")
            return True
        return False
    except Exception as e:
        logging.error(f"Error checking data existence: {e}")
        return False    

def fetch_page(start_index, results_per_page):
    base_url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }

    retries = 10
    timeout = 120  # seconds

    for attempt in range(retries):
        try:
            response = requests.get(base_url, params=params, timeout=timeout)
            if response.status_code == 403:
                logging.warning(f"Rate limit reached, sleeping for 60 seconds")
                time.sleep(60)
                continue
            elif response.status_code == 404:
                logging.error(f"Error fetching data from NVD API: 404 Not Found, URL: {response.url}")
                return None
            response.raise_for_status()

            try:
                return response.json()  # Parse JSON response
            except json.JSONDecodeError as e:
                logging.error(f"JSON decoding error: {e}. Response content might be malformed.")
                logging.debug(f"Response content: {response.text}")
                time.sleep(5)  # Short delay before retrying
                continue

        except requests.Timeout:
            logging.error(f"Timeout error fetching data from NVD API, attempt {attempt + 1}")
            time.sleep(2 ** attempt)  # Exponential backoff
        except requests.RequestException as e:
            logging.error(f"Error fetching data from NVD API: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff
    logging.error("Max retries reached. Unable to fetch data.")
    return None

def save_vulnerabilities(vulnerabilities, total_stored_count):
    stored_count = 0

    for vulnerability in vulnerabilities:
        match_string_data = vulnerability.get('matchString')
        if not match_string_data:
            continue

        match_criteria_id = match_string_data.get('matchCriteriaId')
        criteria = match_string_data.get('criteria')
        last_modified = parse_datetime(match_string_data.get('lastModified'))
        cpe_last_modified = parse_datetime(match_string_data.get('cpeLastModified'))
        created = parse_datetime(match_string_data.get('created'))
        status = match_string_data.get('status')

        version_start_including = match_string_data.get('versionStartIncluding')
        version_end_including = match_string_data.get('versionEndIncluding')
        version_start_excluding = match_string_data.get('versionStartExcluding')
        version_end_excluding = match_string_data.get('versionEndExcluding')

        matches = match_string_data.get('matches', [])

        # Save each match string to the database individually
        match_string = MatchString(
            match_criteria_id=match_criteria_id,
            criteria=criteria,
            last_modified=last_modified,
            cpe_last_modified=cpe_last_modified,
            created=created,
            status=status,
            version_start_including=version_start_including,
            version_end_including=version_end_including,
            version_start_excluding=version_start_excluding,
            version_end_excluding=version_end_excluding,
            matches=matches
        )
        match_string.save()
        stored_count += 1

    total_stored_count += stored_count
    logging.info(f"Stored {stored_count} match strings in this batch. Total stored so far: {total_stored_count}")

    return total_stored_count

def main(start_index=None):
    # If no start index is provided, check if data exists in the database
    if start_index is None:
        if check_if_data_exists():
            return  # Exit the script if data exists

    results_per_page = 500
    total_stored_count = 0

    # If a start index was provided via argparse, use that; otherwise, start from 0
    start_index = start_index or 0

    # Fetch the initial data
    initial_data = fetch_page(start_index, results_per_page)
    if not initial_data or 'totalResults' not in initial_data:
        logging.error("Failed to fetch the initial data or totalResults not found.")
        return

    total_results = initial_data['totalResults']
    logging.info(f"Total results to be fetched: {total_results}")

    # Process the initial data
    total_stored_count = save_vulnerabilities(initial_data['matchStrings'], total_stored_count)
    start_index += results_per_page

    # Fetch and process the remaining data
    while start_index < total_results:
        data = fetch_page(start_index, results_per_page)
        if not data or 'matchStrings' not in data:
            logging.error("Failed to fetch data or 'matchStrings' not found.")
            time.sleep(60)  # Sleep before retrying
            continue

        total_stored_count = save_vulnerabilities(data['matchStrings'], total_stored_count)
        start_index += results_per_page
        logging.info(f"Fetched {start_index}/{total_results} records so far.")

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Fetch CPEMatch response and store it into a local database.')
        parser.add_argument('--start-index', type=int, help='Specify the start index for data fetching.')
        args = parser.parse_args()

        # Pass None to main if start-index is not provided
        main(start_index=args.start_index if args.start_index is not None else None)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
