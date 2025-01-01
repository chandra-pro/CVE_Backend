"""
====================
sync_cpe_fetch.py
Syncs CPE Match Strings local database data with updated NVD data.
author: Shubham
===================
 
"""

import os
import django
import requests
from datetime import datetime, timedelta
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware
import time
import argparse
import logging
import logging.config
import settings

# Set up Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
django.setup()

from serverapp.models import MatchString, MatchStringSyncLog  # Import models after Django setup

# Set up logging
LOG_DIR_PATH = settings.LOG_DIR_PATH
LOG_FILE_NAME = 'sync_cpe_fetch_log.log'
LOG_FILE_PATH = os.path.join(LOG_DIR_PATH, LOG_FILE_NAME)
LOG_LEVEL = settings.LOG_LEVEL  # Adjust this as needed

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
logger = logging.getLogger(__name__)

# Sync function
def sync_cpematch(start_date_str=None, end_date_str=None):
    # Determine sync start and end dates
    if start_date_str and end_date_str:
        try:
            start_date = make_aware(parse_datetime(start_date_str))
            end_date = make_aware(parse_datetime(end_date_str))
        except ValueError as e:
            logger.error(f"Error parsing dates: {e}")
            return
    else:
        try:
            last_sync_log = MatchStringSyncLog.objects.latest('last_sync')
            start_date = last_sync_log.last_sync
        except MatchStringSyncLog.DoesNotExist:
            start_date = make_aware(datetime.now() - timedelta(days=5))
        end_date = make_aware(datetime.now())

    logger.info(f"Starting sync from {start_date.isoformat()} to {end_date.isoformat()}")

    base_url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
    
    params = {
        'resultsPerPage': 500,
        'lastModStartDate': start_date.isoformat(),
        'lastModEndDate': end_date.isoformat(),
    }

    match_count = 0
    start_index = 0
    retry_attempts = 10
    delay_between_retries = 10  # seconds
    rate_limit_delay = 1  # Delay between requests to handle rate limits
    backoff_factor = 2  # Factor for exponential backoff
    total_results = 0

    try:
        while True:
            params['startIndex'] = start_index
            for attempt in range(retry_attempts):
                response = None  # Initialize response variable
                try:
                    response = requests.get(base_url, params=params, timeout=30)  # Add a timeout to the request
                    response.raise_for_status()

                    # Check if the response is incomplete
                    content_length = response.headers.get('Content-Length')
                    if content_length and len(response.content) != int(content_length):
                        logger.error("Incomplete response received")
                        continue  # Retry if the response is incomplete

                    try:
                        data = response.json()  # Attempt to parse JSON
                    except requests.exceptions.JSONDecodeError as e:
                        logger.error(f"JSON decoding failed: {e}")
                        logger.error(f"Received response: {response.text[:1000]}...")  # Log the start of the response
                        continue  # Retry on JSON decoding failure

                    match_strings = data.get('matchStrings', [])
                    total_results = data.get('totalResults', 0)

                    if not match_strings:
                        break

                    for item in match_strings:
                        match_criteria = item['matchString']
                        match_criteria_id = match_criteria['matchCriteriaId']
                        criteria = match_criteria.get('criteria', '')
                        last_modified = match_criteria.get('lastModified')
                        cpe_last_modified = match_criteria.get('cpeLastModified')
                        created = match_criteria.get('created')
                        status = match_criteria.get('status', 'Inactive')

                        # Optional fields
                        version_start_including = match_criteria.get('versionStartIncluding', '')
                        version_end_including = match_criteria.get('versionEndIncluding', '')
                        version_start_excluding = match_criteria.get('versionStartExcluding', '')
                        version_end_excluding = match_criteria.get('versionEndExcluding', '')

                        matches = match_criteria.get('matches', [])

                        # Convert dates from string to datetime
                        last_modified_date = last_modified and make_aware(parse_datetime(last_modified))
                        cpe_last_modified_date = cpe_last_modified and make_aware(parse_datetime(cpe_last_modified))
                        created_date = created and make_aware(parse_datetime(created))

                        # Update or create the CPE Match Criteria entry
                        MatchString.objects.update_or_create(
                            match_criteria_id=match_criteria_id,
                            defaults={
                                'criteria': criteria,
                                'last_modified': last_modified_date,
                                'cpe_last_modified': cpe_last_modified_date,
                                'created': created_date,
                                'status': status,
                                'version_start_including': version_start_including,
                                'version_end_including': version_end_including,
                                'version_start_excluding': version_start_excluding,
                                'version_end_excluding': version_end_excluding,
                                'matches': matches,
                            }
                        )
                        match_count += 1

                    if start_index + 500 > total_results:
                        start_index = total_results
                    else:
                        start_index += 500

                    # Log the progress correctly
                    fetched_count = min(start_index, total_results)
                    logger.info(f"Syncing {fetched_count} of {total_results}...")

                    if start_index >= total_results:
                        break

                    # Sleep to handle rate limits
                    time.sleep(rate_limit_delay)

                except requests.RequestException as e:
                    logger.error(f"HTTP Error on attempt {attempt + 1} of {retry_attempts}: {e}")
                    if response is not None and response.status_code in [403, 503, 504]:  # Service Unavailable
                        logger.warning("Service unavailable or forbidden, backing off and retrying...")
                        time.sleep(delay_between_retries * (backoff_factor ** attempt))  # Exponential backoff
                    elif attempt < retry_attempts - 1:
                        time.sleep(delay_between_retries * (2 ** attempt))  # Exponential backoff
                    else:
                        logger.error(f"HTTP Error: {e}")
                                                
                else:
                    break

            if start_index >= total_results:
                break

        # Only create the sync log entry if we successfully completed the entire sync
        MatchStringSyncLog.objects.create(
            last_sync=end_date,
            status='Success',
            message=f"Successfully synced {match_count} CPE Match Criteria records."
        )
        logger.info(f"Successfully synced {match_count} CPE Match Criteria records.")

    except Exception as e:
        logger.error(f"Sync failed: {str(e)}")
        raise

# Main function to run the script
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Syncs CPE Match Criteria data from NVD API')
    parser.add_argument('--start-date', type=str, help='Start date for the sync period in ISO-8601 format.')
    parser.add_argument('--end-date', type=str, help='End date for the sync period in ISO-8601 format.')

    args = parser.parse_args()

    sync_cpematch(start_date_str=args.start_date, end_date_str=args.end_date)
