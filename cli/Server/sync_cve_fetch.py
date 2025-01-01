"""
====================
sync_cve_data.py
Syncs CVE local database data with updated NVD data.
author: Shubham
===================
"""

import os
import django
import requests
import time
from datetime import datetime, timedelta
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware, now
from django.db import transaction
from requests.exceptions import HTTPError
import logging
import logging.config
import settings

# Set up Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
django.setup()

from serverapp.models import CVE, CVETag, CVEDescription, CVSSMetricV2, CVSSMetricV31, CVEWeakness, CVEConfiguration, CPEMatch, CVEReference, CVENode, CPEMatchInNode, CVESyncLog

# Set up logging
LOG_DIR_PATH = settings.LOG_DIR_PATH
LOG_FILE_NAME = 'sync_cve_fetch_log.log'
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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"
RATE_LIMIT_SLEEP_TIME = 6  # seconds between requests to comply with rate limits

def sync_cve_data():
    # Get the last sync time
    try:
        last_sync_log = CVESyncLog.objects.latest('last_sync')
        last_mod_start_date = last_sync_log.last_sync
    except CVESyncLog.DoesNotExist:
        last_mod_start_date = now() - timedelta(days=5)

    last_mod_end_date = now()

    # Log the sync start time range
    logger.info(f"Starting sync from {last_mod_start_date} to {last_mod_end_date}")

    # Prepare API parameters
    params = {
        'resultsPerPage': 2000,  # Adjusted for better granularity
        'startIndex': 0,
        'lastModStartDate': last_mod_start_date.isoformat(),
        'lastModEndDate': last_mod_end_date.isoformat(),
    }

    total_results = 1  # Initialize to enter the loop
    fetched_results = 0
    retry_attempts = 10
    delay_between_retries = 10  # seconds
    backoff_factor = 2  # Factor for exponential backoff
    sync_successful = False

    try:
        with transaction.atomic():
            while params['startIndex'] < total_results:
                current_attempt = 0
                
                while current_attempt < retry_attempts:
                    try:
                        response = requests.get(NVD_API_URL, params=params)
                        response.raise_for_status()
                        data = response.json()

                        total_results = data.get('totalResults', 0)
                        fetched_count = len(data['vulnerabilities'])
                        fetched_results += fetched_count
                        logger.info(f"Syncing {params['startIndex'] + fetched_count} of {total_results}...")

                        for item in data['vulnerabilities']:
                            cve_data = item['cve']
                            process_cve(cve_data)

                        params['startIndex'] += fetched_count
                        time.sleep(RATE_LIMIT_SLEEP_TIME)

                        if params['startIndex'] >= total_results:
                             sync_successful = True
                        break  # Successful fetch, exit retry loop

                    except requests.RequestException as e:
                        current_attempt += 1
                        logger.error(f"HTTP Error on attempt {current_attempt} of {retry_attempts}: {e}")
                        
                        if current_attempt < retry_attempts:
                            if response is not None and response.status_code in [403, 503, 504]:
                                logger.warning("Service unavailable or forbidden, backing off and retrying...")
                                time.sleep(delay_between_retries * (backoff_factor ** current_attempt))
                            else:
                                time.sleep(delay_between_retries * (2 ** current_attempt))
                        else:
                            logger.error(f"HTTP Error : {e}")
                            
                
                else:
                    break

            # Log success in CVESyncLog (only if loop completes successfully)
            if sync_successful:
                CVESyncLog.objects.create(
                last_sync=last_mod_end_date,
                status="success",
                message=f"Synced {fetched_results} CVEs from {last_mod_start_date} to {last_mod_end_date}"
            )           

        logger.info(f"Sync completed successfully. Synced {fetched_results} CVEs from {last_mod_start_date} to {last_mod_end_date}")

    except Exception as err:
        logger.error(f"An error occurred during the sync: {err}")
        raise

def process_cve(cve_data):
    cve_id = cve_data['id']
    cve, created = CVE.objects.update_or_create(
        id=cve_id,
        defaults={
            'source_identifier': cve_data['sourceIdentifier'],
            'published': make_aware(parse_datetime(cve_data['published'])),
            'last_modified': make_aware(parse_datetime(cve_data['lastModified'])),
            'vuln_status': cve_data['vulnStatus'],
        }
    )

    update_tags(cve, cve_data.get('cveTags', []))
    update_descriptions(cve, cve_data.get('descriptions', []))
    update_metrics(cve, cve_data.get('metrics', {}))
    update_weaknesses(cve, cve_data.get('weaknesses', []))
    update_configurations(cve, cve_data.get('configurations', []))
    update_references(cve, cve_data.get('references', []))

def update_tags(cve, tags):
    CVETag.objects.filter(cve=cve).delete()
    for tag in tags:
        for t in tag.get('tags', []):
            CVETag.objects.create(cve=cve, source=tag['sourceIdentifier'], tag=t)

def update_descriptions(cve, descriptions):
    CVEDescription.objects.filter(cve=cve).delete()
    for desc in descriptions:
        CVEDescription.objects.create(cve=cve, lang=desc['lang'], value=desc['value'])

def update_metrics(cve, metrics):
    CVSSMetricV2.objects.filter(cve=cve).delete()
    for metric in metrics.get('cvssMetricV2', []):
        CVSSMetricV2.objects.create(
            cve=cve,
            source=metric.get('source', ''),
            type=metric.get('type', ''),
            version=metric.get('cvssData', {}).get('version', ''),
            vector_string=metric.get('cvssData', {}).get('vectorString', ''),
            access_vector=metric.get('cvssData', {}).get('accessVector', ''),
            access_complexity=metric.get('cvssData', {}).get('accessComplexity', ''),
            authentication=metric.get('cvssData', {}).get('authentication', ''),
            confidentiality_impact=metric.get('cvssData', {}).get('confidentialityImpact', ''),
            integrity_impact=metric.get('cvssData', {}).get('integrityImpact', ''),
            availability_impact=metric.get('cvssData', {}).get('availabilityImpact', ''),
            base_score=metric.get('cvssData', {}).get('baseScore', 0),
            base_severity=metric.get('baseSeverity', ''),
            exploitability_score=metric.get('exploitabilityScore', 0),
            impact_score=metric.get('impactScore', 0),
            ac_insuf_info=metric.get('acInsufInfo', False),
            obtain_all_privilege=metric.get('obtainAllPrivilege', False),
            obtain_user_privilege=metric.get('obtainUserPrivilege', False),
            obtain_other_privilege=metric.get('obtainOtherPrivilege', False),
            user_interaction_required=metric.get('userInteractionRequired', False)
        )

    # Update CVSS v3.1 metrics
    CVSSMetricV31.objects.filter(cve=cve).delete()
    for metric in metrics.get('cvssMetricV31', []):
        CVSSMetricV31.objects.create(
            cve=cve,
            source=metric.get('source', ''),
            type=metric.get('type', ''),
            version=metric.get('cvssData', {}).get('version', ''),
            vector_string=metric.get('cvssData', {}).get('vectorString', ''),
            attack_vector=metric.get('cvssData', {}).get('attackVector', ''),
            attack_complexity=metric.get('cvssData', {}).get('attackComplexity', ''),
            privileges_required=metric.get('cvssData', {}).get('privilegesRequired', ''),
            user_interaction=metric.get('cvssData', {}).get('userInteraction', ''),
            scope=metric.get('cvssData', {}).get('scope', ''),
            confidentiality_impact=metric.get('cvssData', {}).get('confidentialityImpact', ''),
            integrity_impact=metric.get('cvssData', {}).get('integrityImpact', ''),
            availability_impact=metric.get('cvssData', {}).get('availabilityImpact', ''),
            base_score=metric.get('cvssData', {}).get('baseScore', 0),
            base_severity=metric.get('baseSeverity', ''),
            exploitability_score=metric.get('exploitabilityScore', 0),
            impact_score=metric.get('impactScore', 0)
        )    

def update_weaknesses(cve, weaknesses):
    CVEWeakness.objects.filter(cve=cve).delete()
    for weakness in weaknesses:
        CVEWeakness.objects.create(
            cve=cve,
            source=weakness.get('source', ''),
            type=weakness.get('type', ''),
            description=weakness.get('description', [{}])[0].get('value', '')
        )

def update_configurations(cve, configurations):
    CVEConfiguration.objects.filter(cve=cve).delete()
    for config in configurations:
        configuration = CVEConfiguration.objects.create(
            cve=cve,
            operator=config.get('operator', ''),
            negate=config.get('negate', False)
        )
        for node in config.get('nodes', []):
            cve_node = CVENode.objects.create(
                configuration=configuration,
                operator=node.get('operator', ''),
                negate=node.get('negate', False)
            )
            for match in node.get('cpeMatch', []):
                CPEMatchInNode.objects.create(
                    node=cve_node,
                    vulnerable=match.get('vulnerable', False),
                    criteria=match.get('criteria', ''),
                    version_start_including=match.get('versionStartIncluding', ''),
                    version_end_including=match.get('versionEndIncluding', ''),
                    version_start_excluding=match.get('versionStartExcluding', ''),
                    version_end_excluding=match.get('versionEndExcluding', ''),
                    match_criteria_id=match.get('matchCriteriaId', '')
                )

def update_references(cve, references):
    CVEReference.objects.filter(cve=cve).delete()
    for ref in references:
        CVEReference.objects.create(
            cve=cve,
            url=ref.get('url', ''),
            source=ref.get('source', ''),
            tags=ref.get('tags', [])
        )

if __name__ == "__main__":
    sync_cve_data()