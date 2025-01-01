"""
====================
cve_fetch.py
Fetch CVE response and store it into local database
author: Chandramani Kumar, Shubham
===================
"""

import os
import django
import logging
import logging.config
import time
from datetime import datetime
from django.db import transaction
from django.utils import timezone
import aiohttp
import asyncio
from uuid import uuid4
from asgiref.sync import sync_to_async
import settings
import argparse
import json

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')

# Initialize Django
django.setup()

# Set up logging
LOG_DIR_PATH = settings.LOG_DIR_PATH
LOG_FILE_NAME = settings.LOG_FILE_NAME
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

# Now import your Django models
from serverapp.models import CVE, CVEDescription, CVSSMetricV2,CVSSMetricV31, CVEWeakness, CVEConfiguration, CVENode, CPEMatchInNode, CVEReference

def parse_datetime(dt_str):
    try:
        if dt_str.endswith('Z'):
            return timezone.make_aware(datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%fZ"))
        else:
            return timezone.make_aware(datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%f"))
    except ValueError as e:
        logging.error(f"Error parsing datetime: {e}")
        return None
    

async def check_if_data_exists():
    try:
        cve_exists = await sync_to_async(CVE.objects.exists)()
        if cve_exists:
            logging.info("Data already exists in the database. Exiting.")
            return True
        return False
    except Exception as e:
        logging.error(f"Error checking data existence: {e}")
        return False


async def fetch_initial_page(session, start_index, results_per_page):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    
    try:
        async with session.get(base_url, params=params) as response:
            response.raise_for_status()  # Raise an exception for bad response status
            return await response.json()
    except aiohttp.ClientError as e:
        logging.error(f"Error fetching data from NVD API: {e}")
        return None
    


async def fetch_page(session, start_index, results_per_page, retry_attempts=10, retry_delay=10):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    
    attempt = 0
    while attempt < retry_attempts:
        try:
            async with session.get(base_url, params=params) as response:
                if response.status == 403:
                    
                    await asyncio.sleep(60)  # Wait for a minute before retrying
                    continue  # Retry after the sleep
                
                elif response.status == 404:
                    logging.error(f"Error fetching data from NVD API: 404 Not Found, URL: {response.url}")
                    return None
                
                response.raise_for_status()  # Raise an exception for bad response status
                return await response.json()

        except aiohttp.ClientError as e:
            attempt += 1
            logging.error(f"Error fetching data from NVD API at startIndex {start_index}: {e}. Retrying ({attempt}/{retry_attempts}) in {retry_delay} seconds.")
            await asyncio.sleep(retry_delay * attempt)  # Exponential backoff
        except asyncio.TimeoutError:
            logging.error(f"Request timed out. Retrying ({attempt + 1}/{retry_attempts})...")
        
        attempt += 1
        await asyncio.sleep(retry_delay * attempt)  # Exponential backoff    
        
    logging.error(f"Failed to fetch data from NVD API after {retry_attempts} attempts at startIndex {start_index}.")
    return None


async def save_vulnerabilities(vulnerabilities):
    stored_count = 0
    cve_objs = []
    descriptions = []
    cvssmetricsV2 = []
    cvssmetricsV31=[]
    weaknesses = []
    configurations = []
    nodes = []
    cpe_matches = []
    references = []

    for vulnerability in vulnerabilities:
        cve_id = vulnerability['cve']['id']
        source_identifier = vulnerability['cve']['sourceIdentifier']
        published = parse_datetime(vulnerability['cve']['published'])
        last_modified = parse_datetime(vulnerability['cve']['lastModified'])

        if not published or not last_modified:
            logging.warning(f"Skipping CVE {cve_id} due to date parsing issues.")
            continue

        vuln_status = vulnerability['cve']['vulnStatus']
        cve_obj = CVE(
            id=cve_id,
            source_identifier=source_identifier,
            published=published,
            last_modified=last_modified,
            vuln_status=vuln_status,
        )
        cve_objs.append(cve_obj)
        stored_count += 1

        descriptions_data = vulnerability['cve'].get('descriptions', [])
        for desc_data in descriptions_data:
            lang = desc_data['lang']
            value = desc_data['value']
            descriptions.append(CVEDescription(cve=cve_obj, lang=lang, value=value))

        metrics_dataV2 = vulnerability['cve'].get('metrics', {}).get('cvssMetricV2', [])
        for metric_data in metrics_dataV2:
            base_score = metric_data.get('cvssData', {}).get('baseScore', None)
            severity = metric_data.get('baseSeverity', None)
            exploitability_score = metric_data.get('exploitabilityScore', None)
            impact_score = metric_data.get('impactScore', None)
            cvssmetricsV2.append(
                CVSSMetricV2(
                    cve=cve_obj,
                    source=metric_data.get('source', ''),
                    type=metric_data.get('type', ''),
                    version=metric_data.get('cvssData', {}).get('version', ''),
                    vector_string=metric_data.get('cvssData', {}).get('vectorString', ''),
                    access_vector=metric_data.get('cvssData', {}).get('accessVector', ''),
                    access_complexity=metric_data.get('cvssData', {}).get('accessComplexity', ''),
                    authentication=metric_data.get('cvssData', {}).get('authentication', ''),
                    confidentiality_impact=metric_data.get('cvssData', {}).get('confidentialityImpact', ''),
                    integrity_impact=metric_data.get('cvssData', {}).get('integrityImpact', ''),
                    availability_impact=metric_data.get('cvssData', {}).get('availabilityImpact', ''),
                    base_score=base_score,
                    base_severity=severity,
                    exploitability_score=exploitability_score,
                    impact_score=impact_score,
                    ac_insuf_info=metric_data.get('acInsufInfo', False),
                    obtain_all_privilege=metric_data.get('obtainAllPrivilege', False),
                    obtain_user_privilege=metric_data.get('obtainUserPrivilege', False),
                    obtain_other_privilege=metric_data.get('obtainOtherPrivilege', False),
                    user_interaction_required=metric_data.get('userInteractionRequired', False),
                )
            )

        
        metrics_dataV31 = vulnerability['cve'].get('metrics', {}).get('cvssMetricV31', [])
        for metric_dat in metrics_dataV31:
                base_score = metric_dat.get('cvssData', {}).get('baseScore', None)
                version = metric_dat.get('cvssData', {}).get('version', None)
                vector_string = metric_dat.get('cvssData', {}).get('vectorString', None)
                
                severity = metric_dat.get('cvssData', {}).get('baseSeverity', None)
                exploitability_score = metric_dat.get('exploitabilityScore', None)
                impact_score = metric_dat.get('impactScore', None)

                cvssmetricsV31.append(
                    CVSSMetricV31(
                        cve=cve_obj,
                        source=metric_dat.get('source', ''),
                        type=metric_dat.get('type', ''),
                        version=version,
                        vector_string=vector_string,

                        attack_vector=metric_dat.get('cvssData', {}).get('attackVector', ''),
                        attack_complexity=metric_dat.get('cvssData', {}).get('attackComplexity', ''),
                        privileges_required=metric_dat.get('cvssData', {}).get('privilegesRequired', ''),
                        user_interaction=metric_dat.get('cvssData', {}).get('userInteraction', ''),
                        scope=metric_dat.get('cvssData', {}).get('scope', ''),


                        access_vector=metric_dat.get('cvssData', {}).get('attackVector', ''),
                        access_complexity=metric_dat.get('cvssData', {}).get('attackComplexity', ''),
                        authentication=metric_dat.get('cvssData', {}).get('privilegesRequired', ''),
                        confidentiality_impact=metric_dat.get('cvssData', {}).get('confidentialityImpact', ''),
                        integrity_impact=metric_dat.get('cvssData', {}).get('integrityImpact', ''),
                        availability_impact=metric_dat.get('cvssData', {}).get('availabilityImpact', ''),
                        base_score=base_score,
                        base_severity=severity,
                        exploitability_score=exploitability_score,
                        impact_score=impact_score,

                    )
                )

        weaknesses_data = vulnerability['cve'].get('weaknesses', [])
        for weakness_data in weaknesses_data:
            source = weakness_data['source']
            type = weakness_data['type']
            description = weakness_data.get('description', "")
            weaknesses.append(CVEWeakness(cve=cve_obj, source=source, type=type, description=description))

        configurations_data = vulnerability['cve'].get('configurations', [])
        for config_data in configurations_data:
            config_obj = CVEConfiguration(cve=cve_obj, operator=config_data.get('operator', ''), negate=config_data.get('negate', False))
            configurations.append(config_obj)

    await sync_to_async(CVE.objects.bulk_create)(cve_objs)
    await sync_to_async(CVEConfiguration.objects.bulk_create)(configurations)

    saved_configurations = {
        (config.cve_id, config.operator): config
        for config in await sync_to_async(lambda: list(CVEConfiguration.objects.filter(
            cve__in=[cve_obj.id for cve_obj in cve_objs]
        ).all()))()
    }

    for vulnerability in vulnerabilities:
        cve_id = vulnerability['cve']['id']
        configurations_data = vulnerability['cve'].get('configurations', [])
        for config_data in configurations_data:
            config_obj = saved_configurations.get((cve_id, config_data.get('operator', '')))
            nodes_data = config_data.get('nodes', [])
            for node_data in nodes_data:
                operator = node_data.get('operator', '')
                negate = node_data.get('negate', False)
                node_obj = CVENode(configuration=config_obj, operator=operator, negate=negate)
                nodes.append(node_obj)

    # Save nodes before creating CPEMatchInNode objects
    await sync_to_async(CVENode.objects.bulk_create)(nodes)

    # Retrieve saved nodes with their IDs for creating CPEMatchInNode
    saved_nodes = {
        (node.configuration_id, node.operator, node.negate): node
        for node in await sync_to_async(lambda: list(CVENode.objects.filter(
            configuration__cve__in=[cve_obj.id for cve_obj in cve_objs]
        ).all()))()
    }

    for vulnerability in vulnerabilities:
        cve_id = vulnerability['cve']['id']
        configurations_data = vulnerability['cve'].get('configurations', [])
        for config_data in configurations_data:
            config_obj = saved_configurations.get((cve_id, config_data.get('operator', '')))
            nodes_data = config_data.get('nodes', [])
            for node_data in nodes_data:
                node_obj = saved_nodes.get((config_obj.id, node_data.get('operator', ''), node_data.get('negate', False)))
                cpe_matches_data = node_data.get('cpeMatch', [])
                for cpe_match_data in cpe_matches_data:
                    vulnerable = cpe_match_data.get('vulnerable', False)
                    criteria = cpe_match_data.get('criteria', '')
                    match_criteria_id = cpe_match_data.get('matchCriteriaId', uuid4())
                    cpe_matches.append(CPEMatchInNode(node=node_obj, vulnerable=vulnerable, criteria=criteria, match_criteria_id=match_criteria_id))

        references_data = vulnerability['cve'].get('references', [])
        for reference_data in references_data:
            url = reference_data['url']
            source = reference_data.get('source', '')
            tags = reference_data.get('tags', [])
            references.append(CVEReference(cve=await sync_to_async(CVE.objects.get)(id=cve_id), url=url, source=source, tags=tags))

    await sync_to_async(CVEDescription.objects.bulk_create)(descriptions)
    await sync_to_async(CVSSMetricV2.objects.bulk_create)(cvssmetricsV2)
    await sync_to_async(CVSSMetricV31.objects.bulk_create)(cvssmetricsV31)
    await sync_to_async(CVEWeakness.objects.bulk_create)(weaknesses)
    await sync_to_async(CPEMatchInNode.objects.bulk_create)(cpe_matches)
    await sync_to_async(CVEReference.objects.bulk_create)(references)

    return stored_count

async def fetch_nvd_data_and_save(start_index):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'startIndex': 0,
        'resultsPerPage': 2000
    }

    # Initial request to get the total number of results
    async with aiohttp.ClientSession() as session:
        initial_response = await fetch_initial_page(session, 0, 1)
        if initial_response is None:
            return
        total_results = initial_response.get('totalResults', 0)
        logging.info(f"Total results available: {total_results}")
        total_fetched = 0
        total_stored = 0

        tasks = []
        for start_index in range(0, total_results, params['resultsPerPage']):
            tasks.append(fetch_page(session, start_index, params['resultsPerPage']))

        for future in asyncio.as_completed(tasks):
            page_data = await future
            if page_data:
                vulnerabilities = page_data.get('vulnerabilities', [])
                fetched_count = len(vulnerabilities)
                total_fetched += fetched_count
                stored_count = await save_vulnerabilities(vulnerabilities)
                total_stored += stored_count
                logging.info(f"Fetched {fetched_count} CVEs in this page, Total fetched: {total_fetched}/{total_results}, Total stored: {total_stored}")

                # Log after every 2000 CVEs fetched
                if total_fetched % 2000 == 0:
                    logging.info(f"Log after {total_fetched} CVEs fetched and processed.")

        logging.info(f"Total CVEs fetched: {total_fetched}, Total CVEs stored: {total_stored}")


def log_database_counts():
    logging.info(f"Total CVEs in database: {CVE.objects.count()}")
    logging.info(f"Total Descriptions in database: {CVEDescription.objects.count()}")
    logging.info(f"Total CVSSV2 Metrics in database: {CVSSMetricV2.objects.count()}")
    logging.info(f"Total CVSSV31 Metric in database: {CVSSMetricV31.objects.count()}")
    logging.info(f"Total Weaknesses in database: {CVEWeakness.objects.count()}")
    logging.info(f"Total Configurations in database: {CVEConfiguration.objects.count()}")
    logging.info(f"Total Nodes in database: {CVENode.objects.count()}")
    logging.info(f"Total CPE Matches in database: {CPEMatchInNode.objects.count()}")
    logging.info(f"Total References in database: {CVEReference.objects.count()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch CVE data from NVD API and store it in the local database.')
    parser.add_argument('--start-index', type=int, default=0, help='Index to start fetching data from.')
    args = parser.parse_args()
    
    if args.start_index == 0:
        # Check if data exists only if start-index is 0
        data_exists = asyncio.run(check_if_data_exists())
        if data_exists:
            # If data exists, exit
            exit()

    # Fetch NVD data and save it to the database
    asyncio.run(fetch_nvd_data_and_save(args.start_index))
    log_database_counts()