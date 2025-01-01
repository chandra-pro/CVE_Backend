'''
============
customlog.py
============

This module is wrapper over python logging class.
Used throughout application for logging purpose.

'''
# customLog.py

import os
import logging
import logging.config
import settings  # Ensure you have a settings module or adjust as needed

LOG_DIR_PATH = settings.LOG_DIR_PATH
LOG_LEVEL = settings.LOG_LEVEL

# Ensure the log directory exists
if not os.path.exists(LOG_DIR_PATH):
    os.makedirs(LOG_DIR_PATH)

def setup_logging(script_name):
    """
    Set up logging configuration.
    :param script_name: The name of the script requesting logging setup.
    """
    log_file_name = f'{script_name}.log'
    log_file_path = os.path.join(LOG_DIR_PATH, log_file_name)

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
                'filename': log_file_path,
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

    logging.config.dictConfig(logging_config)
