#!/bin/bash

# Navigate to the Server directory
cd "$(dirname "$0")" || exit 1

# Activate virtual environment if needed (uncomment and update path if required)
# source /path/to/your/venv/bin/activate

# Run Django commands
echo "Running migrations..."
python3 manage.py makemigrations && python3 manage.py migrate

echo "Syncing CVE data..."
python3 sync_cve_fetch.py

echo "Syncing CPE data..."
python3 sync_cpe_fetch.py

echo "Script execution completed."