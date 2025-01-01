from django_cron import CronJobBase, Schedule
import subprocess
import os
from datetime import datetime



class UpdateV2CronJob(CronJobBase):
    RUN_EVERY_MINS = 720

    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'serverapp.update_v2_cron_job'

    def do(self):
        # Define the log file path
        log_file = os.path.join(os.path.dirname(__file__), 'cronjob.log')

        try:
            # Determine server directory and script path
            server_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
            script_path = os.path.join(server_directory, 'update_v2.0.sh')

            # Log the start time and action
            with open(log_file, 'a') as log:
                log.write(f"\n[{datetime.now()}] Running update_v2.0.sh...\n")

            # Run the bash script
            subprocess.run(['bash', script_path], cwd=server_directory, check=True)

            # Log success
            with open(log_file, 'a') as log:
                log.write(f"[{datetime.now()}] Cron job executed successfully.\n")

        except subprocess.CalledProcessError as e:
            # Log any errors that occur
            with open(log_file, 'a') as log:
                log.write(f"[{datetime.now()}] Error running the script: {e}\n")
