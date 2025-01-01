# delete_all_data.py

from django.core.management.base import BaseCommand
from django.db import connection

class Command(BaseCommand):
    help = 'Deletes all data from all tables in the database'

    def handle(self, *args, **kwargs):
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA foreign_keys = OFF;")  # Disable foreign key checks in SQLite
            table_names = connection.introspection.table_names()

            for table_name in table_names:
                cursor.execute(f'DELETE FROM {table_name};')

            cursor.execute("PRAGMA foreign_keys = ON;")  # Re-enable foreign key checks
        
        self.stdout.write(self.style.SUCCESS('Successfully deleted all data.'))
