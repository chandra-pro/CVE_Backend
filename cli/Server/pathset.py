import os
import json
import argparse

# Path to the config.json file in the root folder (relative to the test.py script)
CONFIG_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'config.json'))

def normalize_path(path):
    """Convert Windows-style backslashes to forward slashes."""
    return path.replace('\\', '/')

def store_paths_in_config(path_dict):
    # Load existing config if the file exists
    if os.path.exists(CONFIG_FILE_PATH):
        with open(CONFIG_FILE_PATH, 'r') as config_file:
            config_data = json.load(config_file)
    else:
        config_data = {}

    # Add the new paths to the config file with specified keys
    config_data.update(path_dict)

    # Write the updated config back to the file
    with open(CONFIG_FILE_PATH, 'w') as config_file:
        json.dump(config_data, config_file, indent=4)
    print(f"Paths {path_dict} stored in {CONFIG_FILE_PATH}.")

def main():
    # Initialize argparse to get the absolute paths from the user with flags
    parser = argparse.ArgumentParser(description="Store multiple absolute paths with flags in the config.json file.")
    
    parser.add_argument('-v1', type=str, help="Absolute path for downloads directory")
    parser.add_argument('-v2', type=str, help="Absolute path for uploads directory")
    parser.add_argument('-v3', type=str, help="Absolute path for absolute_path3")
    

    
    # Parse the arguments
    args = parser.parse_args()

    # Collect the paths provided by the user
    path_dict = {}
    if args.v1:
        path_dict['download_dir'] = normalize_path(os.path.abspath(args.v1))
    if args.v2:
        path_dict['upload_dir'] = normalize_path(os.path.abspath(args.v2))
    if args.v3:
        path_dict['working_dir'] = normalize_path(os.path.abspath(args.v3))

    

    # If no paths are provided, show a message
    if not path_dict:
        print("No paths provided. Use -v1, -v2 to specify paths.")
        return

    # Store the paths in config.json
    store_paths_in_config(path_dict)

if __name__ == '__main__':
    main()
