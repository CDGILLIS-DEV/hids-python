import time 
import hashlib
import logging
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from vt_api import check_virustotal, get_threat_level
from hash_utils import get_file_hash

# File event handler
class FileMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            logging.info(f"File created: {file_path}")

        file_hash = get_file_hash(file_path)
        if file_hash:
            logging.info(f"Computed SHA256: {file_hash}")

            vt_result = check_virustotal(file_hash)
            if vt_result:
                threat_level = get_threat_level(vt_result)
                logging.info(f"Threat level for {file_path}: {threat_level}")
                logging.info(f"VirusTotal result: {vt_result}")
            else:
                logging.info(f"No VirusTotal data for {file_path}")
    
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            logging.info(f"File modified: {file_path}")
        
        file_hash = get_file_hash(file_path)
        if file_hash:
            logging.info(f"Computed SHA256: {file_hash}")

            vt_result = check_virustotal(file_hash)
            if vt_result:
                threat_level = get_threat_level(vt_result)
                logging.info(f"Threat level for {file_path}: {threat_level}")
                logging.info(f"VirusTotal result: {vt_result}")
            else:
                logging.info(f"No VirusTotal data for {file_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f"File deleted: {event.src_path}")

# Watcher setup
def start_watching(path_to_watch):
    event_handler = FileMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    logging.info(f"Started monitoring {path_to_watch}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopped monitoring")
    observer.join()

    # Run the monitor
    if __name__ == "__main__":
        folder = input("Enter the folder path to monitor: ").strip()
        if os.path.isdir(folder):
            start_watching(folder)
        else:
            print("This is not a valid folder path.")