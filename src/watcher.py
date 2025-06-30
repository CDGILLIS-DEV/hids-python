import time 
import hashlib
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from .hash_utils import get_file_hash

# File event handler
class FileMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            hash = get_file_hash(event.src_path)
            logging.info(f"File created: {event.src_path} | SHA256: {hash}")
    
    def on_modified(self, event):
        if not event.is_directory:
            hash = get_file_hash(event.src_path)
            logging.info(f"File modified: {event.src_path} | SHA256: {hash}")

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