import time
import os
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class QuarantineHandler(FileSystemEventHandler):
    def __init__(self, file_queue):
        super().__init__()
        self.file_queue = file_queue

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            logging.info(f"New file detected: {file_path}")

            time.sleep(2)  # wait for file copy to finish

            if os.path.exists(file_path):
                self.file_queue.put(file_path)
                logging.info(f"File added to queue: {file_path}")

    def on_moved(self, event):
        if not event.is_directory:
            file_path = event.dest_path
            logging.info(f"File moved into quarantine: {file_path}")
            self.file_queue.put(file_path)


def start_watcher(folder_to_watch, file_queue):
    if not os.path.exists(folder_to_watch):
        logging.warning(f"Folder '{folder_to_watch}' not found. Creating...")
        os.makedirs(folder_to_watch)

    event_handler = QuarantineHandler(file_queue)
    observer = Observer()
    observer.schedule(event_handler, folder_to_watch, recursive=False)
    observer.start()

    logging.info(f"Started monitoring folder: {folder_to_watch}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping watcher...")
        observer.stop()

    observer.join()