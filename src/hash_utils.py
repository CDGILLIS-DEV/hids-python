import hashlib
import logging

# Function to calculate file hash (SHA256)
def get_file_hash(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        logging.warning(f"Could not hash {filepath}: {e}")
        return None