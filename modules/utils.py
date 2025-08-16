import os, glob
from typing import Union, List
from modules.logger import setup_logging

class FileSizeError(Exception):
    pass

class UTILS:
    def __init__(self):    
        self.log = setup_logging(name="ReCrypt", level="DEBUG")

    def get_file_size(self, path: Union[str, os.PathLike], human_readable: bool = False) -> Union[int, str]:
        try:
            if not os.path.isfile(path):
                raise FileSizeError(f"File not found: {path}")
            size = os.path.getsize(path)
            return self._format_size(size) if human_readable else size
        except (OSError, FileSizeError) as e:
            self.log.error(f"Error getting file size: {e}")
            raise FileSizeError(f"Failed to get size of file '{path}': {e}") from e

    def get_all_files(self, directory: str, pattern: str = "*") -> List[str]:
        search_path = os.path.join(directory, pattern)
        return glob.glob(search_path)

    def _format_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} PB"