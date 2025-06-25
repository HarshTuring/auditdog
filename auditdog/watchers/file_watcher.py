import os
import asyncio
import pyinotify
from typing import Callable, Dict, Any, Optional

from .base import BaseWatcher

class FileWatcher(BaseWatcher):
    """Watch a file for new content using inotify"""
    
    def __init__(
        self, 
        file_path: str, 
        callback: Callable[[str, Dict[str, Any]], None],
        seek_to_end: bool = True
    ):
        """
        Initialize a file watcher.
        
        Args:
            file_path: Path to the file to watch
            callback: Function to call with (log_line, metadata) for each new log entry
            seek_to_end: If True, start watching from the end of the file
        """
        super().__init__(callback)
        self.file_path = file_path
        self.seek_to_end = seek_to_end
        self._watcher = None
        self._watch_manager = None
        self._watch_descriptor = None
        self._file_handle = None
        self._loop = None
        
    async def start(self) -> None:
        """Start watching the file for changes"""
        if self._running:
            return
            
        self._running = True
        self._loop = asyncio.get_event_loop()
        
        # Open the file for reading
        self._file_handle = open(self.file_path, 'r')
        if self.seek_to_end:
            self._file_handle.seek(0, os.SEEK_END)
        
        # Set up inotify watcher
        self._watch_manager = pyinotify.WatchManager()
        self._watcher = pyinotify.AsyncioNotifier(
            self._watch_manager, self._loop,
            default_proc_fun=self._process_event
        )
        
        # Add the file to watch for modifications
        mask = pyinotify.IN_MODIFY
        self._watch_descriptor = self._watch_manager.add_watch(
            self.file_path, mask
        )
        
    async def stop(self) -> None:
        """Stop watching the file"""
        if not self._running:
            return
            
        self._running = False
        
        if self._watcher:
            self._watcher.stop()
            self._watcher = None
            
        if self._watch_manager and self._watch_descriptor:
            self._watch_manager.rm_watch(self._watch_descriptor.values())
            self._watch_manager = None
            
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
    
    def _process_event(self, event):
        """Process an inotify event"""
        if not event.mask & pyinotify.IN_MODIFY:
            return
            
        # Read all new lines
        while True:
            line = self._file_handle.readline()
            if not line:
                break
                
            # Skip empty lines
            line = line.strip()
            if not line:
                continue
                
            # Send the line to the callback with metadata
            metadata = {
                'source': self.file_path,
                'timestamp': event.timestamp
            }
            self.callback(line, metadata)