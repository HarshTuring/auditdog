import os
import asyncio
import time
from typing import Callable, Dict, Any, Optional
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from .base import BaseWatcher

class LogFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that monitors file modifications"""
    
    def __init__(self, file_path: str, callback: Callable[[FileModifiedEvent], None], debug=False):
        """
        Initialize the event handler.
        
        Args:
            file_path: The file path to watch
            callback: Function to call when the file is modified
            debug: Whether to enable debug logging
        """
        super().__init__()
        self.file_path = Path(file_path)
        self.callback = callback
        self.debug = debug
    
    def on_modified(self, event):
        """Called when a file modification event occurs"""
        # Check if the modified file is the one we're watching
        if not event.is_directory and Path(event.src_path) == self.file_path:
            if self.debug:
                print(f"DEBUG: File modification detected: {event.src_path}")
            self.callback(event)

class FileWatcher(BaseWatcher):
    """Watch a file for new content using watchdog"""
    
    def __init__(
        self, 
        file_path: str, 
        callback: Callable[[str, Dict[str, Any]], None],
        seek_to_end: bool = True,
        debug: bool = False
    ):
        """
        Initialize a file watcher.
        
        Args:
            file_path: Path to the file to watch
            callback: Function to call with (log_line, metadata) for each new log entry
            seek_to_end: If True, start watching from the end of the file
            debug: Whether to enable debug logging
        """
        super().__init__(callback)
        self.file_path = file_path
        self.seek_to_end = seek_to_end
        self.debug = debug
        self._observer = None
        self._file_handle = None
        self._loop = None
        self._position = 0
        self._check_interval = 0.1  # seconds
        self._check_task = None
        
    async def start(self) -> None:
        """Start watching the file for changes"""
        if self._running:
            return
            
        self._running = True
        self._loop = asyncio.get_event_loop()
        
        if self.debug:
            print(f"DEBUG: Starting file watcher for {self.file_path}")
        
        try:
            # Open the file for reading
            self._file_handle = open(self.file_path, 'r')
            if self.seek_to_end:
                self._file_handle.seek(0, os.SEEK_END)
                if self.debug:
                    print(f"DEBUG: Seeked to end of file at position {self._file_handle.tell()}")
            
            # Store current position
            self._position = self._file_handle.tell()
            
            # Process any existing content if not seeking to end
            if not self.seek_to_end:
                await self._read_new_content(initial=True)
            
            # Set up watchdog observer
            self._observer = Observer()
            event_handler = LogFileEventHandler(self.file_path, self._handle_file_modified, self.debug)
            self._observer.schedule(
                event_handler, 
                path=os.path.dirname(self.file_path),
                recursive=False
            )
            self._observer.start()
            if self.debug:
                print(f"DEBUG: Watchdog observer started for {self.file_path}")
            
            # Create a task to periodically check for new content
            self._check_task = asyncio.create_task(self._check_file_content())
            
        except Exception as e:
            if self.debug:
                print(f"ERROR: Failed to start file watcher: {str(e)}")
            await self.stop()
            raise
        
    async def stop(self) -> None:
        """Stop watching the file"""
        if not self._running:
            return
            
        self._running = False
        
        if self.debug:
            print(f"DEBUG: Stopping file watcher for {self.file_path}")
        
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
            self._check_task = None
            
        if self._observer:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
    
    def _handle_file_modified(self, event):
        """Handle a file modification event from watchdog"""
        if self.debug:
            print(f"DEBUG: File modification event received for {self.file_path}")
        asyncio.run_coroutine_threadsafe(self._read_new_content(), self._loop)
        
    async def _check_file_content(self):
        """Periodically check for new content in the file"""
        while self._running:
            await self._read_new_content()
            await asyncio.sleep(self._check_interval)
    
    async def _read_new_content(self, initial=False):
        """Read new content from the file since the last read"""
        if not self._file_handle or not self._running:
            return
            
        try:
            # Check if file has been truncated
            try:
                size = os.path.getsize(self.file_path)
            except OSError:
                # File might have been temporarily unavailable
                return
                
            if size < self._position:
                # File was truncated
                if self.debug:
                    print(f"DEBUG: File appears to have been truncated, resetting position")
                self._file_handle.seek(0)
                self._position = 0
                
            # Seek to where we left off
            self._file_handle.seek(self._position)
            
            # Read all new lines
            new_lines = []
            while True:
                line = self._file_handle.readline()
                if not line:
                    break
                    
                # Skip empty lines
                line = line.rstrip('\n')
                if not line:
                    continue
                    
                new_lines.append(line)
                    
            # Update position
            self._position = self._file_handle.tell()
            
            # Process all new lines
            if new_lines:
                if self.debug:
                    print(f"DEBUG: Read {len(new_lines)} new line(s)")
                
                # Send the lines to the callback with metadata
                for line in new_lines:
                    metadata = {
                        'source': self.file_path,
                        'timestamp': time.time()
                    }
                    self.callback(line, metadata)
            elif initial and self.debug:
                print(f"DEBUG: Initial read found no lines to process")
                
        except Exception as e:
            if self.debug:
                print(f"ERROR: Error reading from file: {str(e)}")