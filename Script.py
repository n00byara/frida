import os

from frida.core import Script
from watchdog.events import FileSystemEvent, FileSystemEventHandler

class Script(FileSystemEventHandler):
    def __init__(self, session, path) -> None:
        self.session = session
        self.path = path
        self.script_file = open(path, "r")
        self.script = self.session.create_script(self.script_file.read())
        self.script.load()

    def on_modified(self, event: FileSystemEvent) -> None:
        os.system("clear" if os.name != "nt" else "cls")
        print("Updated script...")
        self.script.unload()

        self.script_file = open(self.path, "r")
        self.script = self.session.create_script(self.script_file.read())
        self.script.load()
    
    def get(self) -> Script:
        return self.script