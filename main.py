import configparser
import os
import signal
import sys

import frida
from watchdog.observers import Observer
from watchdog.events import FileModifiedEvent

from Script import Script

config_path = "./configurate/config.ini"
config = None

current = {
    "observer": None,
    "script": None
}


def main() -> None:
    if get_config():
        global current
        device = frida.get_usb_device()
        current["device"] = device

        processes = device.enumerate_processes()
        pid = get_pid(processes=processes)
        session = device.attach(target=pid)
        create_script(session=session)
        
        add_keyboard_listener()
    else:
        print("Bad Config!")

# Getting config from keyboard
def get_config() -> bool:
    global config
    config = configparser.ConfigParser()
    config.read(config_path)
    config = config["Values"]

    if config["script"] != "" and config["app_name"] != "" and config["package_name"] != "":
        return True
    else:
        print("Please fill in the config!")

        config = {
            "app_name": "",
            "package_name": "",
            "script": ""
        }

        set_line_from_keyboard(message="app name", key="app_name")
        set_line_from_keyboard(message="package name", key="package_name")
        set_line_from_keyboard(message="script", key="script")

        clear_console()

        return True

def set_line_from_keyboard(message, key) -> str:
    global config

    while config[key] == "":
        print(f"Enter {message}")
        config[key] = sys.stdin.readline().strip()

# Get PID from all processes ho like from config package_name or app_name
def get_pid(processes) -> int:
    for process in processes:
        if process.name == config["package_name"] or process.name == config["app_name"]:
            return process.pid

# Creating script with observer for updating script text
def create_script(session) -> None:
    global current
    observer = Observer()

    script_file_path = f"scripts/{config["script"]}.js"
    print(f"Create script...")
    script = Script(session, script_file_path)

    observer.schedule(script, path="./scripts", recursive=False, event_filter=[FileModifiedEvent])
    current["observer"] = observer
    observer.start()
    current["script"] = script.get()

def exit(signal_number, frame_object) -> None:
    stop()

# Added a listener for using commands
def add_keyboard_listener() -> None:
    global current
    for line in sys.stdin:
        match line.strip():
            case "clear":
                clear_console()
            case "exit":
                stop()

                sys.exit()

def stop():
    global current
    # "observer, script = current.values()" Don't work. Why??
    observer = current["observer"]
    script = current["script"]

    if observer != None:
        observer.stop()

    if script != None:
        script.unload()

def clear_console() -> None:
    os.system("clear" if os.name != "nt" else "cls")

try:
    signal.signal(signal.SIGTERM, exit)
    signal.signal(signal.SIGINT, exit)
    main()
except ValueError:
    raise ValueError