import os
import subprocess
import platform
import time

def launch_terminals():
    # Your specific commands
    commands = [
        ("Layer 1 - Ingestion", "python layer_1_feature_engineering/mock_layer_1_output.py"),
        ("Layer 2 - Detection", "python -m layer_2_detection.detection_orchestrator"),
        ("Layer 3 - AI Analyst", "python layer_3_ai_analysis/app.py"),
        ("Layer 4 - CVSS Scoring", "python -m layer_4_cvss.cvss_orchestrator"),
        ("Layer 5 - Response", "python -m layer_5_response.response_orchestrator")
    ]

    os_name = platform.system()
    cwd = os.getcwd()

    print(f"🚀 Detected OS: {os_name}. Launching tuxSOC layers in separate terminals...")

    for title, cmd in commands:
        print(f"➡️ Spawning: {title}")
        
        if os_name == "Windows":
            # Opens a new Command Prompt window for each process
            subprocess.Popen(f'start "{title}" cmd /k "{cmd}"', shell=True)
            
        elif os_name == "Darwin": # macOS
            # Uses AppleScript to open a new Terminal window/tab
            apple_script = f'tell application "Terminal" to do script "cd {cwd} && {cmd}"'
            subprocess.Popen(['osascript', '-e', apple_script])
            
        elif os_name == "Linux":
            # Attempts to use gnome-terminal (Ubuntu default), falls back to xterm
            try:
                subprocess.Popen(['kitty', '--title', title, '--', 'bash', '-c', f'{cmd}; exec bash'])
            except FileNotFoundError:
                subprocess.Popen(['xterm', '-T', title, '-e', f'{cmd}; bash'])
                
        else:
            print(f"❌ Unsupported OS: {os_name}")
            return
            
        # Slight pause so the terminal windows don't trip over each other
        time.sleep(0.5)

    print("✅ All 5 layers launched successfully! Check your taskbar.")

if __name__ == "__main__":
    launch_terminals()