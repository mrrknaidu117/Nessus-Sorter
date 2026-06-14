import os
import subprocess
import sys

def main():
    print("==================================================")
    print("    Nessus CSV Sorter Executable Builder          ")
    print("==================================================")
    
    # 1. Check/Install PyInstaller
    print("\n[1/3] Verifying PyInstaller installation...")
    try:
        import PyInstaller
        print("  - PyInstaller is already installed.")
    except ImportError:
        print("  - PyInstaller not found. Installing via pip...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
            print("  - PyInstaller installed successfully!")
        except Exception as e:
            print(f"  - ERROR: Failed to install PyInstaller: {e}")
            sys.exit(1)
            
    # 2. Run PyInstaller Compilation
    print("\n[2/3] Building standalone executable...")
    # Parameters:
    # --noconsole : hide the black CMD window when the GUI launches
    # --onefile   : package everything into a single .exe
    # --name      : set name of the compiled file
    cmd = [
        "pyinstaller",
        "--noconsole",
        "--onefile",
        "--name=NessusSorter",
        "nessus_sorter.py"
    ]
    try:
        subprocess.run(cmd, check=True)
        print("\n[3/3] Build compilation successful!")
        exe_path = os.path.join("dist", "NessusSorter.exe")
        print(f"\nCompleted! You can find your standalone executable at:\n  -> {os.path.abspath(exe_path)}")
    except subprocess.CalledProcessError as e:
        print(f"\n  - ERROR: PyInstaller build failed with exit code: {e.returncode}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  - ERROR: Build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
