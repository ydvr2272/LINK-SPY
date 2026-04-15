import subprocess
import sys
import os


def start():
    print("\n" + "-" * 45)
    print("  LinkSpy - URL Threat Detection Tool")
    print("-" * 45)

    # check if flask is installed, if not install it automatically
    try:
        import flask
        print("Flask is already installed")
    except ImportError:
        print("Flask not found, installing now...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "flask"])
        print("Flask installed!")

    # check if requests is installed
    try:
        import requests
        print("Requests is already installed")
    except ImportError:
        print("Installing requests...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        print("Requests installed!")

    # check if whois is installed
    try:
        import whois
        print("Whois is already installed")
    except ImportError:
        print("Installing python-whois...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-whois"])
        print("Whois installed!")

    # go to the folder where this script lives
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("\nAll libraries ready!")
    print("Starting LinkSpy server...")
    print("Open your browser: http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    # start the flask app
    os.system('"' + sys.executable + '" app.py')


if __name__ == "__main__":
    start()