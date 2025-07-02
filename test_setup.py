import requests
import jwt
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

print(f"{Fore.GREEN}✓ Setup successful!")
print(f"{Fore.BLUE}Testing connection to your app...")

try:
    response = requests.get("https://brimai-test-v1.web.app/", timeout=5)
    print(f"{Fore.GREEN}✓ Connection successful! Status: {response.status_code}")
except Exception as e:
    print(f"{Fore.RED}✗ Connection failed: {e}")

print(f"\n{Fore.YELLOW}Checking installed packages:")
packages = ['requests', 'jwt', 'colorama', 'aiohttp', 'pytest']
for package in packages:
    try:
        __import__(package)
        print(f"{Fore.GREEN}✓ {package} installed")
    except ImportError:
        print(f"{Fore.RED}✗ {package} not installed")
