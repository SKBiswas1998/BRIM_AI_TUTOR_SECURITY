from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time
import json

print("="*60)
print("BrimAI Browser-Based Security Testing")
print("="*60)

# Setup Chrome with DevTools
options = webdriver.ChromeOptions()
options.add_argument('--disable-blink-features=AutomationControlled')
options.add_experimental_option("excludeSwitches", ["enable-automation"])
options.add_experimental_option('useAutomationExtension', False)

# Enable DevTools Protocol
options.set_capability("goog:loggingPrefs", {"browser": "ALL", "network": "ALL"})

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

try:
    print("\n[1] Loading BrimAI app...")
    driver.get("https://brimai-test-v1.web.app/")
    time.sleep(3)
    
    # Check what's in the global scope
    print("\n[2] Checking JavaScript globals...")
    globals_check = driver.execute_script("""
        return {
            firebase: typeof firebase !== 'undefined',
            gapi: typeof gapi !== 'undefined',
            auth: typeof auth !== 'undefined',
            db: typeof db !== 'undefined',
            config: typeof config !== 'undefined',
            api: typeof api !== 'undefined',
            localStorage_keys: Object.keys(localStorage),
            sessionStorage_keys: Object.keys(sessionStorage),
            cookies: document.cookie
        }
    """)
    
    print(f"Firebase available: {globals_check['firebase']}")
    print(f"Google API available: {globals_check['gapi']}")
    print(f"LocalStorage keys: {globals_check['localStorage_keys']}")
    print(f"SessionStorage keys: {globals_check['sessionStorage_keys']}")
    print(f"Cookies: {globals_check['cookies'][:100] if globals_check['cookies'] else 'None'}")
    
    # Monitor network requests
    print("\n[3] Monitoring network requests...")
    print("Please perform the following actions:")
    print("1. Try to login")
    print("2. Navigate around the app")
    print("3. Try to access protected features")
    print("\nPress Ctrl+C when done...")
    
    # Get browser logs
    logs = driver.get_log('browser')
    for log in logs:
        if 'api' in log['message'].lower() or 'auth' in log['message'].lower():
            print(f"Console: {log['message']}")
    
    # Keep browser open for manual testing
    input("\nPress Enter to close browser...")
    
except KeyboardInterrupt:
    print("\nStopping browser test...")
except Exception as e:
    print(f"Error: {e}")
finally:
    # Extract any found API calls from browser
    try:
        api_calls = driver.execute_script("""
            return window.performance.getEntries()
                .filter(e => e.initiatorType === 'fetch' || e.initiatorType === 'xmlhttprequest')
                .map(e => e.name);
        """)
        
        if api_calls:
            print("\n[4] API calls detected:")
            for call in api_calls:
                if 'brimai' not in call and 'firebase' in call or 'googleapis' in call:
                    print(f"  - {call}")
    except:
        pass
        
    driver.quit()
