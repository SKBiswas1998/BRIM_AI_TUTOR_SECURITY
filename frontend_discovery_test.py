import requests
import re
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

def test_frontend_exposure():
    """Test what can be discovered from the frontend using direct access methods"""
    print("="*60)
    print("🔍 TESTING FRONTEND EXPOSURE: https://brimai-test-v1.web.app/")
    print("="*60)
    
    base_url = "https://brimai-test-v1.web.app"
    findings = []
    
    def add_finding(severity, finding_type, path, details, evidence):
        findings.append({
            "severity": severity,
            "type": finding_type,
            "path": path,
            "details": details,
            "evidence": evidence
        })
        print(f"{severity}: {finding_type} at {path}")
        print(f"   → {details}")
    
    # 1. TEST COMMON FRONTEND PATHS
    print("\n📂 [1] TESTING COMMON FRONTEND PATHS...")
    
    common_paths = [
        # Common static files
        "/robots.txt",
        "/sitemap.xml", 
        "/.well-known/security.txt",
        "/manifest.json",
        "/favicon.ico",
        
        # Common config files
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.json",
        "/firebase.json",
        "/.firebaserc",
        "/package.json",
        
        # Development files
        "/.git/config",
        "/webpack.config.js",
        "/.gitignore",
        "/yarn.lock",
        "/package-lock.json",
        
        # Common directories
        "/admin",
        "/dashboard", 
        "/api",
        "/docs",
        "/debug",
        "/test",
        "/dev",
        
        # React specific
        "/static/js/",
        "/static/css/",
        "/build/",
        "/public/",
    ]
    
    for path in common_paths:
        try:
            response = requests.get(f"{base_url}{path}", timeout=5)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '')
                content = response.text[:500]
                
                # Check if it's actually useful content (not the React app fallback)
                if not ("<!doctype html>" in content.lower() and "react" in content.lower()):
                    severity = "HIGH" if any(sensitive in path for sensitive in ['.env', 'config', '.git']) else "MEDIUM"
                    
                    add_finding(
                        severity,
                        "Exposed Static File",
                        path,
                        f"Static file accessible: {content_type}",
                        f"Content preview: {content[:100]}..."
                    )
                    
                    # Special handling for sensitive files
                    if "firebase" in content.lower() or "api" in content.lower():
                        print(f"     ⚠️  Contains Firebase/API configuration!")
                    
        except Exception as e:
            continue
    
    # 2. ANALYZE MAIN PAGE FOR EXPOSED INFORMATION
    print("\n🌐 [2] ANALYZING MAIN PAGE FOR EXPOSED INFORMATION...")
    
    try:
        response = requests.get(base_url, timeout=10)
        if response.status_code == 200:
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract JavaScript bundle URLs
            script_tags = soup.find_all('script', src=True)
            print(f"Found {len(script_tags)} JavaScript files")
            
            for script in script_tags:
                src = script.get('src')
                if src and src.startswith('/static/js/'):
                    full_url = urljoin(base_url, src)
                    print(f"   📜 JavaScript bundle: {src}")
                    
                    # Download and analyze the main JS bundle
                    if 'main' in src:
                        try:
                            js_response = requests.get(full_url, timeout=10)
                            if js_response.status_code == 200:
                                js_content = js_response.text
                                
                                # Search for exposed secrets/configs
                                secrets_found = []
                                
                                # Firebase configuration
                                firebase_config = re.findall(r'apiKey["\s:]+["\'](.*?)["\']', js_content)
                                if firebase_config:
                                    secrets_found.append(f"Firebase API Key: {firebase_config[0][:20]}...")
                                
                                # API URLs  
                                api_urls = re.findall(r'https?://[a-zA-Z0-9\-\.]+\.(?:run\.app|cloudfunctions\.net|herokuapp\.com)[/a-zA-Z0-9\-]*', js_content)
                                if api_urls:
                                    unique_urls = list(set(api_urls))[:5]
                                    secrets_found.extend([f"API URL: {url}" for url in unique_urls])
                                
                                # Hardcoded secrets
                                secret_patterns = [
                                    (r'(?:secret|password|key|token)["\s:]+["\'](.*?)["\']', 'Hardcoded Secret'),
                                    (r'(?:api_key|apiKey)["\s:]+["\'](.*?)["\']', 'API Key'),
                                    (r'(?:auth_token|authToken)["\s:]+["\'](.*?)["\']', 'Auth Token'),
                                ]
                                
                                for pattern, secret_type in secret_patterns:
                                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                                    for match in matches[:3]:  # First 3 matches
                                        if len(match) > 10:  # Only meaningful secrets
                                            secrets_found.append(f"{secret_type}: {match[:20]}...")
                                
                                if secrets_found:
                                    add_finding(
                                        "HIGH",
                                        "Exposed Secrets in JavaScript",
                                        src,
                                        f"Found {len(secrets_found)} potential secrets in main JS bundle",
                                        f"Secrets: {secrets_found[:3]}"
                                    )
                                    
                                    for secret in secrets_found:
                                        print(f"     🔑 {secret}")
                                
                        except Exception as e:
                            print(f"     ❌ Error analyzing JS bundle: {str(e)}")
            
            # Check for inline scripts with secrets
            inline_scripts = soup.find_all('script', src=False)
            for script in inline_scripts:
                if script.string:
                    script_content = script.string
                    if any(keyword in script_content.lower() for keyword in ['apikey', 'token', 'secret', 'password']):
                        add_finding(
                            "MEDIUM",
                            "Inline Script with Potential Secrets",
                            "/",
                            "Inline JavaScript contains potential secrets",
                            f"Script content: {script_content[:100]}..."
                        )
            
    except Exception as e:
        print(f"❌ Error analyzing main page: {str(e)}")
    
    # 3. TEST FOR DIRECTORY LISTING
    print("\n📁 [3] TESTING FOR DIRECTORY LISTING...")
    
    directories = ["/static/", "/assets/", "/public/", "/build/", "/src/"]
    
    for directory in directories:
        try:
            response = requests.get(f"{base_url}{directory}", timeout=5)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for directory listing indicators
                if any(indicator in content for indicator in ['index of', 'directory listing', '<a href=']):
                    add_finding(
                        "MEDIUM",
                        "Directory Listing Enabled",
                        directory,
                        "Directory listing may be enabled",
                        "Response suggests directory browsing possible"
                    )
                    
        except Exception as e:
            continue
    
    # 4. TEST FOR SOURCE MAP FILES
    print("\n🗺️ [4] TESTING FOR SOURCE MAP FILES...")
    
    source_map_paths = [
        "/static/js/main.js.map",
        "/static/css/main.css.map",
        "/build/static/js/main.js.map"
    ]
    
    for path in source_map_paths:
        try:
            response = requests.get(f"{base_url}{path}", timeout=5)
            
            if response.status_code == 200:
                add_finding(
                    "MEDIUM",
                    "Source Map File Exposed",
                    path,
                    "Source map files expose original source code structure",
                    f"Source map size: {len(response.content)} bytes"
                )
                
                # Try to extract file names from source map
                try:
                    source_map = response.json()
                    if 'sources' in source_map:
                        sources = source_map['sources'][:5]  # First 5 files
                        print(f"     📄 Source files exposed: {sources}")
                except:
                    pass
                    
        except Exception as e:
            continue
    
    # 5. TEST FOR ERROR PAGES THAT LEAK INFO
    print("\n🚫 [5] TESTING ERROR PAGES FOR INFORMATION LEAKAGE...")
    
    error_test_paths = [
        "/admin/login",
        "/api/test",
        "/debug/info",
        "/internal/status",
        "/test/error"
    ]
    
    for path in error_test_paths:
        try:
            response = requests.get(f"{base_url}{path}", timeout=5)
            
            if response.status_code in [400, 401, 403, 500]:
                content = response.text.lower()
                
                # Check for information leakage in error pages
                leakage_indicators = ['stack trace', 'internal server', 'debug info', 'firebase', 'backend url']
                found_indicators = [ind for ind in leakage_indicators if ind in content]
                
                if found_indicators:
                    add_finding(
                        "LOW",
                        "Information Leakage in Error Pages",
                        path,
                        f"Error page may leak sensitive information",
                        f"Indicators found: {found_indicators}"
                    )
                    
        except Exception as e:
            continue
    
    # GENERATE REPORT
    print("\n" + "="*60)
    print("📊 FRONTEND EXPOSURE REPORT")
    print("="*60)
    
    if findings:
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity_counts[finding["severity"]] += 1
        
        print(f"\n🔍 TOTAL EXPOSURES FOUND: {len(findings)}")
        print(f"   High: {severity_counts['HIGH']}")
        print(f"   Medium: {severity_counts['MEDIUM']}")
        print(f"   Low: {severity_counts['LOW']}")
        
        print(f"\n📋 DETAILED FINDINGS:")
        for finding in findings:
            print(f"\n   {finding['severity']}: {finding['type']}")
            print(f"      Path: {finding['path']}")
            print(f"      Details: {finding['details']}")
            print(f"      Evidence: {finding['evidence']}")
        
        # Compare with backend
        print(f"\n🔄 COMPARISON WITH BACKEND:")
        print(f"   Frontend Security: {'Better' if len(findings) < 5 else 'Similar issues'}")
        print(f"   Backend Security: 7 critical vulnerabilities")
        print(f"   Overall Assessment: Backend is the primary security concern")
        
    else:
        print(f"\n✅ NO SIGNIFICANT EXPOSURES FOUND!")
        print("Frontend appears to be properly configured")
        print("Static hosting (Firebase) provides good security by default")
    
    print(f"\n💡 KEY DIFFERENCES FROM BACKEND:")
    print("• Frontend is static hosting (limited attack surface)")
    print("• No server-side processing (fewer vulnerabilities)")
    print("• Firebase hosting provides security by default")
    print("• Main risks are exposed secrets in JavaScript")
    
    return findings

if __name__ == "__main__":
    test_frontend_exposure()