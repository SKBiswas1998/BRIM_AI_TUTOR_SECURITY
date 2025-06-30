# JWT-Quick-Secret-Viewer.ps1
# Quick tool to view all information in JWT tokens

param(
    [string]$Token = "", # Paste a token here to decode
    [string]$BaseUrl = "https://brimai-test-v1.web.app"
)

function Show-TokenSecrets {
    param([string]$JwtToken)
    
    Write-Host "`n🔍 DECODING JWT TOKEN" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    
    $parts = $JwtToken.Split('.')
    
    # Decode header
    $header = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[0] + "=="))
    $headerObj = $header | ConvertFrom-Json
    
    # Decode payload
    $payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1] + "=="))
    $payloadObj = $payload | ConvertFrom-Json
    
    Write-Host "`n📋 TOKEN HEADER:" -ForegroundColor Yellow
    Write-Host $header -ForegroundColor Gray
    
    Write-Host "`n🔓 TOKEN PAYLOAD (ALL YOUR SECRETS):" -ForegroundColor Red
    Write-Host $payload -ForegroundColor White
    
    Write-Host "`n📊 EXTRACTED INFORMATION:" -ForegroundColor Green
    Write-Host "=========================" -ForegroundColor Green
    
    # User information
    Write-Host "`nUser Data:" -ForegroundColor Cyan
    Write-Host "  User ID: $($payloadObj.user_id)" -ForegroundColor White
    Write-Host "  Email: $($payloadObj.email)" -ForegroundColor White
    Write-Host "  Role: $($payloadObj.role)" -ForegroundColor White
    
    # Time information
    if ($payloadObj.exp) {
        $expDate = [DateTimeOffset]::FromUnixTimeSeconds($payloadObj.exp).DateTime
        $remaining = ($expDate - (Get-Date).ToUniversalTime())
        Write-Host "`nToken Timing:" -ForegroundColor Cyan
        Write-Host "  Expires: $expDate UTC" -ForegroundColor White
        Write-Host "  Valid for: $([Math]::Round($remaining.TotalHours, 2)) hours" -ForegroundColor Yellow
    }
    
    # Additional claims
    Write-Host "`nAdditional Claims:" -ForegroundColor Cyan
    $payloadObj.PSObject.Properties | Where-Object { $_.Name -notin @("user_id", "email", "role", "exp") } | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor White
    }
    
    # What this token can access
    Write-Host "`n🚪 THIS TOKEN CAN ACCESS:" -ForegroundColor Yellow
    switch ($payloadObj.role) {
        "admin" {
            Write-Host "  ✓ All user data" -ForegroundColor Red
            Write-Host "  ✓ System settings" -ForegroundColor Red
            Write-Host "  ✓ Delete operations" -ForegroundColor Red
            Write-Host "  ✓ Export all data" -ForegroundColor Red
        }
        "teacher" {
            Write-Host "  ✓ Student grades" -ForegroundColor Yellow
            Write-Host "  ✓ Create quizzes" -ForegroundColor Yellow
            Write-Host "  ✓ Class analytics" -ForegroundColor Yellow
        }
        default {
            Write-Host "  ✓ Personal profile" -ForegroundColor Green
            Write-Host "  ✓ Own quiz results" -ForegroundColor Green
        }
    }
    
    # Show how to forge this token
    Write-Host "`n⚠️  ANYONE CAN CREATE THIS TOKEN WITH:" -ForegroundColor Red
    Write-Host @"

Python:
    import jwt
    token = jwt.encode($payload, 'randomNumber', algorithm='HS256')

Node.js:
    const jwt = require('jsonwebtoken');
    const token = jwt.sign($payload, 'randomNumber');

PowerShell:
    # Using the Create-Token function from the main script
"@ -ForegroundColor Gray
}

# If no token provided, get one
if (-not $Token) {
    Write-Host "No token provided. Getting one from the API..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl/api/auth/login" `
            -Method POST `
            -Body (@{email = "test@example.com" } | ConvertTo-Json) `
            -ContentType "application/json" `
            -UseBasicParsing
        
        $Token = ($response.Content | ConvertFrom-Json).access_token
    }
    catch {
        Write-Host "Failed to get token. Please provide one with -Token parameter" -ForegroundColor Red
        return
    }
}

# Show the secrets
Show-TokenSecrets -JwtToken $Token

# Show what attackers see
Write-Host "`n🔴 WHAT ATTACKERS SEE:" -ForegroundColor Red
Write-Host "=====================" -ForegroundColor Red
Write-Host "1. Your secret is 'randomNumber' (hardcoded)" -ForegroundColor Yellow
Write-Host "2. Algorithm is HS256 (symmetric)" -ForegroundColor Yellow
Write-Host "3. Tokens last 24 hours (too long)" -ForegroundColor Yellow
Write-Host "4. No unique token ID (can't revoke)" -ForegroundColor Yellow
Write-Host "5. They can create ANY token they want!" -ForegroundColor Red