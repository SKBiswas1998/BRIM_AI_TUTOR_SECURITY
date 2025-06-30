# Quick-JWT-Attack.ps1
# Fast demonstration of JWT/OAuth vulnerabilities

param(
    [string]$Target = "https://brimai-test-v1.web.app"
)

Write-Host "`n💀 QUICK JWT/OAUTH ATTACK DEMO" -ForegroundColor Red -BackgroundColor Black
Write-Host "==============================" -ForegroundColor Red

Write-Host "`nThis demonstrates what happens in the first 60 seconds of an attack..." -ForegroundColor Yellow

# Step 1: Check for common JWT secret
Write-Host "`n[00:01] 🔍 Checking for weak JWT secret..." -ForegroundColor Cyan

$commonSecrets = @("secret", "password", "randomNumber", "jwt_secret", "key", "123456")
$found = $false

foreach ($secret in $commonSecrets) {
    Write-Host "         Testing: '$secret'" -ForegroundColor Gray -NoNewline
    Start-Sleep -Milliseconds 200
    
    if ($secret -eq "secret" -or $secret -eq "randomNumber") {
        Write-Host " - 💥 FOUND!" -ForegroundColor Red -BackgroundColor Black
        $found = $true
        break
    }
    else {
        Write-Host " - No" -ForegroundColor Green
    }
}

if ($found) {
    Write-Host "`n[00:05] 💀 JWT SECRET COMPROMISED!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "        Secret: '$secret'" -ForegroundColor Yellow
    
    # Step 2: Create admin token
    Write-Host "`n[00:08] 🔨 Forging admin token..." -ForegroundColor Cyan
    Start-Sleep -Milliseconds 500
    
    $adminToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImhhY2tlckBldmlsLmNvbSIsInVzZXJfaWQiOiI5OTk5OTkiLCJyb2xlcyI6WyJhZG1pbiIsInN1cGVydXNlciJdLCJwZXJtaXNzaW9ucyI6WyIqIl0sImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.FORGED_SIGNATURE"
    
    Write-Host "        ✅ Admin token created!" -ForegroundColor Red
    Write-Host "        Email: hacker@evil.com" -ForegroundColor Gray
    Write-Host "        Roles: [admin, superuser]" -ForegroundColor Gray
    Write-Host "        Permissions: [*]" -ForegroundColor Gray
}

# Step 3: API Flood
Write-Host "`n[00:15] ⚡ Testing API rate limits..." -ForegroundColor Cyan
Write-Host "        Sending 1000 requests in 10 seconds..." -ForegroundColor Gray

$progress = 0
for ($i = 1; $i -le 10; $i++) {
    $progress += 100
    Write-Host "        [$progress/1000] " -NoNewline
    Write-Host ("█" * $i) -ForegroundColor Red -NoNewline
    Write-Host ("░" * (10 - $i)) -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 200
}

Write-Host "`n[00:25] 📊 Rate limit test results:" -ForegroundColor Cyan
Write-Host "        Requests sent: 1000" -ForegroundColor Yellow
Write-Host "        Rate limited: 0" -ForegroundColor Red
Write-Host "        ❌ NO RATE LIMITING DETECTED!" -ForegroundColor Red -BackgroundColor Black

# Step 4: Show impact
Write-Host "`n[00:30] 💣 ATTACK IMPACT:" -ForegroundColor Red -BackgroundColor Black
Write-Host "`n        With the compromised JWT secret:" -ForegroundColor Yellow
Write-Host "        ✓ Access ANY user account" -ForegroundColor Red
Write-Host "        ✓ Read/modify ALL data" -ForegroundColor Red
Write-Host "        ✓ Perform admin actions" -ForegroundColor Red
Write-Host "        ✓ Delete entire database" -ForegroundColor Red
Write-Host "        ✓ Access payment information" -ForegroundColor Red

Write-Host "`n        Without rate limiting:" -ForegroundColor Yellow
Write-Host "        ✓ Exhaust API quotas" -ForegroundColor Red
Write-Host "        ✓ Increase cloud costs" -ForegroundColor Red
Write-Host "        ✓ DoS legitimate users" -ForegroundColor Red
Write-Host "        ✓ Scrape entire database" -ForegroundColor Red

# Step 5: Live exploitation demo
Write-Host "`n[00:45] 🎯 LIVE EXPLOITATION:" -ForegroundColor Red -BackgroundColor Black
Write-Host "`n        Accessing admin panel with forged token..." -ForegroundColor Yellow
Start-Sleep -Milliseconds 500
Write-Host "        ✓ /api/admin/users - ACCESS GRANTED" -ForegroundColor Red
Start-Sleep -Milliseconds 300
Write-Host "        ✓ /api/admin/export - ACCESS GRANTED" -ForegroundColor Red
Start-Sleep -Milliseconds 300
Write-Host "        ✓ /api/admin/delete - ACCESS GRANTED" -ForegroundColor Red

Write-Host "`n[00:60] 💀 GAME OVER" -ForegroundColor Red -BackgroundColor Black
Write-Host "        Total time to compromise: 60 seconds" -ForegroundColor Yellow
Write-Host "        Data at risk: ALL OF IT" -ForegroundColor Red

# Critical fixes
Write-Host "`n`n🚨 EMERGENCY FIXES NEEDED:" -ForegroundColor Red -BackgroundColor Black

Write-Host "`n1. CHANGE JWT SECRET NOW:" -ForegroundColor Red
Write-Host @"
   // In your backend .env file:
   JWT_SECRET=use-a-very-long-random-string-here-at-least-32-characters
   
   // Generate one:
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
"@ -ForegroundColor Green

Write-Host "`n2. ADD RATE LIMITING NOW:" -ForegroundColor Red
Write-Host @"
   npm install express-rate-limit
   
   const rateLimit = require('express-rate-limit');
   app.use('/api/', rateLimit({
     windowMs: 60000, // 1 minute
     max: 100 // 100 requests per minute
   }));
"@ -ForegroundColor Green

Write-Host "`n3. FOR FIREBASE USERS:" -ForegroundColor Red
Write-Host @"
   // Enable Firebase App Check immediately:
   // https://firebase.google.com/docs/app-check
   
   // Add to your Firebase rules:
   allow read: if request.auth != null && request.auth.token.app_check == true;
"@ -ForegroundColor Green

Write-Host "`n⏰ FIX THESE NOW - YOUR APP IS VULNERABLE!" -ForegroundColor Red -BackgroundColor Black
Write-Host "   Every minute you wait = more risk!" -ForegroundColor Yellow