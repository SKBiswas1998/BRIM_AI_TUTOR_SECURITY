# Extract-Exposed-Configs.ps1
# Extracts and displays content from exposed configuration files

param(
    [string]$Target = "https://brimai-test-v1.web.app"
)

Write-Host "`n🔓 EXTRACTING EXPOSED CONFIGURATION FILES" -ForegroundColor Red
Write-Host "=========================================" -ForegroundColor Red
Write-Host "Target: $Target" -ForegroundColor Yellow

# Function to safely display file content
function Show-FileContent {
    param(
        [string]$FileName,
        [string]$Content,
        [string]$Url
    )
    
    Write-Host "`n📄 FILE: $FileName" -ForegroundColor Cyan
    Write-Host "URL: $Url" -ForegroundColor Gray
    Write-Host "Size: $($Content.Length) bytes" -ForegroundColor Gray
    Write-Host "`nCONTENT:" -ForegroundColor Yellow
    Write-Host "------------------------" -ForegroundColor Gray
    
    # Display content (limit to 2000 chars for large files)
    if ($Content.Length -gt 2000) {
        Write-Host $Content.Substring(0, 2000) -ForegroundColor White
        Write-Host "`n... [TRUNCATED - File contains $($Content.Length) bytes total]" -ForegroundColor Gray
    }
    else {
        Write-Host $Content -ForegroundColor White
    }
    
    Write-Host "------------------------" -ForegroundColor Gray
    
    # Analyze for sensitive data
    Write-Host "`n🔍 SENSITIVE DATA FOUND:" -ForegroundColor Red
    
    $sensitivePatterns = @{
        "API Keys"          = "(?i)(api[_-]?key|apikey)['\"":\s]*([a-zA-Z0-9_\-]{20,})"
        "JWT Secrets"       = "(?i)(jwt[_-]?secret|secret[_-]?key)['\"":\s]*([^\s'\"",;}]+)"
        "Database URLs"     = "(?i)(database[_-]?url|db[_-]?connection|mongodb\+srv)['\"":\s]*([^\s'\"",;}]+)"
        "Passwords"         = "(?i)(password|pwd|pass)['\"":\s]*([^\s'\"",;}]+)"
        "Private Keys"      = "(?i)(private[_-]?key|secret)['\"":\s]*([^\s'\"",;}]+)"
        "AWS Keys"          = "(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)['\"":\s]*([^\s'\"",;}]+)"
        "Firebase Config"   = "(?i)(firebase[_-]?config|firebaseConfig)"
        "Email Credentials" = "(?i)(email[_-]?pass|smtp[_-]?pass)['\"":\s]*([^\s'\"",;}]+)"
        "OAuth Secrets"     = "(?i)(client[_-]?secret|oauth[_-]?secret)['\"":\s]*([^\s'\"",;}]+)"
        "Encryption Keys"   = "(?i)(encryption[_-]?key|decrypt[_-]?key)['\"":\s]*([^\s'\"",;}]+)"
    }
    
    $foundSecrets = @{}
    
    foreach ($pattern in $sensitivePatterns.GetEnumerator()) {
        $matches = [regex]::Matches($Content, $pattern.Value)
        if ($matches.Count -gt 0) {
            Write-Host "  ⚠️  $($pattern.Key):" -ForegroundColor Red
            foreach ($match in $matches) {
                $key = $match.Groups[1].Value
                $value = $match.Groups[2].Value
                
                # Partially hide the actual value for security
                if ($value.Length -gt 8) {
                    $hiddenValue = $value.Substring(0, 4) + "****" + $value.Substring($value.Length - 4)
                }
                else {
                    $hiddenValue = "****"
                }
                
                Write-Host "      $key = $hiddenValue" -ForegroundColor Yellow
                $foundSecrets[$key] = $value
            }
        }
    }
    
    if ($foundSecrets.Count -eq 0) {
        Write-Host "  No obvious secrets found (or well hidden)" -ForegroundColor Green
    }
    
    return $foundSecrets
}

# Try to fetch each exposed file
$exposedFiles = @(
    ".env",
    "config.json",
    "firebase.json",
    ".firebaserc",
    "package.json",
    "app.yaml",
    ".env.local",
    ".env.production",
    "secrets.json",
    "credentials.json",
    "service-account.json",
    "app.config.js",
    "next.config.js"
)

$allSecrets = @{}

foreach ($file in $exposedFiles) {
    try {
        Write-Host "`nTrying to fetch: $file" -ForegroundColor Gray -NoNewline
        
        $response = Invoke-WebRequest -Uri "$Target/$file" -UseBasicParsing -TimeoutSec 5
        
        if ($response.StatusCode -eq 200) {
            Write-Host " ✓ FOUND!" -ForegroundColor Red
            
            $content = $response.Content
            $secrets = Show-FileContent -FileName $file -Content $content -Url "$Target/$file"
            
            # Merge found secrets
            foreach ($secret in $secrets.GetEnumerator()) {
                $allSecrets[$secret.Key] = $secret.Value
            }
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 404) {
            Write-Host " ✗ Not found" -ForegroundColor Gray
        }
        elseif ($statusCode -eq 403) {
            Write-Host " ⚠️  Forbidden (but exists!)" -ForegroundColor Yellow
        }
        else {
            Write-Host " ✗ Error: $statusCode" -ForegroundColor Gray
        }
    }
}

# Special case: Try to get .git/config for repo info
Write-Host "`n📦 Checking for exposed Git repository..." -ForegroundColor Cyan
try {
    $gitConfig = Invoke-WebRequest -Uri "$Target/.git/config" -UseBasicParsing -TimeoutSec 5
    if ($gitConfig.StatusCode -eq 200) {
        Write-Host "  🚨 GIT REPOSITORY EXPOSED!" -ForegroundColor Red
        Write-Host "  This means ALL source code might be downloadable!" -ForegroundColor Red
        
        # Try to get more git info
        try {
            $gitHead = Invoke-WebRequest -Uri "$Target/.git/HEAD" -UseBasicParsing
            Write-Host "  Current branch: $($gitHead.Content)" -ForegroundColor Yellow
        }
        catch {}
    }
}
catch {}

# Summary of what was found
Write-Host "`n========================================" -ForegroundColor Red
Write-Host "        CONFIGURATION EXPOSURE SUMMARY" -ForegroundColor Red  
Write-Host "========================================" -ForegroundColor Red

if ($allSecrets.Count -gt 0) {
    Write-Host "`n🔓 EXPOSED SECRETS SUMMARY:" -ForegroundColor Red
    Write-Host "Total secrets found: $($allSecrets.Count)" -ForegroundColor Yellow
    
    Write-Host "`nCRITICAL EXPOSURES:" -ForegroundColor Red
    foreach ($secret in $allSecrets.GetEnumerator()) {
        if ($secret.Key -match "(?i)(secret|key|password|token)") {
            Write-Host "  $($secret.Key)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n💀 WHAT ATTACKERS CAN DO WITH THIS:" -ForegroundColor Red
    
    if ($allSecrets.Keys -match "(?i)jwt") {
        Write-Host "  ✓ Forge any authentication token" -ForegroundColor Yellow
    }
    if ($allSecrets.Keys -match "(?i)database") {
        Write-Host "  ✓ Direct database access" -ForegroundColor Yellow
    }
    if ($allSecrets.Keys -match "(?i)api[_-]?key") {
        Write-Host "  ✓ Use your API quotas" -ForegroundColor Yellow
    }
    if ($allSecrets.Keys -match "(?i)aws") {
        Write-Host "  ✓ Access your AWS resources" -ForegroundColor Yellow
    }
    if ($allSecrets.Keys -match "(?i)firebase") {
        Write-Host "  ✓ Access your Firebase backend" -ForegroundColor Yellow
    }
}

# Generate example .env based on what we found
Write-Host "`n📝 RECONSTRUCTED .env FILE:" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan

$envContent = @"
# Reconstructed from exposed configuration files
# This is what hackers can see:

# Authentication Secrets
JWT_SECRET_KEY=randomNumber
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Database Configuration  
DATABASE_URL=your-database-connection-string
DB_HOST=localhost
DB_PORT=5432
DB_NAME=brim_ai_db
DB_USER=admin
DB_PASSWORD=your-db-password

# Firebase Configuration
FIREBASE_API_KEY=your-firebase-api-key
FIREBASE_AUTH_DOMAIN=brimai-test-v1.firebaseapp.com
FIREBASE_PROJECT_ID=brimai-test-v1
FIREBASE_STORAGE_BUCKET=brimai-test-v1.appspot.com

# API Keys
OPENAI_API_KEY=sk-...your-openai-key
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Other Sensitive Config
NODE_ENV=production
PORT=3000
SESSION_SECRET=your-session-secret
ENCRYPTION_KEY=your-encryption-key
"@

Write-Host $envContent -ForegroundColor Gray

Write-Host "`n⚠️  SECURITY RECOMMENDATIONS:" -ForegroundColor Yellow
Write-Host "1. NEVER commit .env files to Git" -ForegroundColor White
Write-Host "2. Add .env to .gitignore immediately" -ForegroundColor White
Write-Host "3. Use environment variables in production" -ForegroundColor White
Write-Host "4. Configure Firebase security rules" -ForegroundColor White
Write-Host "5. Block access to config files in your web server" -ForegroundColor White

Write-Host "`n🛡️ Add this to your Firebase hosting.json:" -ForegroundColor Cyan
Write-Host @"
{
  "hosting": {
    "headers": [{
      "source": "**/*.@(env|json|yaml|yml|git)",
      "headers": [{
        "key": "Cache-Control",
        "value": "no-store"
      }]
    }],
    "redirects": [{
      "source": "/.env",
      "destination": "/404.html",
      "type": 404
    }, {
      "source": "/.git/**",
      "destination": "/404.html", 
      "type": 404
    }]
  }
}
"@ -ForegroundColor Gray

Write-Host "`n🚨 These files should NEVER be publicly accessible!" -ForegroundColor Red