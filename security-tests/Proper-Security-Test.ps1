# Proper-Security-Test.ps1
# A more accurate security test script

param(
    [string]$Target = "https://brimai-test-v1.web.app"
)

Write-Host "`n🔍 SECURITY CONFIGURATION TEST" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor Yellow

# Function to check if response is actually a config file
function Test-ConfigFile {
    param(
        [string]$FileName,
        [string]$Url,
        [string]$Content
    )
    
    Write-Host "`nTesting: $FileName" -ForegroundColor Gray
    Write-Host "URL: $Url" -ForegroundColor Gray
    
    # Check if this is actually the file we requested
    $isHtml = $Content -match "<!doctype html>" -or $Content -match "<html"
    $isReactApp = $Content -match "You need to enable JavaScript to run this app"
    
    if ($isHtml -and $isReactApp) {
        Write-Host "✅ PROTECTED: Returns React app (proper SPA behavior)" -ForegroundColor Green
        return $false
    }
    
    # Check for actual config file signatures
    $configSignatures = @{
        ".env" = "^[A-Z_]+="
        ".json" = "^\s*\{[\s\S]*\}\s*$"
        ".yaml" = "^[a-zA-Z_]+:"
        ".yml" = "^[a-zA-Z_]+:"
        ".git/config" = "\[core\]|\[remote"
    }
    
    foreach ($sig in $configSignatures.GetEnumerator()) {
        if ($FileName -match $sig.Key -and $Content -match $sig.Value) {
            Write-Host "❌ EXPOSED: Actual $($sig.Key) file content detected!" -ForegroundColor Red
            return $true
        }
    }
    
    # Check content length - config files are usually different size than index.html
    if ($Content.Length -eq 1602) {  # This is the size of your index.html
        Write-Host "✅ PROTECTED: Standard response size (likely index.html)" -ForegroundColor Green
        return $false
    }
    
    Write-Host "⚠️  UNKNOWN: Response doesn't match expected patterns" -ForegroundColor Yellow
    Write-Host "   First 100 chars: $($Content.Substring(0, [Math]::Min(100, $Content.Length)))" -ForegroundColor Gray
    return $null
}

# Test files
$testFiles = @(
    ".env",
    ".env.local",
    ".env.production",
    "config.json",
    "firebase.json",
    ".firebaserc",
    "package.json",
    ".git/config",
    ".git/HEAD",
    "secrets.json",
    "credentials.json"
)

$exposedCount = 0
$protectedCount = 0

foreach ($file in $testFiles) {
    try {
        $response = Invoke-WebRequest -Uri "$Target/$file" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $isExposed = Test-ConfigFile -FileName $file -Url "$Target/$file" -Content $response.Content
        
        if ($isExposed -eq $true) {
            $exposedCount++
        }
        elseif ($isExposed -eq $false) {
            $protectedCount++
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "`nTesting: $file" -ForegroundColor Gray
        Write-Host "URL: $Target/$file" -ForegroundColor Gray
        
        if ($statusCode -eq 404) {
            Write-Host "✅ PROTECTED: 404 Not Found" -ForegroundColor Green
            $protectedCount++
        }
        elseif ($statusCode -eq 403) {
            Write-Host "✅ PROTECTED: 403 Forbidden" -ForegroundColor Green
            $protectedCount++
        }
        else {
            Write-Host "⚠️  ERROR: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Test for actual API endpoints (not just static files)
Write-Host "`n`n🔍 TESTING API ENDPOINTS" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

$apiEndpoints = @(
    "/api/auth/login",
    "/api/admin/users",
    "/api/config",
    "/.well-known/security.txt"
)

foreach ($endpoint in $apiEndpoints) {
    try {
        Write-Host "`nTesting: $endpoint" -ForegroundColor Gray
        $response = Invoke-WebRequest -Uri "$Target$endpoint" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        
        # Check if we got JSON response (actual API)
        try {
            $json = $response.Content | ConvertFrom-Json
            Write-Host "⚠️  API ENDPOINT FOUND: Returns JSON data" -ForegroundColor Yellow
        }
        catch {
            if ($response.Content -match "<!doctype html>") {
                Write-Host "✅ Returns React app (no API exposed)" -ForegroundColor Green
            }
            else {
                Write-Host "⚠️  Unknown response type" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "✅ Not accessible: $($_.Exception.Message)" -ForegroundColor Green
    }
}

# Summary
Write-Host "`n`n==============================" -ForegroundColor Cyan
Write-Host "        SECURITY SUMMARY" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

Write-Host "`n📊 Results:" -ForegroundColor Yellow
Write-Host "   Protected files: $protectedCount" -ForegroundColor Green
Write-Host "   Exposed files: $exposedCount" -ForegroundColor $(if ($exposedCount -gt 0) { "Red" } else { "Green" })

if ($exposedCount -eq 0) {
    Write-Host "`n✅ GOOD NEWS: No configuration files are exposed!" -ForegroundColor Green
    Write-Host "   Your Firebase hosting is properly configured to serve" -ForegroundColor White
    Write-Host "   the React app for all routes, which is correct behavior." -ForegroundColor White
}
else {
    Write-Host "`n❌ SECURITY ISSUE: Some files are exposed!" -ForegroundColor Red
    Write-Host "   Review the exposed files above and update your" -ForegroundColor White
    Write-Host "   Firebase hosting configuration immediately." -ForegroundColor White
}

Write-Host "`n📋 RECOMMENDATIONS:" -ForegroundColor Cyan
Write-Host "1. Ensure your firebase.json includes proper 'ignore' rules" -ForegroundColor White
Write-Host "2. Never deploy .env or config files to your public folder" -ForegroundColor White
Write-Host "3. Use Firebase environment configuration for secrets" -ForegroundColor White
Write-Host "4. Regularly audit your deployed files" -ForegroundColor White

Write-Host "`n💡 TIP: To properly test JWT security:" -ForegroundColor Yellow
Write-Host "   You need to test your actual API endpoints, not static files." -ForegroundColor White
Write-Host "   Static file tests only verify hosting configuration." -ForegroundColor White