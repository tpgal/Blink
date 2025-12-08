#######################################################################################################################
#
# Author: Nayrk
# Date: 12/28/2018
# Last Updated: 12/07/2025
# Purpose: To download all Blink videos locally to the PC. Existing videos will be skipped.
# Output: All Blink videos downloaded in the following directory format.
#         Default Location Desktop - "C:\temp\Blink"
#         Sub-Folders - Blink --> Home Network Name --> Camera Name #1
#                                                   --> Camera Name #2
#
# Notes: You can change anything below this section.
# Credits: https://github.com/MattTW/BlinkMonitorProtocol
# Fixed By: colinreid89 on 05/15/2020
# Fixed By: tyuhas on 02/03/2021
# Fixed By: ttteee90 on 03/19/2021
# Fixed By: tpgal on 11/23/2025 - OAuth2 migration fix
# Fixed By: tpgal on 12/07/2025 - New OAuth2 with PKCE Authorization Code Flow
#             Solution based on blinkpy's OAuth2 implementation (https://github.com/fronzbot/blinkpy)
#             Adapted to PowerShell by Claude Sonnet 4.5 (Anthropic)
#             Analysis and debugging with user collaboration
# Updates: Added infinite loop to re-run every 30 minutes as a keep alive to bypass pin prompt from Blink/Amazon
#          03/22/2021 - Cleaned up the code and added more debug messages. Added try/catch on invalid pin.
#          11/23/2025 - Migrated to OAuth2 authentication endpoint with automatic token refresh and 2FA support
#          11/30/2025 - Updated to download thumbnails getting url from the homescreen endpoint
#          12/07/2025 - Updated to support PKCE
#######################################################################################################################

# Change saveDirectory directory if you want the Blink Files to be saved somewhere else, default is user Desktop
#$saveDirectory = "C:\Users\$env:UserName\Desktop"
$saveDirectory = "C:\temp\Blink"

# Blink Credentials. Please fill in!
# Please keep the quotation marks "
$email = "Your Email Here"
$password = "Your Password Here"

# Blink's API Server
$blinkAPIServer = 'rest-prod.immedia-semi.com'

# Use this server below if you are in Germany. Remove the # symbol below.
# $blinkAPIServer = 'prde.immedia-semi.com'

# OAuth v2 Constants
$oauthBaseUrl = 'https://api.oauth.blink.com'
$oauthClientId = 'ios'
$oauthScope = 'client'
$oauthRedirectUri = 'immedia-blink://applinks.blink.com/signin/callback'

# User-Agents (simulating iOS Safari)
$oauthUserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1'
$oauthTokenUserAgent = 'Blink/2511191620 CFNetwork/3860.200.71 Darwin/25.1.0'

#######################################################################################################################
#
# Do not change anything below unless you know what you are doing or you want to...
#
#######################################################################################################################

if($email -eq "Your Email Here") { Write-Host 'Please enter your email by modifying the line: $email = "Your Email Here"'; pause; exit;}
if($password -eq "Your Password Here") { Write-Host 'Please enter your password by modifying the line: $password = "Your Password Here"'; pause; exit;}

#Load System.Web for URL encoding
Add-Type -AssemblyName System.Web

# Global variables for token management
$script:authToken = $null
$script:refreshToken = $null
$script:tokenExpirationTime = $null
$script:region = $null
$script:accountID = $null
$script:hardwareId = [guid]::NewGuid().ToString().ToUpper()

# Function to generate PKCE pair
function New-PKCEPair {
    # Generate code_verifier (43-128 characters, URL-safe base64)
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $codeVerifier = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    # Generate code_challenge (SHA256 hash of verifier, URL-safe base64)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $challengeBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))
    $codeChallenge = [Convert]::ToBase64String($challengeBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    
    return @{
        Verifier = $codeVerifier
        Challenge = $codeChallenge
    }
}

# Function to extract CSRF token from HTML
function Get-CSRFToken {
    param([string]$Html)
    
    # Extract CSRF token from oauth-args script tag
    if ($Html -match '<script[^>]*id="oauth-args"[^>]*type="application/json"[^>]*>(.*?)</script>') {
        $jsonContent = $Matches[1]
        try {
            $oauthData = $jsonContent | ConvertFrom-Json
            return $oauthData.'csrf-token'
        } catch {
            Write-Host "Failed to parse OAuth args JSON" -ForegroundColor Red
        }
    }
    return $null
}

# Step 1: OAuth Authorization Request
function Invoke-OAuthAuthorize {
    param($CodeChallenge)
    
    $params = @{
        'app_brand' = 'blink'
        'app_version' = '50.1'
        'client_id' = $oauthClientId
        'code_challenge' = $CodeChallenge
        'code_challenge_method' = 'S256'
        'device_brand' = 'Apple'
        'device_model' = 'iPhone16,1'
        'device_os_version' = '26.1'
        'hardware_id' = $script:hardwareId
        'redirect_uri' = $oauthRedirectUri
        'response_type' = 'code'
        'scope' = $oauthScope
    }
    
    $queryString = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
    $url = "$oauthBaseUrl/oauth/v2/authorize?$queryString"
    
    $headers = @{
        'User-Agent' = $oauthUserAgent
        'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        'Accept-Language' = 'en-US,en;q=0.9'
    }
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method Get -Headers $headers -SessionVariable 'oauthSession' -UseBasicParsing -ErrorAction Stop
        $script:oauthSession = $oauthSession
        return $response.StatusCode -eq 200
    } catch {
        Write-Host "OAuth Authorization failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Step 2: Get Signin Page and Extract CSRF Token
function Get-SigninPageCSRF {
    $url = "$oauthBaseUrl/oauth/v2/signin"
    
    $headers = @{
        'User-Agent' = $oauthUserAgent
        'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        'Accept-Language' = 'en-US,en;q=0.9'
    }
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method Get -Headers $headers -WebSession $script:oauthSession -UseBasicParsing -ErrorAction Stop
        $csrfToken = Get-CSRFToken -Html $response.Content
        return $csrfToken
    } catch {
        Write-Host "Failed to get signin page: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Step 3: Submit Login Credentials
function Submit-LoginCredentials {
    param(
        [string]$CsrfToken
    )
    
    $url = "$oauthBaseUrl/oauth/v2/signin"
    
    $headers = @{
        'User-Agent' = $oauthUserAgent
        'Accept' = '*/*'
        'Content-Type' = 'application/x-www-form-urlencoded'
        'Origin' = $oauthBaseUrl
        'Referer' = "$oauthBaseUrl/oauth/v2/signin"
    }
    
    $body = @{
        'username' = $email
        'password' = $password
        'csrf-token' = $CsrfToken
    }
    
    $bodyString = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -Body $bodyString -WebSession $script:oauthSession -MaximumRedirection 0 -ErrorAction SilentlyContinue
        
        # Check status code
        if ($response.StatusCode -eq 412) {
            return "2FA_REQUIRED"
        } elseif ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
            return "SUCCESS"
        }
        
        return $null
    } catch {
        # PowerShell treats 3xx as errors if MaximumRedirection=0
        if ($_.Exception.Response.StatusCode.Value__ -in @(301, 302, 303, 307, 308)) {
            return "SUCCESS"
        } elseif ($_.Exception.Response.StatusCode.Value__ -eq 412) {
            return "2FA_REQUIRED"
        }
        
        Write-Host "Login submission failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Step 3b: Verify 2FA Code
function Submit-2FACode {
    param(
        [string]$CsrfToken,
        [string]$TwoFactorCode
    )
    
    $url = "$oauthBaseUrl/oauth/v2/2fa/verify"
    
    $headers = @{
        'User-Agent' = $oauthUserAgent
        'Accept' = '*/*'
        'Content-Type' = 'application/x-www-form-urlencoded'
        'Origin' = $oauthBaseUrl
        'Referer' = "$oauthBaseUrl/oauth/v2/signin"
    }
    
    $body = @{
        '2fa_code' = $TwoFactorCode
        'csrf-token' = $CsrfToken
        'remember_me' = 'false'
    }
    
    $bodyString = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $bodyString -WebSession $script:oauthSession -ErrorAction Stop
        return $response.status -eq "auth-completed"
    } catch {
        Write-Host "2FA verification failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Step 4: Get Authorization Code
function Get-AuthorizationCode {
    $url = "$oauthBaseUrl/oauth/v2/authorize"
    
    $headers = @{
        'User-Agent' = $oauthUserAgent
        'Accept' = '*/*'
        'Referer' = "$oauthBaseUrl/oauth/v2/signin"
    }
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method Get -Headers $headers -WebSession $script:oauthSession -MaximumRedirection 0 -ErrorAction SilentlyContinue
        
        # Should redirect to blink://... with code parameter
        if ($response.Headers.Location) {
            $location = $response.Headers.Location
            if ($location -match '[?&]code=([^&]+)') {
                return $Matches[1]
            }
        }
        
        return $null
    } catch {
        # Check redirect location in exception
        if ($_.Exception.Response.Headers.Location) {
            $location = $_.Exception.Response.Headers.Location.ToString()
            if ($location -match '[?&]code=([^&]+)') {
                return $Matches[1]
            }
        }
        
        Write-Host "Failed to get authorization code: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Step 5: Exchange Code for Token
function Get-AccessToken {
    param(
        [string]$Code,
        [string]$CodeVerifier
    )
    
    $url = "$oauthBaseUrl/oauth/token"
    
    $headers = @{
        'User-Agent' = $oauthTokenUserAgent
        'Content-Type' = 'application/x-www-form-urlencoded'
        'Accept' = '*/*'
    }
    
    $body = @{
        'app_brand' = 'blink'
        'client_id' = $oauthClientId
        'code' = $Code
        'code_verifier' = $CodeVerifier
        'grant_type' = 'authorization_code'
        'hardware_id' = $script:hardwareId
        'redirect_uri' = $oauthRedirectUri
        'scope' = $oauthScope
    }
    
    $bodyString = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $bodyString -ErrorAction Stop
        return $response
    } catch {
        Write-Host "Failed to exchange code for token: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Complete OAuth Flow
function Invoke-OAuthLogin {
    echo "Starting OAuth2 login flow with PKCE..."
    
    # Step 1: Generate PKCE pair
    echo "Generating PKCE pair..."
    $pkce = New-PKCEPair
    
    # Step 2: Authorization request
    echo "Sending authorization request..."
    if (-not (Invoke-OAuthAuthorize -CodeChallenge $pkce.Challenge)) {
        Write-Host "Authorization request failed" -ForegroundColor Red
        return $null
    }
    
    # Step 3: Get CSRF token
    echo "Getting CSRF token..."
    $csrfToken = Get-SigninPageCSRF
    if (-not $csrfToken) {
        Write-Host "Failed to get CSRF token" -ForegroundColor Red
        return $null
    }
    
    # Step 4: Submit login
    echo "Submitting credentials..."
    $loginResult = Submit-LoginCredentials -CsrfToken $csrfToken
    
    # Step 4b: Handle 2FA if needed
    if ($loginResult -eq "2FA_REQUIRED") {
        Write-Host "`nTwo-factor authentication required." -ForegroundColor Yellow
        Write-Host "Please check your email or SMS for the 2FA code." -ForegroundColor Yellow
        $twoFactorCode = Read-Host -Prompt "Enter your 2FA code"
        
        echo "Verifying 2FA code..."
        if (-not (Submit-2FACode -CsrfToken $csrfToken -TwoFactorCode $twoFactorCode)) {
            Write-Host "2FA verification failed" -ForegroundColor Red
            return $null
        }
    } elseif ($loginResult -ne "SUCCESS") {
        Write-Host "Login failed" -ForegroundColor Red
        return $null
    }
    
    # Step 5: Get authorization code
    echo "Getting authorization code..."
    $code = Get-AuthorizationCode
    if (-not $code) {
        Write-Host "Failed to get authorization code" -ForegroundColor Red
        return $null
    }
    
    # Step 6: Exchange code for token
    echo "Exchanging code for access token..."
    $tokenData = Get-AccessToken -Code $code -CodeVerifier $pkce.Verifier
    if (-not $tokenData) {
        Write-Host "Failed to get access token" -ForegroundColor Red
        return $null
    }
    
    return $tokenData
}

# Function to refresh token
function Update-AuthToken {
    if ($script:refreshToken) {
        echo "Refreshing access token..."
        
        $url = "$oauthBaseUrl/oauth/token"
        
        $headers = @{
            'User-Agent' = $oauthTokenUserAgent
            'Content-Type' = 'application/x-www-form-urlencoded'
            'Accept' = '*/*'
        }
        
        $body = @{
            'grant_type' = 'refresh_token'
            'refresh_token' = $script:refreshToken
            'client_id' = $oauthClientId
            'scope' = $oauthScope
            'hardware_id' = $script:hardwareId
        }
        
        $bodyString = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
        
        try {
            $tokenData = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $bodyString -ErrorAction Stop
            
            $script:authToken = $tokenData.access_token
            $script:refreshToken = $tokenData.refresh_token
            
            $currentTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
            $script:tokenExpirationTime = $currentTime + $tokenData.expires_in
            
            echo "Token refreshed successfully"
            return $true
        } catch {
            Write-Host "Token refresh failed: $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }
    return $false
}

# Function to check if token needs refresh
function Test-TokenNeedsRefresh {
    if ($null -eq $script:tokenExpirationTime) {
        return $true
    }
    
    $currentTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
    $timeUntilExpiration = $script:tokenExpirationTime - $currentTime
    
    # Refresh if less than 5 minutes (300 seconds) until expiration
    return $timeUntilExpiration -lt 300
}

# Function to get current auth headers (always fresh)
function Get-AuthHeaders {
    if (Test-TokenNeedsRefresh) {
        if (-not (Update-AuthToken)) {
            Write-Host "Warning: Unable to refresh token" -ForegroundColor Yellow
        }
    }
    
    return @{
        "Authorization" = "Bearer $script:authToken"
        "Content-Type" = "application/json"
    }
}

# Perform OAuth login
$tokenData = Invoke-OAuthLogin

if (-not $tokenData) {
    Write-Host "Login failed. Exiting." -ForegroundColor Red
    pause
    exit
}

# Extract tokens
$script:authToken = $tokenData.access_token
$script:refreshToken = $tokenData.refresh_token
$expiresIn = $tokenData.expires_in

$currentTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$script:tokenExpirationTime = $currentTime + $expiresIn

echo "`nLogin successful!"
echo "Access token obtained (expires in $expiresIn seconds)"

# Get tier information
$tierUri = "https://$blinkAPIServer/api/v1/users/tier_info"
$tierHeaders = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $script:authToken"
}

try {
    $tierResponse = Invoke-RestMethod -UseBasicParsing $tierUri -Method Get -Headers $tierHeaders -ErrorAction Stop
    $script:region = $tierResponse.tier
    $script:accountID = $tierResponse.account_id
    echo "Region: $script:region, Account ID: $script:accountID"
} catch {
    Write-Host "Failed to get tier info" -ForegroundColor Red
    pause
    exit
}

# Main download loop
while (1)
{
    echo "`nStarting download cycle..."
    
    # Get homescreen info - single endpoint with all camera and network data
    $homescreenUri = "https://rest-$script:region.immedia-semi.com/api/v3/accounts/$script:accountID/homescreen"
    $homescreen = Invoke-RestMethod -UseBasicParsing $homescreenUri -Method Get -Headers (Get-AuthHeaders)
    
    # Build network name lookup dictionary
    $networkNames = @{}
    foreach($network in $homescreen.networks) {
        $networkNames[$network.id] = $network.name
    }
    
    # Process each camera directly from homescreen
    foreach($camera in $homescreen.cameras) {
        $cameraId = $camera.id
        $cameraName = $camera.name
        $networkId = $camera.network_id
        $thumbnailPath = $camera.thumbnail
        
        # Get network name from lookup
        $networkName = $networkNames[$networkId]
        if (-not $networkName) {
            $networkName = "Unknown_Network_$networkId"
        }
        
        # Create Blink Directory to store videos if it doesn't exist
        $path = "$saveDirectory\Blink\$networkName\$cameraName"
        if (-not (Test-Path $path)){
            $folder = New-Item  -ItemType Directory -Path $path
        }

        # Download camera thumbnail if available
        if ($thumbnailPath) {
            # Build full URL
            $thumbURL = "https://rest-$script:region.immedia-semi.com$thumbnailPath"
            
            # Extract timestamp from URL for filename
            if ($thumbnailPath -match 'ts=(\d+)') {
                $timestamp = $Matches[1]
                $thumbFilename = "thumbnail_$timestamp.jpg"
            } else {
                $thumbFilename = "thumbnail_latest.jpg"
            }
            
            $thumbPath = "$path\$thumbFilename"
            
            # Skip if already downloaded
            if (-not (Test-Path $thumbPath)){
                try {
                    Invoke-RestMethod -UseBasicParsing $thumbURL -Method Get -Headers (Get-AuthHeaders) -OutFile $thumbPath -ErrorAction Stop
                    echo "Downloaded thumbnail for $cameraName camera in $networkName."
                }
                catch {
                    # Silently skip thumbnails that no longer exist or are inaccessible
                }
            }
        }
    }
    
    # Download videos
    $pageNum = 1
    $videoCount = 0

    # Continue to download videos from each page until all are downloaded
    while ( 1 )
    {
        # Get media list with fresh headers
        $uri = 'https://rest-'+ $script:region +'.immedia-semi.com/api/v1/accounts/'+ $script:accountID +'/media/changed?since=2015-04-19T23:11:20+0000&page=' + $pageNum
        $response = Invoke-RestMethod -UseBasicParsing $uri -Method Get -Headers (Get-AuthHeaders)
        
        # No more videos to download, exit from loop
        if(-not $response.media){
            break
        }

        # Go through each video information and get the download link and relevant information
        foreach($video in $response.media){
            # Video clip information
            $address = $video.media
            $timestamp = $video.created_at
            $network = $video.network_name
            $camera = $video.device_name
            $deleted = $video.deleted
            if($deleted -eq "True"){
                continue
            }
           
            # Get video timestamp in local time
            $videoTime = Get-Date -Date $timestamp -Format "yyyy-MM-dd_HH-mm-ss"

            # Download address of video clip
            $videoURL = 'https://rest-'+ $script:region +'.immedia-semi.com' + $address
            
            # Download video if it is new
            $path = "$saveDirectory\Blink\$network\$camera"
            $videoPath = "$path\$videoTime.mp4"
            if (-not (Test-Path $videoPath)){
                try {
                    # Use fresh headers for each video download
                    Invoke-RestMethod -UseBasicParsing $videoURL -Method Get -Headers (Get-AuthHeaders) -OutFile $videoPath 
					$httpCode = $_.Exception.Response.StatusCode.value__		
					if($httpCode -ne 404){
						echo "Downloading video for $camera camera in $network."
						$videoCount++
					}   
				} catch { 
					# Left empty to prevent spam when video file no longer exists
					echo $httpCode
                }
            }
        }
        $pageNum += 1
    }
    
    if ($videoCount -gt 0) {
        echo "Downloaded $videoCount new videos in this cycle."
    }
    
	echo "All new videos and thumbnails downloaded to $saveDirectory\Blink\"
	echo "Sleeping for 30 minutes before next run..."
	# Sleep for 30 minutes
    Start-Sleep -S 1800
}
