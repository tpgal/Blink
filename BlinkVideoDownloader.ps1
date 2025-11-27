#######################################################################################################################
#
# Author: Nayrk
# Date: 12/28/2018
# Last Updated: 11/23/2025
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
#             Solution based on blinkpy's OAuth2 implementation (https://github.com/fronzbot/blinkpy)
#             Adapted to PowerShell by Claude Sonnet 4.5 (Anthropic)
#             Analysis and debugging with user collaboration
# Updates: Added infinite loop to re-run every 30 minutes as a keep alive to bypass pin prompt from Blink/Amazon
#          03/22/2021 - Cleaned up the code and added more debug messages. Added try/catch on invalid pin.
#          11/23/2025 - Migrated to OAuth2 authentication endpoint with automatic token refresh and 2FA support
#######################################################################################################################

# Change saveDirectory directory if you want the Blink Files to be saved somewhere else, default is user Desktop
#$saveDirectory = "C:\Users\$env:UserName\Desktop"
$saveDirectory = "C:\temp\Blink"

# Blink Credentials. Please fill in!
# Please keep the quotation marks "
$email = "Your Email Here"
$password = "Your Password Here"

# Blink's API Server, this is the URL you are directed to when you are prompted for IFTTT Integration to "Grant Access"
# You can verify this yourself to make sure you are sending the data where you expect it to be
$blinkAPIServer = 'rest-prod.immedia-semi.com'

# Use this server below if you are in Germany. Remove the # symbol below.
# $blinkAPIServer = 'prde.immedia-semi.com'

# OAuth Constants (New for 2025)
$oauthServer = 'api.oauth.blink.com'
$oauthClientId = 'android'
$oauthGrantType = 'password'
$oauthScope = 'client'

#######################################################################################################################
#
# Do not change anything below unless you know what you are doing or you want to...
#
#######################################################################################################################

if($email -eq "Your Email Here") { Write-Host 'Please enter your email by modifying the line: $email = "Your Email Here"'; pause; exit;}
if($password -eq "Your Password Here") { Write-Host 'Please enter your password by modifying the line: $password = "Your Password Here"'; pause; exit;}

# Function to URL-encode a string (compatible with all PowerShell versions)
function ConvertTo-UrlEncoded {
    param([string]$Value)
    
    # Character map for URL encoding
    $urlEncoded = ""
    foreach ($char in $Value.ToCharArray()) {
        $ascii = [int][char]$char
        
        # Check if character needs encoding
        if (($ascii -ge 48 -and $ascii -le 57) -or   # 0-9
            ($ascii -ge 65 -and $ascii -le 90) -or   # A-Z
            ($ascii -ge 97 -and $ascii -le 122) -or  # a-z
            $char -eq '-' -or $char -eq '_' -or 
            $char -eq '.' -or $char -eq '~') {
            $urlEncoded += $char
        } else {
            # Encode the character as %XX
            $urlEncoded += '%' + ([System.String]::Format("{0:X2}", $ascii))
        }
    }
    return $urlEncoded
}

# Global variables for token management
$script:authToken = $null
$script:refreshToken = $null
$script:tokenExpirationTime = $null
$script:region = $null
$script:accountID = $null
$script:lastTokenCheck = 0

# Function to perform OAuth login
function Invoke-BlinkLogin {
    param(
        [string]$TwoFactorCode = $null,
        [switch]$IsRefresh = $false
    )
    
    # Headers for OAuth login
    $loginHeaders = @{
        "Content-Type" = "application/x-www-form-urlencoded"
        "User-Agent" = "Blinkpy/0.22.0"
        "hardware_id" = "Blinkpy"
    }
    
    # Add 2FA code to headers if provided
    if ($TwoFactorCode) {
        $loginHeaders["2fa-code"] = $TwoFactorCode
    }

    # Credential data in URL-encoded format
    if ($IsRefresh -and $script:refreshToken) {
        # Use refresh token for renewal
        $bodyParams = @{
            "grant_type" = "refresh_token"
            "refresh_token" = $script:refreshToken
            "client_id" = $oauthClientId
        }
    } else {
        # Use credentials for initial login
        $bodyParams = @{
            "username" = $email
            "password" = $password
            "grant_type" = $oauthGrantType
            "client_id" = $oauthClientId
            "scope" = $oauthScope
        }
    }

    # Convert to URL-encoded string
    $bodyString = ($bodyParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$(ConvertTo-UrlEncoded $_.Value)" }) -join '&'

    # OAuth Login URL
    $loginUri = "https://$oauthServer/oauth/token"

    # Authenticate credentials with Blink OAuth Server
    try {
        $response = Invoke-RestMethod -UseBasicParsing $loginUri -Method Post -Headers $loginHeaders -Body $bodyString -ErrorAction Stop
        return @{
            Success = $true
            Response = $response
        }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__
        return @{
            Success = $false
            StatusCode = $statusCode
            Error = $_.Exception.Message
        }
    }
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

# Function to refresh authentication token
function Update-AuthToken {
    param(
        [switch]$Force = $false
    )
    
    if ($Force -or (Test-TokenNeedsRefresh)) {
        echo "Token expiring soon, refreshing authentication..."
        
        # Try to refresh using refresh_token first
        $refreshResult = Invoke-BlinkLogin -IsRefresh
        
        # If refresh fails, do a full re-login
        if (-not $refreshResult.Success) {
            echo "Refresh token failed, performing full re-authentication..."
            $refreshResult = Invoke-BlinkLogin
            
            # Check if 2FA is required
            if (-not $refreshResult.Success -and $refreshResult.StatusCode -eq 412) {
                Write-Host "Two-factor authentication required. Please check your email or SMS for the 2FA code."
                $twoFactorCode = Read-Host -Prompt "Enter your 2FA code"
                
                if (-not $twoFactorCode -or $twoFactorCode.Trim() -eq "") {
                    Write-Host "No 2FA code provided. Cannot refresh token."
                    return $false
                }
                
                $refreshResult = Invoke-BlinkLogin -TwoFactorCode $twoFactorCode
            }
        }
        
        if ($refreshResult.Success) {
            $response = $refreshResult.Response
            $script:authToken = $response.access_token
            $script:refreshToken = $response.refresh_token
            
            # Calculate expiration time (current time + expires_in)
            $currentTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
            $script:tokenExpirationTime = $currentTime + $response.expires_in
            $script:lastTokenCheck = $currentTime
            
            echo "Token refreshed successfully. Valid for $($response.expires_in) seconds."
            return $true
        } else {
            Write-Host "Failed to refresh token. Script may stop working."
            return $false
        }
    }
    return $true
}

# Function to get current auth headers (always fresh)
function Get-AuthHeaders {
    # Check token every time headers are requested
    if (-not (Update-AuthToken)) {
        Write-Host "Warning: Unable to refresh token, using potentially expired token."
    }
    
    return @{
        "Authorization" = "Bearer $script:authToken"
        "Content-Type" = "application/json"
    }
}

# Initial login attempt
echo "Performing initial authentication..."
$loginResult = Invoke-BlinkLogin

# Check if 2FA is required (HTTP 412)
if (-not $loginResult.Success -and $loginResult.StatusCode -eq 412) {
    Write-Host "Two-factor authentication required. Please check your email or SMS for the 2FA code."
    $twoFactorCode = Read-Host -Prompt "Enter your 2FA code"
    
    if (-not $twoFactorCode -or $twoFactorCode.Trim() -eq "") {
        Write-Host "No 2FA code provided. Exiting."
        pause
        exit
    }
    
    # Retry login with 2FA code
    $loginResult = Invoke-BlinkLogin -TwoFactorCode $twoFactorCode
}

# Check final login result
if (-not $loginResult.Success) {
    Write-Host "Login failed. Please verify your credentials and try again."
    pause
    exit
}

$response = $loginResult.Response

if(-not $response){
    echo "No response received from server."
    pause
    exit
}

# Extract OAuth token and set expiration time
$script:authToken = $response.access_token
$script:refreshToken = $response.refresh_token
$expiresIn = $response.expires_in

# Calculate expiration time
$currentTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$script:tokenExpirationTime = $currentTime + $expiresIn
$script:lastTokenCheck = $currentTime

if(-not $script:authToken) {
    Write-Host "Failed to obtain access token. Please try again."
    pause
    exit
}

$expirationDate = (Get-Date).AddSeconds($expiresIn)
echo "Access token obtained (valid for $expiresIn seconds, expires at $($expirationDate.ToString('HH:mm:ss')))"

# Get tier information
$tierUri = "https://$blinkAPIServer/api/v1/users/tier_info"
$tierHeaders = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $script:authToken"
    "User-Agent" = "Blinkpy/0.22.0"
}

try {
    $tierResponse = Invoke-RestMethod -UseBasicParsing $tierUri -Method Get -Headers $tierHeaders -ErrorAction Stop
} catch {
    Write-Host "Failed to get account information. Please try again."
    pause
    exit
}

# Extract tier data
$script:region = $tierResponse.tier
$script:accountID = $tierResponse.account_id

if(-not $script:region -or -not $script:accountID) {
    Write-Host "Failed to obtain account details. Please try again."
    pause
    exit
}

echo "Authenticated with Blink successfully (Region: $script:region, Account: $script:accountID)"

while (1)
{
	echo "`nStarting download cycle..."
	
	# Get list of networks (headers always fresh)
	$uri = 'https://rest-'+ $script:region +".immedia-semi.com/api/v1/camera/usage"
	$sync_units = Invoke-RestMethod -UseBasicParsing $uri -Method Get -Headers (Get-AuthHeaders)
	
	foreach($sync_unit in $sync_units.networks)
	{
		$network_id = $sync_unit.network_id
		$networkName = $sync_unit.name
		
		foreach($camera in $sync_unit.cameras){
			$cameraName = $camera.name
			$cameraId = $camera.id
			$uri = 'https://rest-'+ $script:region +".immedia-semi.com/network/$network_id/camera/$cameraId"
			
			# Get camera info with fresh headers
			$camera = Invoke-RestMethod -UseBasicParsing $uri -Method Get -Headers (Get-AuthHeaders)
			$cameraThumbnail = $camera.camera_status.thumbnail

			# Create Blink Directory to store videos if it doesn't exist
			$path = "$saveDirectory\Blink\$networkName\$cameraName"
			if (-not (Test-Path $path)){
				$folder = New-Item  -ItemType Directory -Path $path
			}

			# Download camera thumbnail
			$thumbURL = 'https://rest-'+ $script:region +'.immedia-semi.com' + $cameraThumbnail + ".jpg"
			$thumbPath = "$path\" + "thumbnail_" + $cameraThumbnail.Split("/")[-1] + ".jpg"
			
			# Skip if already downloaded
			if (-not (Test-Path $thumbPath)){
				echo "Downloading thumbnail for $cameraName camera in $networkName."
				Invoke-RestMethod -UseBasicParsing $thumbURL -Method Get -Headers (Get-AuthHeaders) -OutFile $thumbPath
			}
		}
	}

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
			$camera_id = $video.camera_id
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