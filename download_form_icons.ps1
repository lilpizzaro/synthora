# PowerShell script to download form icons for Ducky AI
# This script downloads icons for the login/signup forms

# Create a temporary folder for downloads
$tempFolder = ".\temp_icons"
New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null

# Target folder for icons
$targetFolder = ".\static\images"
New-Item -ItemType Directory -Force -Path $targetFolder | Out-Null

# Define icon URLs - using Material Design Icons
$iconUrls = @{
    "user" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/social/person/materialicons/24dp/2x/baseline_person_black_24dp.png"
    "lock" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/lock/materialicons/24dp/2x/baseline_lock_black_24dp.png"
    "eye" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/visibility/materialicons/24dp/2x/baseline_visibility_black_24dp.png"
    "eye-off" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/visibility_off/materialicons/24dp/2x/baseline_visibility_off_black_24dp.png"
    "camera" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/image/camera_alt/materialicons/24dp/2x/baseline_camera_alt_black_24dp.png"
}

# Download icons
Write-Host "Downloading form icons..." -ForegroundColor Cyan
foreach ($icon in $iconUrls.GetEnumerator()) {
    $iconName = $icon.Name
    $iconUrl = $icon.Value
    $tempPath = Join-Path -Path $tempFolder -ChildPath "$iconName.png"
    
    try {
        Write-Host "Downloading $iconName icon..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $iconUrl -OutFile $tempPath
        
        # Move to the target folder with appropriate names
        Copy-Item -Path $tempPath -Destination "$targetFolder\$iconName.icon.png" -Force
        
        Write-Host "$iconName icon downloaded and saved successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to download $iconName icon: $_" -ForegroundColor Red
    }
}

# Clean up temporary files
Remove-Item -Path $tempFolder -Recurse -Force

Write-Host "Form icon download complete. New icons are in $targetFolder" -ForegroundColor Cyan 