# PowerShell script to download Material Design icons for Ducky AI
# This script downloads modern icons from Material Design Icons GitHub repository

# Create a temporary folder for downloads
$tempFolder = ".\temp_icons"
New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null

# Target folder for icons
$targetFolder = ".\static\images"

# Define icon URLs - using Material Design Icons GitHub
$iconUrls = @{
    "memories" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/bookmark/materialicons/48dp/2x/baseline_bookmark_black_48dp.png"
    "theme" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/image/brightness_6/materialicons/48dp/2x/baseline_brightness_6_black_48dp.png"
    "clear-chat" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/content/clear/materialicons/48dp/2x/baseline_clear_black_48dp.png"
    "share" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/social/share/materialicons/48dp/2x/baseline_share_black_48dp.png"
    "notifications" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/social/notifications/materialicons/48dp/2x/baseline_notifications_black_48dp.png"
    "logout" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/logout/materialicons/48dp/2x/baseline_logout_black_48dp.png"
}

# Download icons
Write-Host "Downloading icons..." -ForegroundColor Cyan
foreach ($icon in $iconUrls.GetEnumerator()) {
    $iconName = $icon.Name
    $iconUrl = $icon.Value
    $tempPath = Join-Path -Path $tempFolder -ChildPath "$iconName.png"
    
    try {
        Write-Host "Downloading $iconName icon..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $iconUrl -OutFile $tempPath
        
        # Rename and move to the target folder with appropriate names
        switch ($iconName) {
            "memories" { Copy-Item -Path $tempPath -Destination "$targetFolder\mem.icon.png" -Force }
            "theme" { Copy-Item -Path $tempPath -Destination "$targetFolder\theme.icon.png" -Force }
            "clear-chat" { Copy-Item -Path $tempPath -Destination "$targetFolder\del-chat.icon.png" -Force }
            "share" { Copy-Item -Path $tempPath -Destination "$targetFolder\share-chat.png" -Force }
            "notifications" { Copy-Item -Path $tempPath -Destination "$targetFolder\notif.icon.png" -Force }
            "logout" { Copy-Item -Path $tempPath -Destination "$targetFolder\logout.icon.png" -Force }
        }
        
        Write-Host "$iconName icon downloaded and saved successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to download $iconName icon: $_" -ForegroundColor Red
    }
}

# Clean up temporary files
Remove-Item -Path $tempFolder -Recurse -Force

Write-Host "Icon download complete. New icons are in $targetFolder" -ForegroundColor Cyan 