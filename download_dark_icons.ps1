# PowerShell script to download WHITE Material Design icons for Ducky AI dark mode
# This script downloads white icons from Material Design Icons GitHub repository

# Create a temporary folder for downloads
$tempFolder = ".\temp_icons_dark"
New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null

# Target folder for dark mode icons
$targetFolder = ".\static\images\dark"
New-Item -ItemType Directory -Force -Path $targetFolder | Out-Null

# Define icon URLs - using Material Design Icons GitHub (white versions)
$iconUrls = @{
    "memories" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/bookmark/materialiconstwotone/48dp/2x/twotone_bookmark_white_48dp.png"
    "theme" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/image/brightness_6/materialiconstwotone/48dp/2x/twotone_brightness_6_white_48dp.png"
    "clear-chat" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/content/clear/materialiconstwotone/48dp/2x/twotone_clear_white_48dp.png"
    "share" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/social/share/materialiconstwotone/48dp/2x/twotone_share_white_48dp.png"
    "notifications" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/social/notifications/materialiconstwotone/48dp/2x/twotone_notifications_white_48dp.png"
    "logout" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/logout/materialiconstwotone/48dp/2x/twotone_logout_white_48dp.png"
    "settings" = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/settings/materialiconstwotone/48dp/2x/twotone_settings_white_48dp.png"
}

# Download icons
Write-Host "Downloading dark mode icons..." -ForegroundColor Cyan
foreach ($icon in $iconUrls.GetEnumerator()) {
    $iconName = $icon.Name
    $iconUrl = $icon.Value
    $tempPath = Join-Path -Path $tempFolder -ChildPath "$iconName.png"
    
    try {
        Write-Host "Downloading $iconName dark icon..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $iconUrl -OutFile $tempPath
        
        # Rename and move to the target folder with appropriate names
        switch ($iconName) {
            "memories" { Copy-Item -Path $tempPath -Destination "$targetFolder\mem.icon.png" -Force }
            "theme" { Copy-Item -Path $tempPath -Destination "$targetFolder\theme.icon.png" -Force }
            "clear-chat" { Copy-Item -Path $tempPath -Destination "$targetFolder\del-chat.icon.png" -Force }
            "share" { Copy-Item -Path $tempPath -Destination "$targetFolder\share-chat.png" -Force }
            "notifications" { Copy-Item -Path $tempPath -Destination "$targetFolder\notif.icon.png" -Force }
            "logout" { Copy-Item -Path $tempPath -Destination "$targetFolder\logout.icon.png" -Force }
            "settings" { Copy-Item -Path $tempPath -Destination "$targetFolder\settings.icon.png" -Force }
        }
        
        Write-Host "$iconName dark icon downloaded and saved successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to download $iconName dark icon: $_" -ForegroundColor Red
    }
}

# Also download the regular (black) settings icon for light mode
try {
    Write-Host "Downloading settings icon for light mode..." -ForegroundColor Yellow
    $settingsLightUrl = "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/settings/materialicons/48dp/2x/baseline_settings_black_48dp.png"
    $tempPath = Join-Path -Path $tempFolder -ChildPath "settings.png"
    Invoke-WebRequest -Uri $settingsLightUrl -OutFile $tempPath
    Copy-Item -Path $tempPath -Destination ".\static\images\settings.icon.png" -Force
    Write-Host "Settings light icon downloaded and saved successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to download settings light icon: $_" -ForegroundColor Red
}

# Clean up temporary files
Remove-Item -Path $tempFolder -Recurse -Force

Write-Host "Dark mode icon download complete. New icons are in $targetFolder" -ForegroundColor Cyan 