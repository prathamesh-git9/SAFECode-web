# SAFECode-Web Version Manager
# This script allows you to easily switch between different versions

param(
    [Parameter(Mandatory=$false)]
    [string]$Action = "list",
    [Parameter(Mandatory=$false)]
    [string]$Version = ""
)

function Show-VersionList {
    Write-Host "Available Versions:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    # Get all tags
    $tags = git tag --sort=-version:refname
    $currentBranch = git branch --show-current
    
    foreach ($tag in $tags) {
        $tagDate = git log -1 --format="%ad" --date=short $tag
        $tagMessage = git tag -l --format='%(contents:subject)' $tag
        
        if ($tag -eq $currentBranch) {
            Write-Host "  * $tag ($tagDate)" -ForegroundColor Green
        } else {
            Write-Host "    $tag ($tagDate)" -ForegroundColor White
        }
        Write-Host "    $tagMessage" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "Current branch: $currentBranch" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\version_manager.ps1 list                    # List all versions"
    Write-Host "  .\version_manager.ps1 switch v1.0             # Switch to v1.0"
    Write-Host "  .\version_manager.ps1 switch v2.0             # Switch to v2.0"
    Write-Host "  .\version_manager.ps1 switch main             # Switch to main branch"
    Write-Host "  .\version_manager.ps1 create v2.1 'message'   # Create new version"
}

function Switch-Version {
    param([string]$Version)
    
    Write-Host "Switching to version: $Version" -ForegroundColor Yellow
    
    # Check if version exists
    if ($Version -eq "main") {
        git checkout main
    } else {
        $tagExists = git tag -l $Version
        if (-not $tagExists) {
            Write-Host "Error: Version '$Version' not found!" -ForegroundColor Red
            Write-Host "Available versions:" -ForegroundColor Yellow
            git tag --sort=-version:refname
            return
        }
        git checkout $Version
    }
    
    Write-Host "Successfully switched to $Version" -ForegroundColor Green
    Write-Host ""
    Write-Host "To start the application:" -ForegroundColor Cyan
    Write-Host "  .\start_backend.bat" -ForegroundColor White
    Write-Host "  or" -ForegroundColor Gray
    Write-Host "  .\start_backend.ps1" -ForegroundColor White
}

function Create-Version {
    param([string]$Version, [string]$Message)
    
    if (-not $Message) {
        $Message = "Version $Version"
    }
    
    Write-Host "Creating new version: $Version" -ForegroundColor Yellow
    Write-Host "Message: $Message" -ForegroundColor Gray
    
    # Check if we have uncommitted changes
    $status = git status --porcelain
    if ($status) {
        Write-Host "Warning: You have uncommitted changes!" -ForegroundColor Red
        Write-Host "Please commit or stash your changes before creating a new version." -ForegroundColor Yellow
        return
    }
    
    # Create tag
    git tag -a $Version -m $Message
    
    Write-Host "Version $Version created successfully!" -ForegroundColor Green
    Write-Host "To push the new version to remote:" -ForegroundColor Cyan
    Write-Host "  git push origin $Version" -ForegroundColor White
}

# Main script logic
switch ($Action.ToLower()) {
    "list" {
        Show-VersionList
    }
    "switch" {
        if (-not $Version) {
            Write-Host "Error: Please specify a version to switch to." -ForegroundColor Red
            Write-Host "Usage: .\version_manager.ps1 switch <version>" -ForegroundColor Yellow
            exit 1
        }
        Switch-Version $Version
    }
    "create" {
        if (-not $Version) {
            Write-Host "Error: Please specify a version name." -ForegroundColor Red
            Write-Host "Usage: .\version_manager.ps1 create <version> [message]" -ForegroundColor Yellow
            exit 1
        }
        Create-Version $Version $Message
    }
    default {
        Write-Host "Unknown action: $Action" -ForegroundColor Red
        Write-Host "Valid actions: list, switch, create" -ForegroundColor Yellow
        Show-VersionList
    }
}
