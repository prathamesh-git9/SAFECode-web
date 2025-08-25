@echo off
REM SAFECode-Web Version Manager (Batch Version)
REM This script allows you to easily switch between different versions

if "%1"=="" goto :list
if "%1"=="list" goto :list
if "%1"=="switch" goto :switch
if "%1"=="create" goto :create
goto :help

:list
echo Available Versions:
echo ==================
git tag --sort=-version:refname
echo.
echo Current branch: 
git branch --show-current
echo.
echo Usage:
echo   version_manager.bat list                    # List all versions
echo   version_manager.bat switch v1.0             # Switch to v1.0
echo   version_manager.bat switch v2.0             # Switch to v2.0
echo   version_manager.bat switch main             # Switch to main branch
echo   version_manager.bat create v2.1 "message"   # Create new version
goto :end

:switch
if "%2"=="" (
    echo Error: Please specify a version to switch to.
    echo Usage: version_manager.bat switch ^<version^>
    goto :end
)
echo Switching to version: %2
if "%2"=="main" (
    git checkout main
) else (
    git checkout %2
)
if %ERRORLEVEL% EQU 0 (
    echo Successfully switched to %2
    echo.
    echo To start the application:
    echo   start_backend.bat
    echo   or
    echo   start_backend.ps1
) else (
    echo Error: Version '%2' not found!
    echo Available versions:
    git tag --sort=-version:refname
)
goto :end

:create
if "%2"=="" (
    echo Error: Please specify a version name.
    echo Usage: version_manager.bat create ^<version^> [message]
    goto :end
)
echo Creating new version: %2
if "%3"=="" (
    git tag -a %2 -m "Version %2"
) else (
    git tag -a %2 -m "%3"
)
if %ERRORLEVEL% EQU 0 (
    echo Version %2 created successfully!
    echo To push the new version to remote:
    echo   git push origin %2
) else (
    echo Error creating version %2
)
goto :end

:help
echo SAFECode-Web Version Manager
echo ============================
echo.
echo Usage:
echo   version_manager.bat [command] [options]
echo.
echo Commands:
echo   list                    List all available versions
echo   switch ^<version^>        Switch to a specific version
echo   create ^<version^> [msg]  Create a new version tag
echo.
echo Examples:
echo   version_manager.bat list
echo   version_manager.bat switch v1.0
echo   version_manager.bat switch v2.0
echo   version_manager.bat create v2.1 "New features added"
goto :end

:end
