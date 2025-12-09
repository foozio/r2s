# Chocolatey Package Build Script

# This script helps build and test the Chocolatey package locally

param(
    [Parameter(Mandatory=$false)]
    [switch]$Build,

    [Parameter(Mandatory=$false)]
    [switch]$Test,

    [Parameter(Mandatory=$false)]
    [switch]$Clean,

    [Parameter(Mandatory=$false)]
    [string]$Version = "2.0.0"
)

$ErrorActionPreference = 'Stop'
$packageName = "react2shell-checker"
$nuspecPath = "choco/$packageName.nuspec"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

if ($Clean) {
    Write-Info "Cleaning previous builds..."
    Remove-Item "*.nupkg" -ErrorAction SilentlyContinue
    Write-Success "Clean completed"
    exit 0
}

if ($Build) {
    Write-Info "Building Chocolatey package..."

    # Update version in nuspec if needed
    $nuspecContent = Get-Content $nuspecPath -Raw
    $nuspecContent = $nuspecContent -replace '<version>.*?</version>', "<version>$Version</version>"
    Set-Content $nuspecPath $nuspecContent

    # Pack the package
    & choco pack $nuspecPath

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Package built successfully"
        Get-ChildItem "*.nupkg" | ForEach-Object {
            Write-Info "Created: $($_.Name)"
        }
    } else {
        Write-Error "Package build failed"
        exit 1
    }
}

if ($Test) {
    Write-Info "Testing Chocolatey package..."

    # Find the nupkg file
    $nupkgFile = Get-ChildItem "*.nupkg" | Select-Object -First 1

    if (-not $nupkgFile) {
        Write-Error "No .nupkg file found. Run with -Build first."
        exit 1
    }

    Write-Info "Testing package: $($nupkgFile.Name)"

    # Test installation
    & choco install $packageName --source . --yes

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Package installed successfully"

        # Test basic functionality
        & react2shell-checker --help > $null 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Basic functionality test passed"
        } else {
            Write-Error "Basic functionality test failed"
        }

        # Uninstall test package
        & choco uninstall $packageName --yes

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Package uninstalled successfully"
        } else {
            Write-Error "Package uninstallation failed"
        }

    } else {
        Write-Error "Package installation failed"
        exit 1
    }
}

if (-not $Build -and -not $Test -and -not $Clean) {
    Write-Host "Chocolatey Package Build Script"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\build-choco.ps1 -Build          # Build the package"
    Write-Host "  .\build-choco.ps1 -Test           # Test the package"
    Write-Host "  .\build-choco.ps1 -Clean          # Clean build artifacts"
    Write-Host "  .\build-choco.ps1 -Build -Test    # Build and test"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\build-choco.ps1 -Build -Version 2.1.0"
    Write-Host "  .\build-choco.ps1 -Test"
}