$ErrorActionPreference = 'Stop'

$packageName = 'react2shell-checker'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url = 'https://github.com/foozio/r2s/releases/download/v2.0.0/react2shell-checker-v2.0.0.zip'
$checksum = 'PLACEHOLDER_SHA256' # Replace with actual SHA256
$checksumType = 'sha256'

# Install Python if not present
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Installing Python 3.9..."
    choco install python --version 3.9.13 -y
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install Python"
    }
    # Refresh environment
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install the package
Install-ChocolateyZipPackage -PackageName $packageName `
                             -Url $url `
                             -UnzipLocation $toolsDir `
                             -Checksum $checksum `
                             -ChecksumType $checksumType

# Create batch file for easy execution
$batchPath = Join-Path $toolsDir "react2shell-checker.bat"
@"
@echo off
python "%~dp0react2shell_checker_unified.py" %*
"@ | Out-File -FilePath $batchPath -Encoding ASCII

# Create PowerShell script for advanced users
$ps1Path = Join-Path $toolsDir "react2shell-checker.ps1"
@"
param(
    [Parameter(Mandatory=`$false)]
    [string]`$Path,

    [Parameter(Mandatory=`$false)]
    [string]`$Url,

    [Parameter(Mandatory=`$false)]
    [switch]`$Json,

    [Parameter(Mandatory=`$false)]
    [switch]`$Quiet,

    [Parameter(Mandatory=`$false)]
    [int]`$Workers = 4,

    [Parameter(Mandatory=`$false)]
    [switch]`$Verbose,

    [Parameter(Mandatory=`$false)]
    [string]`$LogFile,

    [Parameter(Mandatory=`$false)]
    [string]`$Config,

    [Parameter(Mandatory=`$false)]
    [switch]`$NoCache,

    [Parameter(Mandatory=`$false)]
    [switch]`$ClearCache
)

`$pythonPath = Join-Path `$PSScriptRoot "react2shell_checker_unified.py"

`$args = @()
if (`$Path) { `$args += @("--path", `$Path) }
if (`$Url) { `$args += @("--url", `$Url) }
if (`$Json) { `$args += "--json" }
if (`$Quiet) { `$args += "--quiet" }
if (`$Workers -ne 4) { `$args += @("--workers", `$Workers.ToString()) }
if (`$Verbose) { `$args += "--verbose" }
if (`$LogFile) { `$args += @("--log-file", `$LogFile) }
if (`$Config) { `$args += @("--config", `$Config) }
if (`$NoCache) { `$args += "--no-cache" }
if (`$ClearCache) { `$args += "--clear-cache" }

& python `$pythonPath @args
"@ | Out-File -FilePath $ps1Path -Encoding UTF8

# Install dependencies
Write-Host "Installing Python dependencies..."
& python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to upgrade pip, continuing..."
}

# Install required packages
$requirements = @(
    "requests>=2.25.1",
    "packaging"
)

foreach ($req in $requirements) {
    & python -m pip install $req
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to install $req"
    }
}

# Optional: Install PyYAML for config support
try {
    & python -m pip install pyyaml
    if ($LASTEXITCODE -ne 0) {
        Write-Host "PyYAML not available, config files will not be supported"
    }
} catch {
    Write-Host "PyYAML not available, config files will not be supported"
}

Write-Host "React2Shell Vulnerability Checker installed successfully!"
Write-Host ""
Write-Host "Usage:"
Write-Host "  react2shell-checker --path C:\path\to\project"
Write-Host "  react2shell-checker --url https://your-app.com"
Write-Host ""
Write-Host "For help: react2shell-checker --help"