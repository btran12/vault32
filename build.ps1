param(
    [ValidateSet("spec", "onedir", "onefile")]
    [string]$Mode = "spec",

    [switch]$InstallDeps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-PythonLauncher {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-m")
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python", "-m")
    }
    throw "Python launcher not found. Install Python and ensure 'py' or 'python' is in PATH."
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $projectRoot

try {
    $py = Get-PythonLauncher

    if ($InstallDeps) {
        & $py[0] $py[1] pip install --upgrade pip setuptools wheel
        & $py[0] $py[1] pip install pyinstaller cryptography
    }

    switch ($Mode) {
        "spec" {
            Write-Host "Building from VaultLock.spec (onedir) ..."
            & $py[0] $py[1] PyInstaller --noconfirm --clean "VaultLock.spec"
            Write-Host "Done. Output: .\dist\VaultLock\VaultLock.exe"
        }
        "onedir" {
            Write-Host "Building onedir executable ..."
            & $py[0] $py[1] PyInstaller --noconfirm --clean --windowed --name VaultLock --collect-all cryptography "vaultlock.py"
            Write-Host "Done. Output: .\dist\VaultLock\VaultLock.exe"
        }
        "onefile" {
            Write-Host "Building onefile executable ..."
            & $py[0] $py[1] PyInstaller --noconfirm --clean --onefile --windowed --name VaultLock --collect-all cryptography "vaultlock.py"
            Write-Host "Done. Output: .\dist\VaultLock.exe"
        }
    }
}
finally {
    Pop-Location
}
