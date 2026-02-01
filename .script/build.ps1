param(
    [string]$EnvPath = ".env"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Load-EnvFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return @{}
    }

    $map = @{}
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) {
            return
        }
        $parts = $line -split "=", 2
        if ($parts.Count -lt 2) {
            return
        }
        $key = $parts[0].Trim()
        $val = $parts[1].Trim().Trim('"')
        $map[$key] = $val
    }
    return $map
}

$envMap = Load-EnvFile -Path $EnvPath

$imageName = $envMap["IMAGE_NAME"]

podman build -t $imageName -f .\Dockerfile