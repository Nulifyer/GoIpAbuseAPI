param(
    [string]$Image = "",
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

function Get-GhcrToken {
    param(
        [string]$User,
        [string]$Token,
        [string]$Owner,
        [string]$Repo
    )

    $scope = "repository:$Owner/$Repo:pull"
    $uri = "https://ghcr.io/token?service=ghcr.io&scope=$scope"
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Token"))
    $headers = @{ Authorization = "Basic $basic" }

    try {
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $resp.token
    } catch {
        throw "Failed to obtain GHCR token. Check credentials and package visibility."
    }
}

function Get-RemoteTags {
    param(
        [string]$RegistryToken,
        [string]$Owner,
        [string]$Repo
    )

    $uri = "https://ghcr.io/v2/$Owner/$Repo/tags/list"
    $headers = @{ Authorization = "Bearer $RegistryToken" }

    try {
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        if ($null -eq $resp.tags) {
            return @()
        }
        return $resp.tags
    } catch {
        return @()
    }
}

$envMap = Load-EnvFile -Path $EnvPath

$ghcrUser = $env:GITHUB_USR
if (-not $ghcrUser) { $ghcrUser = $envMap["GITHUB_USR"] }

$ghcrToken = $env:GITHUB_PAT
if (-not $ghcrToken) { $ghcrToken = $envMap["GITHUB_PAT"] }

if (-not $ghcrUser -or -not $ghcrToken) {
    throw "Missing GHCR credentials. Set GITHUB_USR and GITHUB_PAT in .env or environment."
}

$image = $env:IMAGE_NAME
if (-not $image) { $image = $envMap["IMAGE_NAME"] }

# Parse owner/repo from image
if ($Image -notmatch "^ghcr\.io/([^/]+)/([^:]+)$") {
    throw "Image must be in form ghcr.io/<owner>/<repo>"
}
$owner = $Matches[1]
$repo = $Matches[2]

# Ensure local image exists
$latestImage = "${Image}:latest"
podman image exists $latestImage | Out-Null

# Determine next tag using YYYY.MM.DD with optional -NN suffix
$dateTag = Get-Date -Format "yyyy.MM.dd"
$registryToken = Get-GhcrToken -User $ghcrUser -Token $ghcrToken -Owner $owner -Repo $repo
$tags = Get-RemoteTags -RegistryToken $registryToken -Owner $owner -Repo $repo

$exactTagExists = $tags -contains $dateTag
$pattern = "^$([regex]::Escape($dateTag))-(\d{2})$"

if (-not $exactTagExists) {
    $nextTag = $dateTag
} else {
    $maxNum = 0
    foreach ($t in $tags) {
        $m = [regex]::Match($t, $pattern)
        if ($m.Success) {
            $num = [int]$m.Groups[2].Value
            if ($num -gt $maxNum) {
                $maxNum = $num
            }
        }
    }
    $nextNum = $maxNum + 1
    $nextTag = "{0}-{1:D2}" -f $dateTag, $nextNum
}

Write-Host "Next tag: $nextTag"

# Login
podman login ghcr.io --username $ghcrUser --password $ghcrToken

# Tag and push
$versionedImage = "${Image}:$nextTag"
podman tag $latestImage $versionedImage

podman push $versionedImage
podman push $latestImage

Write-Host "Pushed $versionedImage and updated $latestImage"