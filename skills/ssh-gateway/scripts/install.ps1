param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\ssh-gateway\bin",
    [switch]$NoPathUpdate
)

$ErrorActionPreference = "Stop"

$repo = "TYzzt/ssh-gateway"
$binaryName = "ssh-gateway.exe"
$apiHeaders = @{
    "Accept" = "application/vnd.github+json"
    "User-Agent" = "ssh-gateway-skill-installer"
}

if (-not $env:LOCALAPPDATA) {
    throw "LOCALAPPDATA is not set"
}

function Normalize-PathEntry {
    param(
        [string]$PathValue
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $null
    }

    $trimmed = $PathValue.Trim().Trim('"').TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $null
    }

    try {
        return [System.IO.Path]::GetFullPath($trimmed).TrimEnd('\')
    }
    catch {
        return $trimmed
    }
}

function Test-PathContains {
    param(
        [string]$PathValue,
        [string]$ExpectedEntry
    )

    $normalizedExpected = Normalize-PathEntry -PathValue $ExpectedEntry
    if (-not $normalizedExpected) {
        return $false
    }

    foreach ($entry in ($PathValue -split ';')) {
        $normalizedEntry = Normalize-PathEntry -PathValue $entry
        if ($normalizedEntry -and $normalizedEntry -eq $normalizedExpected) {
            return $true
        }
    }

    return $false
}

function Add-PathEntryToUserPath {
    param(
        [string]$PathEntry
    )

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (Test-PathContains -PathValue $userPath -ExpectedEntry $PathEntry) {
        return $false
    }

    $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
        $PathEntry
    }
    else {
        "$($userPath.TrimEnd(';'));$PathEntry"
    }

    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    return $true
}

if ($Version -eq "latest") {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $apiHeaders
    $versionTag = $release.tag_name
}
else {
    $versionTag = $Version
    if (-not $versionTag.StartsWith("v")) {
        $versionTag = "v$versionTag"
    }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/tags/$versionTag" -Headers $apiHeaders
}

$assetName = "ssh-gateway-$versionTag-x86_64-pc-windows-msvc.zip"
$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
if (-not $asset) {
    throw "release asset not found: $assetName"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ssh-gateway-install-" + [guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $tempRoot $assetName
$extractDir = Join-Path $tempRoot "extract"
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -Headers $apiHeaders
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force

    $binary = Get-ChildItem -Path $extractDir -Recurse -Filter $binaryName | Select-Object -First 1
    if (-not $binary) {
        throw "binary not found in archive"
    }

    $targetPath = Join-Path $InstallDir $binaryName
    Copy-Item -LiteralPath $binary.FullName -Destination $targetPath -Force

    $onPath = Test-PathContains -PathValue $env:PATH -ExpectedEntry $InstallDir
    $userPathUpdated = $false

    if (-not $onPath -and -not $NoPathUpdate) {
        $userPathUpdated = Add-PathEntryToUserPath -PathEntry $InstallDir
    }

    $pathReadyInNewShell = $onPath -or (Test-PathContains -PathValue ([Environment]::GetEnvironmentVariable("Path", "User")) -ExpectedEntry $InstallDir)

    [pscustomobject]@{
        version = $versionTag
        binary_path = $targetPath
        install_dir = $InstallDir
        on_path = [bool]$onPath
        user_path_updated = [bool]$userPathUpdated
        path_ready_in_new_shell = [bool]$pathReadyInNewShell
        add_to_path_hint = if ($pathReadyInNewShell) {
            if ($userPathUpdated) { "Open a new shell to pick up the updated user PATH, or invoke '$targetPath' directly right now." }
            else { $null }
        }
        else {
            "Add '$InstallDir' to PATH if you want to invoke ssh-gateway without an absolute path."
        }
    } | ConvertTo-Json -Depth 4
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
