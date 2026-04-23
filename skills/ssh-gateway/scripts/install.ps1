param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\ssh-gateway\bin"
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

    $pathEntries = ($env:PATH -split ';') | Where-Object { $_ -ne "" }
    $onPath = $pathEntries | Where-Object { [System.IO.Path]::GetFullPath($_) -eq [System.IO.Path]::GetFullPath($InstallDir) }

    [pscustomobject]@{
        version = $versionTag
        binary_path = $targetPath
        install_dir = $InstallDir
        on_path = [bool]$onPath
        add_to_path_hint = if ($onPath) { $null } else { "Add '$InstallDir' to PATH if you want to invoke ssh-gateway without an absolute path." }
    } | ConvertTo-Json -Depth 4
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
