# One-line keymitt install for Windows: detect the CPU, download the matching
# release, verify its SHA-256 checksum, install keymitt.exe and add it to your PATH.
#
#   irm https://keymitt.walisayu.com/install.ps1 | iex
#
# Pin a version:  $env:KEYMITT_VERSION = 'v0.1.0'; irm https://keymitt.walisayu.com/install.ps1 | iex
# Other settings: KEYMITT_INSTALL_DIR, KEYMITT_REPO, KEYMITT_BASE_URL, KEYMITT_ALLOW_INSECURE_HTTP=1
#
# Runs inside the caller's session (iex), so it never calls `exit`; errors are thrown.
# Works with Windows PowerShell 5.1 and PowerShell 7. Keep this file ASCII-only.
# The website serves a copy of this file; edit it here, in the keymitt repository.

& {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $ProgressPreference = 'SilentlyContinue'

    $repo = if ($env:KEYMITT_REPO) { $env:KEYMITT_REPO } else { 'walisayu/keymitt' }
    $version = if ($env:KEYMITT_VERSION) { $env:KEYMITT_VERSION } else { 'latest' }
    $baseUrl = $env:KEYMITT_BASE_URL
    $installDir = $env:KEYMITT_INSTALL_DIR
    if (-not $installDir) { $installDir = Join-Path $env:LOCALAPPDATA 'Programs\keymitt' }
    # $IsWindows only exists in PowerShell 6+; under StrictMode a missing variable would throw.
    $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) -eq $true)

    if ($repo -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') { throw "KEYMITT_REPO must look like owner/name" }

    # Windows PowerShell 5.1 may still default to TLS 1.0.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $target = switch ($arch) {
        'AMD64' { 'x86_64-pc-windows-msvc' }
        'ARM64' { 'aarch64-pc-windows-msvc' }
        default { throw "unsupported CPU architecture: $arch" }
    }

    function Get-Url([string] $url, [string] $file) {
        if ($url -notmatch '^https://' -and -not ($url -match '^http://' -and $env:KEYMITT_ALLOW_INSECURE_HTTP -eq '1')) {
            throw "refusing to download over a non-HTTPS URL: $url"
        }
        Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -Headers @{ 'User-Agent' = 'keymitt-installer' }
    }

    if ($version -eq 'latest') {
        if ($baseUrl) { throw "KEYMITT_BASE_URL needs an explicit KEYMITT_VERSION" }
        try {
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'keymitt-installer' }
        } catch {
            throw "could not look up the latest release of $repo (has one been published?)"
        }
        $version = $release.tag_name
    }
    if ($version -notmatch '^v') { $version = "v$version" }
    if ($version -notmatch '^v[A-Za-z0-9._-]+$') { throw "invalid version: $version" }
    if (-not $baseUrl) { $baseUrl = "https://github.com/$repo/releases/download/$version" }
    $baseUrl = $baseUrl.TrimEnd('/')

    $name = "keymitt-$version-$target"
    $archive = "$name.zip"
    Write-Host "==> keymitt $version ($target)"

    $work = Join-Path ([IO.Path]::GetTempPath()) ('keymitt-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $archivePath = Join-Path $work $archive
        $sumsPath = Join-Path $work 'SHA256SUMS.txt'
        Get-Url "$baseUrl/$archive" $archivePath
        Get-Url "$baseUrl/SHA256SUMS.txt" $sumsPath

        $expected = $null
        foreach ($line in Get-Content -Path $sumsPath) {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -ge 2 -and ($parts[1] -eq $archive -or $parts[1] -eq "*$archive")) { $expected = $parts[0]; break }
        }
        if (-not $expected) { throw "SHA256SUMS.txt has no entry for $archive" }
        $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash
        if ($actual.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw "checksum mismatch for $archive; refusing to install" }
        Write-Host '==> checksum verified'

        # Inspect every entry before writing anything (older Expand-Archive versions were
        # vulnerable to path traversal), then extract only keymitt.exe.
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $exe = Join-Path $work 'keymitt.exe'
        $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
        try {
            $wanted = $null
            foreach ($entry in $zip.Entries) {
                $path = $entry.FullName -replace '\\', '/'
                if (-not $path.StartsWith("$name/") -or $path -match '(^|/)\.\.(/|$)' -or $path -match '^[A-Za-z]:') {
                    throw "unexpected entry in the archive: $($entry.FullName)"
                }
                if ($path -eq "$name/keymitt.exe") { $wanted = $entry }
            }
            if (-not $wanted) { throw "the archive does not contain $name/keymitt.exe" }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($wanted, $exe, $true)
        } finally {
            $zip.Dispose()
        }

        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        $dest = Join-Path $installDir 'keymitt.exe'
        Copy-Item -Path $exe -Destination "$dest.new" -Force
        Move-Item -Path "$dest.new" -Destination $dest -Force

        if ($onWindows) {
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            $entries = @()
            if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ } }
            if ($entries -notcontains $installDir) {
                [Environment]::SetEnvironmentVariable('Path', (($entries + $installDir) -join ';'), 'User')
                Write-Host "==> added $installDir to your user PATH (open a new terminal to use it)"
            }
            if (($env:Path -split ';') -notcontains $installDir) { $env:Path = "$env:Path;$installDir" }
            $installed = & $dest --version
            Write-Host "==> installed $installed to $dest"
        } else {
            Write-Host "==> installed $dest"
        }

        Write-Host ''
        Write-Host 'Next steps:'
        Write-Host '  Check Credential Manager and Windows Hello:'
        Write-Host '    keymitt doctor --approval'
        Write-Host '  Store a secret:'
        Write-Host '    keymitt add <name> --host <api-host>'
        Write-Host '  Connect Claude Code:'
        Write-Host '    keymitt setup claude'
        Write-Host 'Docs: https://keymitt.walisayu.com/guide/getting-started'
    } finally {
        Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
