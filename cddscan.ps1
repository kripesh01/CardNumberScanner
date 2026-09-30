# ===============================
# PowerShell Script to Detect Clear-Text Card Numbers in Files
# Author: @kripesh01
# Purpose: Identify and log clear-text card data for compliance audits
#
# Usage:
#   .\CardScan.ps1                        # scan the whole PC (all local fixed drives)
#   .\CardScan.ps1 -IncludeRemovable      # also scan USB / removable drives
#   .\CardScan.ps1 -Path D:\Share, E:\Exports   # scan only specific folders
#
# Run as Administrator so other users' profiles and protected folders can be read.
#
# Output (written to C:\ProgramData\CardScan\ on Windows, monitored by the Wazuh agent):
#   <HOSTNAME>-output.txt   - human-readable report (overwritten each run)
#   <HOSTNAME>-output.json  - NDJSON events for SIEM ingestion (appended; each run has a unique scan_id)
# ===============================

[CmdletBinding()]
param (
    [string[]]$Path,
    [switch]$IncludeRemovable
)

# -------------------------------
# Configuration
# -------------------------------
$MaxFileScanSeconds = 120
$MaxFileSizeMB      = 200

# Masking of detected card numbers (PCI DSS: max first 6 + last 4 by default)
$MaskShowFirst      = 6
$MaskShowLast       = 4
# Stop scanning a file after this many unique cards are found (enough evidence, keeps scans fast)
$MaxCardsPerFile    = 10

# JSON event output (NDJSON: one JSON object per line, UTF-8 without BOM) for SIEM ingestion
$JsonOutputEnabled  = $true
$ScriptVersion      = "2.1"

# Show a progress line every N files (printing every file slows a full-PC scan a lot)
$ProgressEvery      = 500

# -------------------------------
# File extensions to INCLUDE
# -------------------------------
$IncludeExtensions = @(
    # Application Files
    '.bck', '.trc', '.bit', '.dcn', '.dcr', '.pdf',
    # Archive
    '.zip',
    # Backup
    '.bkp', '.bk', '.old',
    # Database Files
    '.accdb', '.dbf', '.mdb', '.nlb', '.sql', '.trn',
    # Log and Error
    '.err', '.log',
    # Microsoft Office
    '.doc', '.docx', '.msg', '.one', '.ppt', '.pptx', '.rtf', '.xls', '.xlsx',
    # Open Office
    '.ods', '.odt',
    # Plain Text
    '.bkd', '.cfg', '.csv', '.dat', '.in', '.lst', '.out', '.text', '.tsv', '.txt', '.xml',
    # Temporary Files
    '.temp', '.tmp'
)

# Files with no extension (noext)
$IncludeNoExtension = $true

# -------------------------------
# File name patterns to EXCLUDE (exclusions win over inclusions)
# -------------------------------
$ExcludePatterns = @(
    '*.css', '*.js', '*.php', '*.java', '*.config', '*.ini', '*.aspx',
    '*.eula*', '*.htm', '*.html', '*.pl', '*.py', '*.bat'
)

# ZIP-based containers: contents are compressed, so they are opened and each entry is scanned
$ZipContainerExtensions = @('.zip', '.docx', '.pptx', '.xlsx', '.odt', '.ods')

$includeSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$IncludeExtensions | ForEach-Object { [void]$includeSet.Add($_) }

$zipSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$ZipContainerExtensions | ForEach-Object { [void]$zipSet.Add($_) }

# -------------------------------
# System folders to EXCLUDE
# -------------------------------
# Windows: any folder with one of these names is skipped, wherever it appears in the tree
$ExcludeFolderNames = @(
    'WINDOWS', 'WINNT', 'Program Files', 'Program Files (x86)', 'ProgramData', 'Contacts',
    'Cookies', 'Favorites', 'Links', 'Local Settings', 'NetHood', 'PrintHood',
    'Recent', 'Roaming', 'Searches', 'SendTo', 'Start Menu', 'Templates',
    'Microsoft', 'IECompactCache', 'IETldCache', 'My Recent Documents', 'PrivacyIE', 'PrivacIE',
    'Symantec', 'McAfee', 'Quest Software', '.svn', 'MSOCache', 'System Volume Information',
    '$RECYCLE.BIN', '$WINDOWS.~BT', '$WINDOWS.~WS', 'Installer', 'Setup', 'Kaspersky Lab',
    'Python27', 'Drivers'
)

# Unix: skipped only at these exact paths (so e.g. a project's own "bin" folder is still scanned)
$ExcludeFolderPaths = @(
    '/proc', '/bin', '/boot', '/dev', '/etc', '/lib',
    '/usr', '/sbin', '/opt', '/var/log', '/rescue', '/sys/kernel'
)

$excludeNameSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$ExcludeFolderNames | ForEach-Object { [void]$excludeNameSet.Add($_) }

$excludePathSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$ExcludeFolderPaths | ForEach-Object { [void]$excludePathSet.Add($_) }

# -------------------------------
# Folder walker: prunes excluded folders so they are never entered
# and records folders that could not be read (access denied etc.)
# -------------------------------
$script:deniedFolders = New-Object 'System.Collections.Generic.List[string]'

function Get-ScanFiles {
    param ([string]$Root)

    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)

    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $errs = $null
        $items = Get-ChildItem -LiteralPath $dir -ErrorAction SilentlyContinue -ErrorVariable errs
        if ($errs) { $script:deniedFolders.Add($dir) }

        foreach ($item in $items) {
            if ($item.PSIsContainer) {
                # skip junctions/symlinks to avoid loops (e.g. legacy "Application Data" links)
                if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                if ($excludeNameSet.Contains($item.Name)) { continue }
                if ($excludePathSet.Contains($item.FullName.TrimEnd('\', '/'))) { continue }
                $stack.Push($item.FullName)
            }
            else {
                $item
            }
        }
    }
}

# -------------------------------
# Scan scope: whole PC by default
# -------------------------------
if ($Path) {
    $ScanRoots = @($Path | ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path })
}
elseif ($IsLinux -or $IsMacOS) {
    $ScanRoots = @('/')
}
else {
    $ScanRoots = @([System.IO.DriveInfo]::GetDrives() |
        Where-Object {
            $_.IsReady -and (
                $_.DriveType -eq [System.IO.DriveType]::Fixed -or
                ($IncludeRemovable -and $_.DriveType -eq [System.IO.DriveType]::Removable)
            )
        } |
        ForEach-Object { $_.RootDirectory.FullName })
}

# -------------------------------
# Environment details
# -------------------------------
$HostName  = $env:COMPUTERNAME
$UserName  = "$($env:USERDOMAIN)\$($env:USERNAME)"
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$ScriptPath      = $MyInvocation.MyCommand.Definition
$ScriptDirectory = Split-Path -Parent $ScriptPath

# -------------------------------
# Output location
# Fixed machine-wide path so the Wazuh agent (running as SYSTEM) can monitor it:
#   <localfile>
#     <location>C:\ProgramData\CardScan\*.json</location>
#     <log_format>json</log_format>
#   </localfile>
# 'ProgramData' is in $ExcludeFolderNames, so the scanner never scans its own reports.
# On non-Windows hosts (no %ProgramData%), falls back to the script's own folder.
# -------------------------------
if ($env:ProgramData) {
    $OutputDir = Join-Path $env:ProgramData "CardScan"
} else {
    $OutputDir = $ScriptDirectory
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$LocalOutputFile = Join-Path $OutputDir "$HostName-output.txt"
$LocalJsonFile   = Join-Path $OutputDir "$HostName-output.json"

$ScanId = [guid]::NewGuid().ToString()

if (Test-Path $LocalOutputFile) {
    Remove-Item $LocalOutputFile -ErrorAction SilentlyContinue
}

$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

# -------------------------------
# Output writer
# -------------------------------
function Save-OutputToFile {
    param ([string]$Output)

    $Output | Out-File -FilePath $LocalOutputFile -Append -ErrorAction SilentlyContinue
}

# -------------------------------
# JSON event writer
# -------------------------------
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Write-JsonEvent {
    param (
        [string]$EventType,
        [System.Collections.Specialized.OrderedDictionary]$Data
    )
    if (-not $JsonOutputEnabled) { return }

    # NOTE: the time field is deliberately NOT named "timestamp". Wazuh's built-in
    # Suricata rule 86600 claims any JSON event that has both "timestamp" and
    # "event_type" (level 0), which stops the CardScan rules from ever matching.
    $evt = [ordered]@{
        event_time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        tool       = "cardscan"
        version    = $ScriptVersion
        event_type = $EventType
        scan_id    = $ScanId
        host       = $HostName
        user       = $UserName
    }
    if ($Data) { foreach ($k in $Data.Keys) { $evt[$k] = $Data[$k] } }

    $line = ($evt | ConvertTo-Json -Compress -Depth 5) + "`n"

    # Out-File defaults to UTF-16 in Windows PowerShell, which most SIEM agents can't parse - write UTF-8
    try { [System.IO.File]::AppendAllText($LocalJsonFile, $line, $Utf8NoBom) } catch { }
}

function Get-FileOwner {
    param ([string]$FilePath)
    try { return (Get-Acl -LiteralPath $FilePath -ErrorAction Stop).Owner } catch { return $null }
}

# -------------------------------
# Execution header
# -------------------------------
$executionDetails = @"
Script executed on: $HostName
User: $UserName
Running as Administrator: $isAdmin
Execution Time: $TimeStamp
Script Location: $ScriptPath
Output Location: $OutputDir
Scan Scope: $($ScanRoots -join ', ')

"@
Save-OutputToFile $executionDetails

Write-JsonEvent -EventType "scan_started" -Data ([ordered]@{
    is_admin      = $isAdmin
    scan_scope    = @($ScanRoots)
    script_path   = $ScriptPath
    max_file_scan_seconds = $MaxFileScanSeconds
    max_cards_per_file    = $MaxCardsPerFile
})

Write-Host "Card Scanning Started..." -ForegroundColor Cyan
Write-Host "Scan scope: $($ScanRoots -join ', ')" -ForegroundColor Cyan
if (-not $isAdmin -and -not ($IsLinux -or $IsMacOS)) {
    Write-Host "WARNING: not running as Administrator - other users' profiles and protected folders will be skipped." -ForegroundColor Yellow
}
Write-Host "----------------------------------------" -ForegroundColor Cyan

# -------------------------------
# BINs and exclusions
# -------------------------------
$validBinsArray = @(
    "3771","4020","4024","4029","4030","4031","4037","4050","4055","4056","4061","4067",
    "4089","4090","4101","4107","4135","4162","4181","4182","4189","4206","4211","4214",
    "4226","4232","4235","4284","4317","4336","4359","4363","4364","4368","4373","4390",
    "4391","4393","4404","4424","4430","4438","4500","4504","4511","4520","4574","4577",
    "4579","4581","4587","4595","4610","4617","4619","4622","4624","4637","4660","4662",
    "4689","4705","4709","4748","4775","4813","4837","4848","4862","4895","4897","4922",
    "4924","4938","4987","5116","5181","5210","5218","5246","5399","5421","5434","5436",
    "5483","5484","5486","5487","5543","5559","6365",

    # --- Issuing BINs (Visa / Mastercard) by member bank ---
    "416211","416212","411655","416213",                           # 1001 SRBL
    "402069","402064","489020","402085",                           # 1002 MBL
    "443830","46958300","443832","46372600","443834",              # 1005 SBL
    "459521","452065","489506","489507",                           # 1006 CTZN
    "474830","474879","418565","431792",                           # 1009 PCBL
    "466046","40907200","45659701","430543","466042","466044",     # 1012 PBL
    "408833","46604300","46372400",                                # 1014 JBBL
    "422592",                                                      # 1015 LBBL
    "439274",                                                      # 1016 SDBL
    "415433",                                                      # 1019 EDBL
    "481367","481364","472387",                                    # 1022 EBL

    # --- NEPALPAY (NPPY) scheme BINs ---
    "65879407","65879507","65879607",                              # Citizens Bank International
    "65879417","65879517","65879617",                              # NIC Asia Bank
    "65879406",                                                    # Kamana Sewa Bikas Bank
    "65879401","65879501","65879601",                              # Himalayan Bank
    "65879402","65879602",                                         # Siddhartha Bank
    "65879403","65879603",                                         # Machhapuchchhre Bank
    "65879404","65879604",                                         # Nepal Investment Mega Bank
    "65879410",                                                    # Lumbini Bikas Bank
    "65879408",                                                    # Prime Commercial Bank
    "65879413",                                                    # Garima Bikas Bank
    "65879405","65879505",                                         # Muktinath Bikas Bank
    "65879414","65879614"                                          # Everest Bank
)

$validBins = @{}
$validBinsArray | ForEach-Object { $validBins[$_] = $true }

# BINs are 4, 6 or 8 digits long; check the longest prefix first
$binLengths = @($validBinsArray | ForEach-Object { $_.Length } | Sort-Object -Unique -Descending)

$skipCards = @(
    "4364442222222222",
    "4020100102020000",
    "4020100202020000"
)

# -------------------------------
# Card detection (runs in-process; a per-file timer replaces the old per-file background job)
# -------------------------------
$cardRegex = New-Object System.Text.RegularExpressions.Regex (
    '\b(\d{4})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)
$latin1 = [System.Text.Encoding]::GetEncoding(28591)

function Reset-ScanState {
    # Full PANs are held only in memory for de-duplication; only masked values are written out
    $script:seenCards = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:seenRaw   = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:masked    = New-Object 'System.Collections.Generic.List[string]'
    $script:limitHit  = $false
    $script:timedOut  = $false
    $script:fileTimer = [System.Diagnostics.Stopwatch]::StartNew()
}

function Test-StopScan {
    if ($script:limitHit -or $script:timedOut) { return $true }
    if ($script:fileTimer.Elapsed.TotalSeconds -gt $MaxFileScanSeconds) {
        $script:timedOut = $true
        return $true
    }
    return $false
}

function Test-Luhn {
    param ($num)
    $digits = $num.ToCharArray()
    $sum = 0
    $even = $false
    for ($i = $digits.Length - 1; $i -ge 0; $i--) {
        $d = [int]$digits[$i].ToString()
        if ($even) {
            $d *= 2
            if ($d -gt 9) { $d -= 9 }
        }
        $sum += $d
        $even = -not $even
    }
    return ($sum % 10 -eq 0)
}

# Masks digits only, keeping the original spaces/dashes so the format is visible
# e.g. 4438-3412-3456-0524 -> 4438-34**-****-0524
function Get-MaskedCard {
    param ([string]$Raw)
    $totalDigits = ($Raw -replace '\D', '').Length
    if ($totalDigits -le ($MaskShowFirst + $MaskShowLast)) { return ($Raw -replace '\d', '*') }
    $sb  = New-Object System.Text.StringBuilder
    $idx = 0
    foreach ($ch in $Raw.ToCharArray()) {
        if ([char]::IsDigit($ch)) {
            if ($idx -lt $MaskShowFirst -or $idx -ge ($totalDigits - $MaskShowLast)) { [void]$sb.Append($ch) }
            else { [void]$sb.Append('*') }
            $idx++
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

# Records every valid (BIN + Luhn) card number found in the text
function Test-Text {
    param ([string]$Text)
    foreach ($m in $cardRegex.Matches($Text)) {
        $card = $m.Value -replace '[-\s]', ''
        if ($skipCards -contains $card) { continue }
        $binOk = $false
        foreach ($len in $binLengths) {
            if ($card.Length -ge $len -and $validBins.ContainsKey($card.Substring(0, $len))) {
                $binOk = $true
                break
            }
        }
        if (-not $binOk) { continue }
        if (-not (Test-Luhn $card)) { continue }

        # list every distinct written format (plain, spaced, dashed) of each card
        if ($script:seenRaw.Add($m.Value)) {
            $script:masked.Add((Get-MaskedCard $m.Value))
        }
        if ($script:seenCards.Add($card) -and $script:seenCards.Count -ge $MaxCardsPerFile) {
            $script:limitHit = $true
            return
        }
    }
}

# Reads any stream (text or binary) in chunks. Bytes are decoded as Latin-1 so
# ASCII/UTF-8 digits survive, and NUL bytes are stripped so UTF-16 text
# (common in .doc, .msg, .xls, .mdb etc.) is also caught.
function Test-Stream {
    param ([System.IO.Stream]$Stream)
    $buffer = New-Object byte[] (4MB)
    $carry  = ''
    while (-not (Test-StopScan) -and ($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $text = $carry + ($latin1.GetString($buffer, 0, $read) -replace "`0", '')
        Test-Text $text
        # keep a tail so numbers split across chunk boundaries are not missed
        if ($text.Length -gt 64) { $carry = $text.Substring($text.Length - 64) } else { $carry = $text }
    }
}

# Opens ZIP-based files (.zip, .docx, .pptx, .xlsx, .odt, .ods) and scans every entry
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
function Test-Zip {
    param ([string]$ZipPath)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $zip.Entries) {
            if (Test-StopScan) { break }
            if ($entry.Length -eq 0) { continue }   # folders / empty entries
            $s = $entry.Open()
            try {
                Test-Stream $s
            } finally {
                $s.Dispose()
            }
        }
    } finally {
        $zip.Dispose()
    }
}

# -------------------------------
# Scan files
# -------------------------------
$totalFiles = 0
$totalFilesWithMatches = 0
$totalFilesSkipped = 0
$totalCardsFound = 0
$scanStart = Get-Date

foreach ($root in $ScanRoots) {

    Write-Host "Scanning drive/folder: $root" -ForegroundColor Cyan

    Get-ScanFiles -Root $root |
    Where-Object {
        # never scan this script's own reports
        if ($_.FullName -eq $LocalOutputFile) { return $false }
        if ($_.FullName -eq $LocalJsonFile) { return $false }

        $name = $_.Name
        foreach ($pattern in $ExcludePatterns) {
            if ($name -like $pattern) { return $false }
        }

        if ([string]::IsNullOrEmpty($_.Extension)) { return $IncludeNoExtension }
        return $includeSet.Contains($_.Extension)
    } |
    ForEach-Object {

        $totalFiles++
        $fileItem  = $_
        $filePath  = $_.FullName
        $extension = $_.Extension.ToLower()

        if ($totalFiles % $ProgressEvery -eq 0) {
            Write-Host ("  [{0:N0} files scanned, {1} with card data] {2}" -f $totalFiles, $totalFilesWithMatches, $filePath) -ForegroundColor DarkGray
        }

     #   if ($_.Length -gt ($MaxFileSizeMB * 1MB)) {
     #       Write-Host "  Skipped (file too large): $filePath" -ForegroundColor Yellow
     #       Save-OutputToFile "File: $filePath`n  Skipped (file size exceeds $MaxFileSizeMB MB)"
     #       return
     #   }

        Reset-ScanState
        $errorMessage = $null

        try {
            if ($zipSet.Contains($extension)) {
                Test-Zip $filePath
            }
            else {
                $fs = [System.IO.File]::Open($filePath, [System.IO.FileMode]::Open,
                                             [System.IO.FileAccess]::Read,
                                             [System.IO.FileShare]::ReadWrite)
                try {
                    Test-Stream $fs
                } finally {
                    $fs.Dispose()
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
        }

        if ($script:masked.Count -gt 0) {
            # cards found (even if the file later errored or timed out)
            $totalFilesWithMatches++
            $totalCardsFound += $script:seenCards.Count
            $countText = "$($script:seenCards.Count)"
            if ($script:limitHit) { $countText += "+ (limit reached, scan of file stopped)" }

            $lines = @("File: $filePath",
                       "  MATCH FOUND: Clear-text card data detected",
                       "  Unique cards: $countText | Formats found: $($script:masked.Count)")
            $script:masked | ForEach-Object { $lines += "    - $_" }
            if ($script:timedOut)  { $lines += "  Note: timed out after $MaxFileScanSeconds s - rest of file not scanned" }
            if ($errorMessage)     { $lines += "  Note: read error before scan completed ($errorMessage)" }

            $msg = $lines -join "`n"
            Write-Host $msg -ForegroundColor Green
            Save-OutputToFile $msg

            Write-JsonEvent -EventType "card_detected" -Data ([ordered]@{
                file_path       = $filePath
                file_name       = $fileItem.Name
                file_extension  = $extension
                file_size_bytes = $fileItem.Length
                file_modified   = $fileItem.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                file_owner      = (Get-FileOwner $filePath)
                unique_cards    = $script:seenCards.Count
                formats_found   = $script:masked.Count
                masked_cards    = @($script:masked)
                limit_reached   = $script:limitHit
                scan_complete   = -not ($script:timedOut -or $errorMessage -or $script:limitHit)
                note            = $(if ($script:timedOut) { "timed out after $MaxFileScanSeconds s" } elseif ($errorMessage) { "read error: $errorMessage" } else { $null })
            })
        }
        elseif ($script:timedOut) {
            $totalFilesSkipped++
            Write-Host "  Skipped (read timeout): $filePath" -ForegroundColor Yellow
            Save-OutputToFile "File: $filePath`n  Skipped (read timeout after $MaxFileScanSeconds s)"
            Write-JsonEvent -EventType "file_skipped" -Data ([ordered]@{
                file_path       = $filePath
                file_size_bytes = $fileItem.Length
                reason          = "timeout"
                error_message   = "no result within $MaxFileScanSeconds s"
            })
        }
        elseif ($errorMessage) {
            $totalFilesSkipped++
            Write-Host "  Skipped (read error): $filePath" -ForegroundColor Yellow
            Save-OutputToFile "File: $filePath`n  Skipped (read error: $errorMessage)"
            Write-JsonEvent -EventType "file_skipped" -Data ([ordered]@{
                file_path       = $filePath
                file_size_bytes = $fileItem.Length
                reason          = "read_error"
                error_message   = $errorMessage
            })
        }
    }
}

# -------------------------------
# Folders that could not be read
# -------------------------------
if ($script:deniedFolders.Count -gt 0) {
    $maxListed = 200
    $deniedText = "Folders not scanned (access denied / unreadable): $($script:deniedFolders.Count)"
    $script:deniedFolders | Select-Object -First $maxListed | ForEach-Object { $deniedText += "`n  - $_" }
    if ($script:deniedFolders.Count -gt $maxListed) {
        $deniedText += "`n  ... and $($script:deniedFolders.Count - $maxListed) more"
    }
    Save-OutputToFile $deniedText

    Write-JsonEvent -EventType "folders_unreadable" -Data ([ordered]@{
        count            = $script:deniedFolders.Count
        folders          = @($script:deniedFolders | Select-Object -First $maxListed)
        folders_truncated = ($script:deniedFolders.Count -gt $maxListed)
    })
}

# -------------------------------
# Summary
# -------------------------------
$duration = (Get-Date) - $scanStart
$summary = @"
----------------------------------------
Scan Completed.
Scan Scope: $($ScanRoots -join ', ')
Duration: $([int]$duration.TotalHours)h $($duration.Minutes)m $($duration.Seconds)s
Total Files Scanned: $totalFiles
Total Files Containing Valid Card Data: $totalFilesWithMatches
Total Unique Card Numbers Found (per-file, masked in report): $totalCardsFound
Total Files Skipped (timeout/read error): $totalFilesSkipped
Folders Not Readable: $($script:deniedFolders.Count)
Results saved to:
  - $LocalOutputFile
  - $LocalJsonFile (JSON events)
----------------------------------------
"@

Write-Host $summary -ForegroundColor Cyan
Save-OutputToFile $summary

Write-JsonEvent -EventType "scan_completed" -Data ([ordered]@{
    scan_scope              = @($ScanRoots)
    duration_seconds        = [int]$duration.TotalSeconds
    files_scanned           = $totalFiles
    files_with_card_data    = $totalFilesWithMatches
    unique_cards_found      = $totalCardsFound
    files_skipped           = $totalFilesSkipped
    folders_unreadable      = $script:deniedFolders.Count
    is_admin                = $isAdmin
})

if ($Host.Name -eq 'ConsoleHost') {
    Write-Host ""
    Write-Host "Scan finished. Press ENTER to close this window." -ForegroundColor White
    [void][System.Console]::ReadLine()
}