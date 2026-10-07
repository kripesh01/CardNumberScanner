# ===============================
# PowerShell Script to Detect Clear-Text Card Numbers in Files
# Author: @kripesh01
# Purpose: Identify and log clear-text card data for compliance audits
#
# Usage:
#   .\CardScan.ps1                        # scan the whole PC (all local fixed drives)
#   .\CardScan.ps1 -IncludeRemovable      # also scan USB / removable drives
#   .\CardScan.ps1 -Path D:\Share, E:\Exports   # scan only specific folders
#   .\CardScan.ps1 -DisableOcr            # skip images (OCR is ON by default - Windows PowerShell 5.1 only)
#
# Run as Administrator so other users' profiles and protected folders can be read.
#
# Detection confidence:
#   high - Luhn-valid PAN whose BIN is in $validBinsArray
#   low  - Luhn-valid PAN matching a global card scheme's IIN range and length (Visa, Amex, JCB, ...)
#
# Output (written to C:\ProgramData\CardScan\ on Windows, monitored by the Wazuh agent):
#   <HOSTNAME>-output.txt   - human-readable report (overwritten each run)
#   <HOSTNAME>-output.json  - NDJSON events for SIEM ingestion (appended; each run has a unique scan_id)
# ===============================

[CmdletBinding()]
param (
    [string[]]$Path,
    [switch]$IncludeRemovable,
    [switch]$DisableOcr,
    [switch]$EnableOcr      # kept for compatibility with existing tasks; OCR is now on by default
)

# OCR runs by default; -DisableOcr turns it off
$EnableOcr = -not $DisableOcr

# -------------------------------
# Configuration
# -------------------------------
$MaxFileScanSeconds = 120
$MaxFileSizeMB      = 200

# Masking of detected card numbers (PCI DSS: max first 6 + last 4 by default)
$MaskShowFirst      = 6
$MaskShowLast       = 4
# Noise controls ------------------------------------------------------------
# Only accept numbers written the way card numbers are actually written: unbroken, or split into
# groups that start with 4 digits and continue in 4s or 6s (4-4-4-4, 4-6-5 Amex, 4-6-4 Diners,
# 4-4-4-4-3 ...). Rejects spaced tables like "82 83 84 85 ..." or "347 419 812 ..." in PDFs/binaries.
$StrictCardGrouping = $true

# Confidence for the generic 4-digit prefixes in the 'Unmapped local BIN' group. They match whole
# blocks of Visa/Mastercard numbers, so random numeric IDs in logs/exports hit them often.
# 'high' = treat like issuer BINs (old behaviour); 'low' = report them in the low tier.
$UnmappedBinConfidence = 'high'

# Full-path wildcard patterns to skip (runtime images, caches) - matched against the whole path
$ExcludePathPatterns = @(
    '*\jre\lib\modules', '*\jdk*\lib\modules',   # Java runtime module images (e.g. Burp Suite)
    '*\Tor\cached-*',                                 # Tor Browser directory/consensus caches
    '*\node_modules\*'
)

# Confidence scoring ---------------------------------------------------------
# Every card gets a 0-100 score; score >= $HighConfidenceScore is reported as 'high'.
#   base (what the BIN matched):  home-country BIN 60 | known BIN in a low tier (foreign, unless
#   $ForeignBinConfidence = 'high') 40 | generic 4-digit prefix when $UnmappedBinConfidence = 'low' 35 |
#   card-scheme range only 25
#   + $ScoreExpiry if an expiry date is within $ContextWindowChars characters of the number
#   + $ScoreCvv    if a CVV/CVC is (keyword + 3-4 digits, or a 3-4 digit value right next to an expiry date)
# CVV digits are only detected, never written to any output.
$ContextWindowChars  = 100
$ScoreHomeBin        = 60
$ScoreKnownLowBin    = 40
$ScoreGenericPrefix  = 35
$ScoreSchemeOnly     = 25
$ScoreExpiry         = 20
$ScoreCvv            = 25
$HighConfidenceScore = 60

# Change tracking: each scan compares findings with the previous scan of this host and marks every
# card_detected event as finding_status = new | changed | unchanged, so Wazuh can alert only on new
# or changed files while dashboards still see every finding.
$TrackChanges = $true

# Report low-confidence matches (global scheme ranges, not in $validBinsArray).
# These are much noisier on number-heavy logs/exports; set to $false for high-confidence-only scans.
$DetectLowConfidence = $true
# Stop scanning a file after this many unique cards are found (enough evidence, keeps scans fast)
$MaxCardsPerFile    = 10

# JSON event output (NDJSON: one JSON object per line, UTF-8 without BOM) for SIEM ingestion
$JsonOutputEnabled  = $true
$ScriptVersion      = "3.4"

# Show a progress line every N files (printing every file slows a full-PC scan a lot)
$ProgressEvery      = 500

# OCR of images (on by default, -DisableOcr to skip). Uses the built-in Windows OCR engine
# (Windows.Media.Ocr), which needs Windows PowerShell 5.1 and an installed OCR language.
$OcrExtensions      = @('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tif', '.tiff')
$OcrLanguage        = 'en-US'
$OcrMinFileSizeKB   = 1      # cropped screenshots of a card number can be only a few KB
$OcrMaxFileSizeMB   = 50
$OcrMinPixelWidth   = 200    # narrower images can't hold a readable card number
$OcrTimeoutSeconds  = 30     # per image

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

$ocrSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$OcrExtensions | ForEach-Object { [void]$ocrSet.Add($_) }

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
$LocalStateFile  = Join-Path $OutputDir "$HostName-state.json"   # previous findings, for change tracking

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
# Tier 1 (HIGH confidence): BINs of NCHL member banks / local issuers, and test-card exclusions
# -------------------------------
# BIN reference list - one line per issuer + card type + country:
#   @{ Issuer = 'Bank name'; Type = 'VISA'; Bins = @("123456","654321"); Country = 'Nepal' },
#   - BINs whose Country is $HomeCountry are the HIGH-confidence list (local issuers / member banks).
#   - Other countries only add issuer + country to a match; their confidence is $ForeignBinConfidence.
#   - Type uses the BIN sheet's names (VISA, MASTERCARD, NEPALPAY, ...) and is reported as the card
#     brand; leave it '' to take the brand from the card-scheme rules.
#   - 4/6/8-digit BINs are supported; the longest matching BIN wins.
# Source: BIN_numbers.xlsx (placeholder rows "... issuer not identified" omitted), plus BINs kept from v3.2
# that are not in the sheet (SBL/PBL 8-digit, JBBL) and generic 4-digit prefixes with no 6-digit BIN yet.
$HomeCountry          = 'Nepal'
$ForeignBinConfidence = 'low'      # 'low' (default) or 'high'

$BinGroups = @(
    # ===== Nepal - HIGH confidence (local issuers / member banks) =====
    @{ Issuer = 'Bank of Kathmandu';                     Type = 'VISA';                 Bins = @("462261","462262","486278"); Country = 'Nepal' },
    # Citizens Bank International - member 1006 CTZN
    @{ Issuer = 'Citizens Bank International';           Type = 'VISA';                 Bins = @("452065","459521","459522","489506","489507"); Country = 'Nepal' },
    @{ Issuer = 'Citizens Bank International';           Type = 'NEPALPAY';             Bins = @("65879407","65879507","65879607"); Country = 'Nepal' },
    # Everest Bank - member 1022 EBL
    @{ Issuer = 'Everest Bank';                          Type = 'VISA';                 Bins = @("472387","481364","481367"); Country = 'Nepal' },
    @{ Issuer = 'Everest Bank';                          Type = 'NEPALPAY';             Bins = @("65879414","65879614"); Country = 'Nepal' },
    # Excel Development Bank - member 1019 EDBL
    @{ Issuer = 'Excel Development Bank';                Type = 'VISA';                 Bins = @("415433"); Country = 'Nepal' },
    @{ Issuer = 'Garima Bikas Bank';                     Type = 'VISA';                 Bins = @("422705","468751"); Country = 'Nepal' },
    @{ Issuer = 'Garima Bikas Bank';                     Type = 'NEPALPAY';             Bins = @("65879413"); Country = 'Nepal' },
    @{ Issuer = 'Global IME Bank';                       Type = 'VISA';                 Bins = @(
        "402896","420792","423274","423276","423298","436895","461993","461994","468950","479955",
        "479956","486266","486267","486268"
    ); Country = 'Nepal' },
    @{ Issuer = 'Himalayan Bank';                        Type = 'VISA';                 Bins = @(
        "410102","410148","410149","428461","436362","440403","440404","440449","440450","440467",
        "440468","484814","484815"
    ); Country = 'Nepal' },
    @{ Issuer = 'Himalayan Bank';                        Type = 'MASTERCARD';           Bins = @("524682","524683","524684","539933","548483","548493","548730","554370","554391","557578"); Country = 'Nepal' },
    @{ Issuer = 'Himalayan Bank';                        Type = 'AMERICAN EXPRESS';     Bins = @("377175","377344","378254"); Country = 'Nepal' },
    @{ Issuer = 'Himalayan Bank';                        Type = 'CHINA UNION PAY';      Bins = @("623499"); Country = 'Nepal' },
    @{ Issuer = 'Himalayan Bank';                        Type = 'NEPALPAY';             Bins = @("65879401","65879501","65879601"); Country = 'Nepal' },
    # JBBL (1014) - member 1014 JBBL
    @{ Issuer = 'JBBL (1014)';                           Type = 'VISA';                 Bins = @("408833","46372400","46604300"); Country = 'Nepal' },
    @{ Issuer = 'Kamana Sewa Bikas Bank';                Type = 'VISA';                 Bins = @("470365","478675"); Country = 'Nepal' },
    @{ Issuer = 'Kamana Sewa Bikas Bank';                Type = 'NEPALPAY';             Bins = @("65879406"); Country = 'Nepal' },
    @{ Issuer = 'Kist Bank';                             Type = 'VISA';                 Bins = @("466045"); Country = 'Nepal' },
    @{ Issuer = 'Kumari Bank';                           Type = 'VISA';                 Bins = @("406866","406888","420611","420622","439128","439129","492469","496646"); Country = 'Nepal' },
    # Laxmi Sunrise Bank - member 1001 SRBL
    @{ Issuer = 'Laxmi Sunrise Bank';                    Type = 'VISA';                 Bins = @(
        "405019","405544","407585","411655","416211","416212","416213","418240","426501","437369",
        "437370"
    ); Country = 'Nepal' },
    # Lumbini Bikas Bank - member 1015 LBBL
    @{ Issuer = 'Lumbini Bikas Bank';                    Type = 'VISA';                 Bins = @("422592"); Country = 'Nepal' },
    @{ Issuer = 'Lumbini Bikas Bank';                    Type = 'NEPALPAY';             Bins = @("65879410"); Country = 'Nepal' },
    # Machhapuchchhre Bank - member 1002 MBL
    @{ Issuer = 'Machhapuchchhre Bank';                  Type = 'VISA';                 Bins = @("402064","402069","402085","470554","489020"); Country = 'Nepal' },
    @{ Issuer = 'Machhapuchchhre Bank';                  Type = 'NEPALPAY';             Bins = @("65879403","65879603"); Country = 'Nepal' },
    @{ Issuer = 'Mahalaxmi Bikas Bank';                  Type = 'VISA';                 Bins = @("406886","430790","463725","479979"); Country = 'Nepal' },
    @{ Issuer = 'Muktinath Bikas Bank';                  Type = 'VISA';                 Bins = @("405514","422476"); Country = 'Nepal' },
    @{ Issuer = 'Muktinath Bikas Bank';                  Type = 'NEPALPAY';             Bins = @("65879405","65879505"); Country = 'Nepal' },
    @{ Issuer = 'NIC Asia Bank';                         Type = 'VISA';                 Bins = @("423510","423559","423567","489325"); Country = 'Nepal' },
    @{ Issuer = 'NIC Asia Bank';                         Type = 'MASTERCARD';           Bins = @("538749","539604"); Country = 'Nepal' },
    @{ Issuer = 'NIC Asia Bank';                         Type = 'NEPALPAY';             Bins = @("65879417","65879517","65879617"); Country = 'Nepal' },
    @{ Issuer = 'NMB Bank';                              Type = 'VISA';                 Bins = @(
        "401651","402723","403019","408910","408911","419816","421158","421159","423803","423815",
        "429326","429502","445973","470946","483751","483752","487458"
    ); Country = 'Nepal' },
    @{ Issuer = 'Nabil Bank';                            Type = 'VISA';                 Bins = @("406750","413545","418902","422627","427142","439371","451132","457987","458701"); Country = 'Nepal' },
    @{ Issuer = 'Nabil Bank';                            Type = 'MASTERCARD';           Bins = @("542157","543496","555934"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Bangladesh Bank';                 Type = 'VISA';                 Bins = @("422306","450485","450486","462470","462471"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Credit and Commerce Bank';        Type = 'VISA';                 Bins = @("429919","462416","468959"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Development Bank';                Type = 'VISA';                 Bins = @("443083"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Grindlays Bank';                  Type = 'MASTERCARD';           Bins = @("543630"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Industrial Development Corporation'; Type = 'MAESTRO';              Bins = @("636523"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Investment Bank';                 Type = 'VISA';                 Bins = @(
        "405635","405673","421404","433621","436439","436441","436443","436444","436478","436497",
        "436498","470553","470555","498758"
    ); Country = 'Nepal' },
    @{ Issuer = 'Nepal Investment Bank';                 Type = 'MASTERCARD';           Bins = @("222718","540357","554038"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Investment Mega Bank';            Type = 'VISA';                 Bins = @(
        "404782","405263","405633","405634","405636","421105","421406","421411","421412","421414",
        "421415","421416","424972","430715","430719","430728","445631","458172","479951","490291",
        "498704"
    ); Country = 'Nepal' },
    @{ Issuer = 'Nepal Investment Mega Bank';            Type = 'MASTERCARD';           Bins = @("222719","222846","222847","521066","538815"); Country = 'Nepal' },
    @{ Issuer = 'Nepal Investment Mega Bank';            Type = 'NEPALPAY';             Bins = @("65879404","65879604"); Country = 'Nepal' },
    @{ Issuer = 'Nepal SBI Bank';                        Type = 'VISA';                 Bins = @("435978","442440","457412","489743"); Country = 'Nepal' },
    @{ Issuer = 'Nepal SBI Bank';                        Type = 'MASTERCARD';           Bins = @("538957"); Country = 'Nepal' },
    # Prabhu Bank - member 1012 PBL
    @{ Issuer = 'Prabhu Bank';                           Type = 'VISA';                 Bins = @(
        "405230","407038","409072","430511","430519","430543","456597","466042","466044","466046",
        "40907200","45659701"
    ); Country = 'Nepal' },
    @{ Issuer = 'Prabhu Bank';                           Type = 'MASTERCARD';           Bins = @("529767","535964","545030"); Country = 'Nepal' },
    # Prime Commercial Bank - member 1009 PCBL
    @{ Issuer = 'Prime Commercial Bank';                 Type = 'VISA';                 Bins = @("418565","431792","474830","474879"); Country = 'Nepal' },
    @{ Issuer = 'Prime Commercial Bank';                 Type = 'NEPALPAY';             Bins = @("65879408"); Country = 'Nepal' },
    @{ Issuer = 'Rastriya Banijya Bank';                 Type = 'VISA';                 Bins = @("401583","418119","418120","418121"); Country = 'Nepal' },
    @{ Issuer = 'Sanima Bank';                           Type = 'VISA';                 Bins = @("403110","403729","403735","450052","461003","461004","461005","461006"); Country = 'Nepal' },
    # Shangri-La Development Bank - member 1016 SDBL
    @{ Issuer = 'Shangri-La Development Bank';           Type = 'VISA';                 Bins = @("439274"); Country = 'Nepal' },
    # Siddhartha Bank - member 1005 SBL
    @{ Issuer = 'Siddhartha Bank';                       Type = 'VISA';                 Bins = @("443830","443832","443834","463726","469583","46372600","46958300"); Country = 'Nepal' },
    @{ Issuer = 'Siddhartha Bank';                       Type = 'MASTERCARD';           Bins = @("530424"); Country = 'Nepal' },
    @{ Issuer = 'Siddhartha Bank';                       Type = 'NEPALPAY';             Bins = @("65879402","65879602"); Country = 'Nepal' },
    @{ Issuer = 'Smartchoice Technologies PVT.LTD.';     Type = 'CHINA UNION PAY';      Bins = @("623459","623477"); Country = 'Nepal' },
    @{ Issuer = 'Standard Chartered Bank';               Type = 'VISA';                 Bins = @(
        "402874","403349","403397","404894","405460","405461","405706","405749","405750","406142",
        "406143","406922","407495","407670","407804","407805","409381","410308","410309","410541",
        "410744","411144","412585","412587","412903","412905","413823","413861","414687","414689",
        "416065","416066","417210","417278","417611","417612","417827","418750","419088","419607",
        "419982","419983","421104","421312","421451","421474"
    ); Country = 'Nepal' },
    @{ Issuer = 'Standard Chartered Bank';               Type = 'MASTERCARD';           Bins = @("223587","518166","548360","548633"); Country = 'Nepal' },
    @{ Issuer = 'Standard Chartered Bank';               Type = 'AMERICAN EXPRESS';     Bins = @("376294"); Country = 'Nepal' },
    @{ Issuer = 'Standard Chartered Bank';               Type = 'JCB';                  Bins = @("356055","356355"); Country = 'Nepal' },
    # Generic 4-digit prefixes with no 6/8-digit BIN yet (confidence: $UnmappedBinConfidence)
    @{ Issuer = 'Unmapped local BIN';                    Type = '';                     Bins = @(
        "4024","4029","4390","4577","4617","4662","4775","4922","4938","5116",
        "5218"
    ); Country = 'Nepal' },

    # ===== Foreign - issuer + country attribution only (confidence: $ForeignBinConfidence) =====
    @{ Issuer = 'Westpac Banking Corporation';           Type = 'VISA';                 Bins = @(
        "400467","419989","421841","427679","427692","429317","429318","429348","429349","431219",
        "431491","431492","431493","431494","431495","437431","451784","451785","451841","451856",
        "451867","451869","451874","451876","451886","451897","451898","452560","452562","452563"
    ); Country = 'Australia' },
    @{ Issuer = 'Westpac Banking Corporation';           Type = 'DINERS CLUB INTERNATIONAL'; Bins = @(
        "361700","361701","361702","361703","361704","361705","361706","361707","361714","361715",
        "361716","361717","361718","361719","361720","361757","361758","361759","361768","361769"
    ); Country = 'Australia' },
    @{ Issuer = 'Inn for Unionpay Card Network';         Type = 'CHINA UNION PAY';      Bins = @(
        "622144","623045","623364","623384","623385","623399","623409","623417","623418","623419",
        "623420","623421","623428","623429","623435","623440","623441","623444","623455","623457",
        "623462","623464","623475","623476","623478","623483","623491","623493","623496","623556",
        "623597","623618","623626","623642","623662","623673","624305","624319","624415","624417",
        "624426","624463","624467","624477","624624","625159","625505","625657","626205","626216"
    ); Country = 'China' },
    @{ Issuer = 'Banco de la Produccion, S.A.';          Type = 'VISA';                 Bins = @(
        "403132","404103","404104","407862","412608","415304","421455","424955","428352","431073",
        "431074","431075","435162","445020","445892","450568","455269","458953","458954","458955",
        "458956","487508","487509","491684","491685","491686","491687"
    ); Country = 'Ecuador' },
    @{ Issuer = 'Banco de la Produccion, S.A.';          Type = 'MASTERCARD';           Bins = @(
        "510846","512209","512221","512738","514991","515449","515631","517321","517609","519950",
        "521709","522612","523054","525648","535053","536169","536777","537873","542267","542948",
        "548040","552451","554468"
    ); Country = 'Ecuador' },
    @{ Issuer = 'Teller, A.S.';                          Type = 'VISA';                 Bins = @(
        "402839","402881","403064","403846","403847","404393","412491","415054","417229","417310",
        "417312","417313","417315","417316","417318","417728","417729","417730","417731","418744",
        "419376","419377","420170","420773","423283","425714","429596","429942","430266","431092",
        "431316","431317","431318","432286","432287","444228","444229","444230","444231","447387",
        "448424","456901","456905","456910","456911","456912","456913","456914","456915"
    ); Country = 'Estonia' },
    @{ Issuer = 'Indusind Bank';                         Type = 'VISA';                 Bins = @(
        "401825","402770","402969","403506","404248","405338","405342","405920","406976","407484",
        "407712","411177","414752","414772","416292","416846","420337","421324","421681","427124",
        "436393","436395","437579","441283","441285","443682","444261","445085","455392","457467",
        "457546","461244","463787","466519","466520","466521","466522","466592","466594","468936",
        "470035","470050","473279","478008","478949","481963","482895","489664","491519"
    ); Country = 'India' },
    @{ Issuer = 'Indusind Bank';                         Type = 'MASTERCARD';           Bins = @("222712"); Country = 'India' },
    @{ Issuer = 'Bank Espirito Santo International';     Type = 'VISA';                 Bins = @("450748","496653"); Country = 'Portugal' },
    @{ Issuer = 'Bankard, Inc.';                         Type = 'VISA';                 Bins = @("405483","426577"); Country = 'United States' },
    @{ Issuer = 'Community Financial Services F.C.U.';   Type = 'VISA';                 Bins = @("464503"); Country = 'United States' },
    @{ Issuer = 'First USA Bank, N.A.';                  Type = 'VISA';                 Bins = @("422692","464013","464015"); Country = 'United States' },
    @{ Issuer = 'First USA Bank, N.A.';                  Type = 'MASTERCARD';           Bins = @("530257"); Country = 'United States' },
    @{ Issuer = 'Friendship State Bank';                 Type = 'VISA';                 Bins = @("412133","438867","442071"); Country = 'United States' },
    @{ Issuer = 'Grimes C.U.';                           Type = 'VISA';                 Bins = @("472363"); Country = 'United States' },
    @{ Issuer = 'Inter National Bank';                   Type = 'VISA';                 Bins = @("438093","453590","475566"); Country = 'United States' },
    @{ Issuer = 'Intl Hdqtrs-Center Owned';              Type = 'VISA';                 Bins = @(
        "400000","400001","400004","400007","400008","400015","400020","400021","400025","400026",
        "400027","400030","400031","400039","400048","400050","400051","400053","400056","400058",
        "400087","400552","400554","400862","401551","402524","403657","403661","403685","403688",
        "403691","403698","404533","404534","405104","405106","405108","405114","405116","405142",
        "405144","405146","405148","405162","405164","405166","405168","405170","405172","405174"
    ); Country = 'United States' },
    @{ Issuer = 'Its Bank';                              Type = 'VISA';                 Bins = @(
        "402225","402226","402233","402237","402239","402243","402244","402245","402250","402259",
        "402261","402262","402867","403174","405000","405001","405002","407936","412274","412907",
        "414461","415228","415249","415251","416845","418500","419056","421721","423359","424673",
        "425402","426214","426438","427801","427802","427803","427805","430054","430121","430331",
        "430707","431013","431415","431434","431659","431700","432590","432637","432644","432724"
    ); Country = 'United States' },
    @{ Issuer = 'Regions Financial Corporation';         Type = 'VISA';                 Bins = @("405490","467552"); Country = 'United States' },
    @{ Issuer = 'Stissing National Bank of Pine Plains'; Type = 'VISA';                 Bins = @("422310"); Country = 'United States' },
    @{ Issuer = 'Wachovia Bank, N.A.';                   Type = 'VISA';                 Bins = @("422462","482806"); Country = 'United States' },
    @{ Issuer = 'Wells Fargo Bank Nevada, N.A.';         Type = 'VISA';                 Bins = @("422918","436440","436442","479948","479949","479950","479958","479989","479990"); Country = 'United States' },
    @{ Issuer = 'Wells Fargo Bank Nevada, N.A.';         Type = 'MASTERCARD';           Bins = @(
        "514120","514121","514122","514123","514124","514125","514126","514127","514128","514129",
        "541447","554405"
    ); Country = 'United States' },
    @{ Issuer = 'Wells Fargo Bank, N.A.';                Type = 'VISA';                 Bins = @(
        "400175","400425","401371","401372","401373","401374","401392","401393","401394","401395",
        "401396","401671","401714","401755","401757","401911","401915","401928","401932","401934",
        "401935","401936","401937","401950","401952","401992","402241","402489","402710","403122",
        "403126","403129","403136","403137","403458","403718","403790","404010","404013","404019",
        "404023","404030","404033","404037","404040","404048","404053","404054","404065","404067"
    ); Country = 'United States' },
    @{ Issuer = 'JSCB Lefco Bank';                       Type = 'VISA';                 Bins = @("405229","405231"); Country = 'Uzbekistan' }
)

# Type -> brand name used in events (same names as the card-scheme rules, so Wazuh/dashboard
# values stay consistent). Lookup is case-insensitive; unknown types are reported as written.
$TypeToBrand = @{
    'VISA' = 'Visa'; 'MASTERCARD' = 'Mastercard'; 'MAESTRO' = 'Maestro'; 'NEPALPAY' = 'NEPALPAY'
    'AMERICAN EXPRESS' = 'Amex'; 'AMEX' = 'Amex'; 'JCB' = 'JCB'
    'DINERS CLUB INTERNATIONAL' = 'Diners Club'; 'DINERS CLUB' = 'Diners Club'
    'CHINA UNION PAY' = 'UnionPay'; 'UNIONPAY' = 'UnionPay'
    'RUPAY' = 'RuPay'; 'DISCOVER' = 'Discover'; 'MIR' = 'Mir'
}

# flatten the groups into one row per BIN for the detection engine
$BinRows = @(foreach ($grp in $BinGroups) {
    $brand = ([string]$grp.Type).Trim()
    if ($brand -and $TypeToBrand.ContainsKey($brand)) { $brand = $TypeToBrand[$brand] }
    foreach ($bin in $grp.Bins) {
        [pscustomobject]@{ Bin = [string]$bin; Brand = $brand; Issuer = [string]$grp.Issuer; Country = [string]$grp.Country }
    }
})

# Flat list of home-country BINs (used for the scan header and anywhere a plain BIN list is needed)
$validBinsArray = @($BinRows | Where-Object { $_.Country -eq $HomeCountry } | ForEach-Object { $_.Bin })

$skipCards = @(
    "4364442222222222",
    "4020100102020000",
    "4020100202020000"
)

# -------------------------------
# Tier 2 (LOW confidence): global card scheme IIN ranges
# Each range is "Lo-Hi" (or a single prefix) compared against the first N digits of the PAN,
# where N is the number of digits in Lo (e.g. "2221-2720" checks the first 4 digits).
# Rules are tried in order and the first one whose prefix AND length both fit names the brand,
# so more specific / co-branded ranges go before broader ones (NEPALPAY sits inside Discover's 65).
# Defunct schemes (enRoute, Voyager) are not included: enRoute PANs were not Luhn-checked
# and neither scheme has issued cards for decades.
# -------------------------------
$BrandRuleDefs = @(
    @{ Brand = 'NEPALPAY';    Lengths = @(16);                Ranges = @('658794-658796') },
    @{ Brand = 'Amex';        Lengths = @(15);                Ranges = @('34', '37') },
    @{ Brand = 'Diners Club'; Lengths = @(14,16,17,18,19);    Ranges = @('300-305') },
    @{ Brand = 'Diners Club'; Lengths = @(14,15,16,17,18,19); Ranges = @('36') },
    @{ Brand = 'Diners Club'; Lengths = @(16,17,18,19);       Ranges = @('38-39') },
    @{ Brand = 'JCB';         Lengths = @(16,17,18,19);       Ranges = @('3528-3589') },
    @{ Brand = 'Mir';         Lengths = @(16,17,18,19);       Ranges = @('2200-2204') },
    @{ Brand = 'Mastercard';  Lengths = @(16);                Ranges = @('51-55', '2221-2720') },
    @{ Brand = 'Maestro';     Lengths = @(12,13,14,15,16,17,18,19)
                              Ranges  = @('5018', '5020', '5038', '5893', '6304', '6759', '6761-6763') },
    @{ Brand = 'UnionPay';    Lengths = @(16,17,18,19);       Ranges = @('62') },
    @{ Brand = 'Discover';    Lengths = @(16,17,18,19);       Ranges = @('6011', '644-649', '65') },
    @{ Brand = 'RuPay';       Lengths = @(16);                Ranges = @('60', '81-82', '508') },
    @{ Brand = 'Visa';        Lengths = @(13,16,19);          Ranges = @('4') }
)

# -------------------------------
# Card detection engine (compiled C#)
# Candidate extraction, Luhn, BIN and scheme checks run in compiled code: doing them in
# PowerShell functions was ~20x slower on number-heavy logs. Add-Type compiles this once per
# run with the .NET compiler that ships with Windows - nothing extra to install.
#
# Candidates are digit runs of 12-19 digits, optionally split by single spaces or dashes in any
# grouping (4-4-4-4, 4-6-5 Amex, 4-6-4 Diners, 4-4-4-4-3 ...). The zero-width lookahead makes the
# regex report a candidate at the start of EVERY digit group, so a card that directly follows
# another number ("2024 4438 3412 3456 0524") is still found. The first digit must be a scheme
# start digit (2,3,4,5,6,8), which cheaply discards most numeric noise. For each candidate every
# possible end point (before a separator, or the end of the run) is tried, longest first; a
# high-confidence reading wins over a low one.
# -------------------------------
if (-not ('CardScanV34.Detector' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace CardScanV34 {
    public sealed class Hit {
        public string Pan;        // digits only - kept in memory for de-duplication, never written out
        public string Raw;        // as written in the file (with separators)
        public string Brand;
        public string Confidence; // "high" | "low"
        public string Issuer;     // issuer from $BinGroups (foreign issuers get "(Country)"), null if BIN unknown
        public string Basis;      // what the BIN matched: home BIN | known BIN (low tier) | generic prefix | scheme range
        public int Score;         // 0-100 confidence score
        public bool HasExpiry;    // expiry date found near the number
        public bool HasCvv;       // CVV/CVC found near the number (value never stored)
    }

    public static class Detector {
        sealed class Range { public int Lo, Hi, Len; }
        sealed class Rule {
            public string Brand;
            public Dictionary<int, bool> Lengths = new Dictionary<int, bool>();
            public List<Range> Ranges = new List<Range>();
        }

        static readonly Regex Rx = new Regex(@"(?<![0-9A-Za-z_])(?=([2-68](?:[- ]?[0-9]){11,18}))",
                                             RegexOptions.Compiled | RegexOptions.CultureInvariant);
        sealed class BinInfo { public string Issuer, Brand; public bool Low; }
        static Dictionary<string, BinInfo> localBins = new Dictionary<string, BinInfo>();   // BIN -> issuer/brand/tier
        static int[] binLens = new int[0];
        static Dictionary<string, bool> skip = new Dictionary<string, bool>();
        static List<Rule> rules = new List<Rule>();
        static bool includeLow = true;
        public static bool StrictLayout = true;     // only real card digit groupings
        public static int ContextChars = 100;       // characters checked on each side of a number
        public static int ScoreHomeBin = 60, ScoreKnownLowBin = 40, ScoreGenericPrefix = 35, ScoreSchemeOnly = 25;
        public static int ScoreExpiry = 20, ScoreCvv = 25, HighScore = 60;

        // Expiry: MM/YY, MM-YY, MM/YYYY (years 2015-2049), not part of a longer date like 2023-12-05 or 05/12/2023
        const string ExpCore = @"(0[1-9]|1[0-2])\s?[/\-]\s?(20(1[5-9]|[2-4][0-9])|1[5-9]|[2-4][0-9])";
        const RegexOptions CtxOpts = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;
        static readonly Regex ExpRx = new Regex(@"(?<![0-9/.\-])" + ExpCore + @"(?![0-9/.\-])", CtxOpts);
        // keyword form also accepts MMYY: "Exp 1227", "VALID THRU 12/27"
        static readonly Regex ExpKwRx = new Regex(
            @"\b(exp(iry|iration|ires)?(\s*date)?|valid\s*(thru|through|till|until)|good\s*thru)\b\W{0,12}(0[1-9]|1[0-2])\s?[/\-]?\s?(20(1[5-9]|[2-4][0-9])|1[5-9]|[2-4][0-9])(?![0-9])", CtxOpts);
        // CVV: keyword followed by 3-4 digits ("CVV: 123", "CVC2 4567", "security code 123")
        static readonly Regex CvvKwRx = new Regex(
            @"\b(cvv2?|cvc2?|cvn2?|csc|card\s*(security|verification)\s*(code|value)|security\s*code)\b\W{0,10}[0-9]{3,4}(?![0-9])", CtxOpts);
        // CVV by position: a 3-4 digit value right next to an expiry date ("12/27,123" / "123|12/27"), not a year
        static readonly Regex CvvAfterExpRx = new Regex(
            @"(?<![0-9/.\-])" + ExpCore + @"[\s,;|""']{1,4}(?!(19|20)[0-9]{2}(?![0-9]))[0-9]{3,4}(?![0-9/.\-])", CtxOpts);
        static readonly Regex CvvBeforeExpRx = new Regex(
            @"(?<![0-9/.\-])(?!(19|20)[0-9]{2}(?![0-9]))[0-9]{3,4}[\s,;|""']{1,4}" + ExpCore + @"(?![0-9/.\-])", CtxOpts);

        // Adds context evidence to a hit and sets its final score / confidence
        static void ScoreContext(Hit h, string text, int start, int end) {
            int ws = Math.Max(0, start - ContextChars);
            int we = Math.Min(text.Length, end + ContextChars);
            // the card number itself is left out so its digits can't be read as a date or CVV
            string ctx = text.Substring(ws, start - ws) + "\n" + text.Substring(end, we - end);
            h.HasExpiry = ExpRx.IsMatch(ctx) || ExpKwRx.IsMatch(ctx);
            h.HasCvv = CvvKwRx.IsMatch(ctx) || CvvAfterExpRx.IsMatch(ctx) || CvvBeforeExpRx.IsMatch(ctx);
            if (h.HasExpiry) h.Score += ScoreExpiry;
            if (h.HasCvv) h.Score += ScoreCvv;
            if (h.Score > 100) h.Score = 100;
            h.Confidence = h.Score >= HighScore ? "high" : "low";
        }
        public static string DemoteIssuer = null;   // issuer label whose hits count as low confidence

        // ruleDefs: "Brand|len,len,...|lo-hi,prefix,..."
        public static void Configure(string[] bins, string[] issuers, string[] brands, bool[] lowTier,
                                     string[] skipCards, string[] ruleDefs, bool detectLow) {
            // Dictionary/List only (mscorlib) so this compiles under Windows PowerShell 5.1 and PowerShell 7 alike
            localBins = new Dictionary<string, BinInfo>();
            var lens = new List<int>();
            for (int i = 0; i < bins.Length; i++) {
                localBins[bins[i]] = new BinInfo {
                    Issuer = issuers[i],
                    Brand  = string.IsNullOrEmpty(brands[i]) ? null : brands[i],
                    Low    = lowTier[i]
                };
                if (!lens.Contains(bins[i].Length)) lens.Add(bins[i].Length);
            }
            lens.Sort();
            lens.Reverse();                         // longest BIN prefix first
            binLens = lens.ToArray();
            skip = new Dictionary<string, bool>();
            foreach (var c in skipCards) skip[c] = true;
            rules = new List<Rule>();
            foreach (var def in ruleDefs) {
                var p = def.Split('|');
                var r = new Rule { Brand = p[0] };
                foreach (var l in p[1].Split(',')) r.Lengths[int.Parse(l)] = true;
                foreach (var rg in p[2].Split(',')) {
                    var lh = rg.Split('-');
                    r.Ranges.Add(new Range { Lo = int.Parse(lh[0]), Hi = int.Parse(lh.Length > 1 ? lh[1] : lh[0]), Len = lh[0].Length });
                }
                rules.Add(r);
            }
            includeLow = detectLow;
        }

        public static bool Luhn(string s) {
            int sum = 0; bool dbl = false;
            for (int i = s.Length - 1; i >= 0; i--) {
                int d = s[i] - '0';
                if (dbl) { d *= 2; if (d > 9) d -= 9; }
                sum += d; dbl = !dbl;
            }
            return sum % 10 == 0;
        }

        public static string GetBrand(string pan) {
            foreach (var r in rules) {
                if (!r.Lengths.ContainsKey(pan.Length)) continue;
                foreach (var g in r.Ranges) {
                    int p = int.Parse(pan.Substring(0, g.Len));
                    if (p >= g.Lo && p <= g.Hi) return r.Brand;
                }
            }
            return null;
        }

        // Longest matching BIN from the reference table, or null
        static BinInfo GetBinInfo(string pan) {
            BinInfo info;
            foreach (var l in binLens)
                if (pan.Length >= l && localBins.TryGetValue(pan.Substring(0, l), out info)) return info;
            return null;
        }

        public static string GetLocalIssuer(string pan) {
            var info = GetBinInfo(pan);
            return info == null ? null : info.Issuer;
        }

        static Hit NewHit(string pan, string brand, string issuer, string basis, int score) {
            return new Hit { Pan = pan, Brand = brand, Issuer = issuer, Basis = basis, Score = score,
                             Confidence = score >= HighScore ? "high" : "low" };
        }

        public static Hit Classify(string pan) {
            if (skip.ContainsKey(pan) || !Luhn(pan)) return null;
            string brand = GetBrand(pan);
            var info = GetBinInfo(pan);
            if (info != null) {
                // known BIN: 16 digits, or any length a card-scheme rule allows (e.g. 15-digit Amex)
                if (brand != null || pan.Length == 16) {
                    string label = info.Brand ?? brand ?? "Local BIN";     // BIN table brand is authoritative
                    if (info.Issuer == DemoteIssuer)
                        return NewHit(pan, label, info.Issuer, "generic prefix", ScoreGenericPrefix);
                    if (info.Low)
                        return NewHit(pan, label, info.Issuer, "known BIN (low tier)", ScoreKnownLowBin);
                    return NewHit(pan, label, info.Issuer, "home BIN", ScoreHomeBin);
                }
                return null;
            }
            if (brand != null) return NewHit(pan, brand, null, "scheme range", ScoreSchemeOnly);
            return null;
        }

        // Real card layouts: one unbroken group, or groups starting with 4 digits whose middle groups
        // are 4 or 6 digits and whose last group is 1-6 digits (4-4-4-4, 4-6-5, 4-6-4, 4-4-4-4-3 ...)
        static bool LayoutOk(List<int> groups) {
            if (!StrictLayout || groups.Count == 1) return true;
            if (groups[0] != 4) return false;
            for (int i = 1; i < groups.Count - 1; i++)
                if (groups[i] != 4 && groups[i] != 6) return false;
            int last = groups[groups.Count - 1];
            return last >= 1 && last <= 6;
        }

        static bool IsWordChar(char c) {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
        }

        public static List<Hit> Find(string text) {
            var hits = new List<Hit>();
            int acceptedEnd = -1;
            var digits = new StringBuilder(19);
            var endDigits = new List<int>(8);
            var endRaw = new List<int>(8);
            var groups = new List<int>(8);

            foreach (Match m in Rx.Matches(text)) {
                var g = m.Groups[1];
                if (g.Index < acceptedEnd) continue;    // a digit group inside a card already accepted

                string raw = g.Value;
                int after = g.Index + g.Length;
                bool nextWord = after < text.Length && IsWordChar(text[after]);

                digits.Clear(); endDigits.Clear(); endRaw.Clear(); groups.Clear();
                int cur = 0;
                for (int i = 0; i < raw.Length; i++) {
                    char c = raw[i];
                    if (c < '0' || c > '9') continue;
                    digits.Append(c);
                    cur++;
                    bool last = i == raw.Length - 1;
                    bool groupEnd = last || raw[i + 1] == ' ' || raw[i + 1] == '-';
                    if (!groupEnd) continue;
                    groups.Add(cur); cur = 0;
                    bool boundary = last ? !nextWord : true;
                    if (boundary && digits.Length >= 12 && LayoutOk(groups)) { endDigits.Add(digits.Length); endRaw.Add(i + 1); }
                }
                if (endDigits.Count == 0) continue;

                string all = digits.ToString();
                Hit best = null; int bestRaw = 0;
                for (int k = endDigits.Count - 1; k >= 0; k--) {
                    var h = Classify(all.Substring(0, endDigits[k]));
                    if (h == null) continue;
                    if (h.Confidence == "high") { best = h; bestRaw = endRaw[k]; break; }
                    if (best == null) { best = h; bestRaw = endRaw[k]; }
                }
                if (best == null) continue;

                best.Raw = raw.Substring(0, bestRaw);
                acceptedEnd = g.Index + bestRaw;
                ScoreContext(best, text, g.Index, g.Index + bestRaw);
                if (best.Confidence == "low" && !includeLow) continue;
                hits.Add(best);
            }
            return hits;
        }
    }
}
'@
}

# parallel arrays for the engine; warn about bad or duplicate rows (the later row would win)
$binList    = New-Object 'System.Collections.Generic.List[string]'
$issuerList = New-Object 'System.Collections.Generic.List[string]'
$brandList  = New-Object 'System.Collections.Generic.List[string]'
$lowList    = New-Object 'System.Collections.Generic.List[bool]'
$binOwner = @{}
foreach ($row in $BinRows) {
    $bin = ([string]$row.Bin).Trim()
    if ($bin -notmatch '^\d{4,8}$') { Write-Warning "Ignoring BIN table row with invalid BIN '$bin'"; continue }
    $isHome = ([string]$row.Country).Trim() -eq $HomeCountry
    $label  = ([string]$row.Issuer).Trim()
    if (-not $isHome) { $label = "$label ($(([string]$row.Country).Trim()))" }
    if ($binOwner.ContainsKey($bin) -and $binOwner[$bin] -ne $label) {
        Write-Warning "BIN $bin is listed under both '$($binOwner[$bin])' and '$label' - using '$label'"
    }
    $binOwner[$bin] = $label
    $binList.Add($bin); $issuerList.Add($label); $brandList.Add(([string]$row.Brand).Trim())
    $lowList.Add((-not $isHome) -and $ForeignBinConfidence -ne 'high')
}
$localBinCount   = @($BinRows | Where-Object { $_.Country -eq $HomeCountry }).Count
$foreignBinCount = $BinRows.Count - $localBinCount

[CardScanV34.Detector]::Configure(
    [string[]]$binList,
    [string[]]$issuerList,
    [string[]]$brandList,
    [bool[]]$lowList,
    [string[]]$skipCards,
    [string[]]@($BrandRuleDefs | ForEach-Object { "$($_.Brand)|$($_.Lengths -join ',')|$($_.Ranges -join ',')" }),
    [bool]$DetectLowConfidence)
[CardScanV34.Detector]::StrictLayout = [bool]$StrictCardGrouping
[CardScanV34.Detector]::ContextChars       = [int]$ContextWindowChars
[CardScanV34.Detector]::ScoreHomeBin       = [int]$ScoreHomeBin
[CardScanV34.Detector]::ScoreKnownLowBin   = [int]$ScoreKnownLowBin
[CardScanV34.Detector]::ScoreGenericPrefix = [int]$ScoreGenericPrefix
[CardScanV34.Detector]::ScoreSchemeOnly    = [int]$ScoreSchemeOnly
[CardScanV34.Detector]::ScoreExpiry        = [int]$ScoreExpiry
[CardScanV34.Detector]::ScoreCvv           = [int]$ScoreCvv
[CardScanV34.Detector]::HighScore          = [int]$HighConfidenceScore
[CardScanV34.Detector]::DemoteIssuer = $(if ($UnmappedBinConfidence -eq 'low') { 'Unmapped local BIN' } else { $null })

$latin1 = [System.Text.Encoding]::GetEncoding(28591)

function Reset-ScanState {
    # Full PANs are held only in memory for de-duplication; only masked values are written out
    $script:seenCards  = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:findingByRaw = @{}                                                  # raw text -> finding
    $script:findings   = New-Object 'System.Collections.Generic.List[object]'   # one per distinct written format
    $script:cardsWithExpiry = 0
    $script:cardsWithCvv    = 0
    $script:maxScore        = 0
    $script:brandsSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:issuersSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:highCards  = 0
    $script:lowCards   = 0
    $script:limitHit   = $false
    $script:timedOut   = $false
    $script:fileTimer  = [System.Diagnostics.Stopwatch]::StartNew()
}

function Test-StopScan {
    if ($script:limitHit -or $script:timedOut) { return $true }
    if ($script:fileTimer.Elapsed.TotalSeconds -gt $MaxFileScanSeconds) {
        $script:timedOut = $true
        return $true
    }
    return $false
}

# "expiry + CVV nearby" style evidence text for reports
function Get-EvidenceText {
    param ($Finding, [switch]$Plain)
    $e = @($Finding.Basis)
    if ($Finding.HasExpiry) { $e += 'expiry nearby' }
    if ($Finding.HasCvv)    { $e += 'CVV nearby' }
    if ($Plain) { return ($e -join ', ') }
    return ", " + ($e -join ', ')
}

# Masks digits only, keeping the original spaces/dashes so the format is visible
# e.g. 4438-3412-3456-0524 -> 4438-34**-****-0524
# PANs shorter than 15 digits show only the last 4 (first 6 + last 4 would expose most of the number)
function Get-MaskedCard {
    param ([string]$Raw)
    $totalDigits = ($Raw -replace '\D', '').Length
    $showFirst = $(if ($totalDigits -ge 15) { $MaskShowFirst } else { 0 })
    if ($totalDigits -le ($showFirst + $MaskShowLast)) { return ($Raw -replace '\d', '*') }
    $sb  = New-Object System.Text.StringBuilder
    $idx = 0
    foreach ($ch in $Raw.ToCharArray()) {
        if ([char]::IsDigit($ch)) {
            if ($idx -lt $showFirst -or $idx -ge ($totalDigits - $MaskShowLast)) { [void]$sb.Append($ch) }
            else { [void]$sb.Append('*') }
            $idx++
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

# Records every valid card number found in the text
function Test-Text {
    param ([string]$Text)
    $hits = [CardScanV34.Detector]::Find($Text)
    if ($hits.Count -eq 0) { return }
    foreach ($h in $hits) {
        $f = $script:findingByRaw[$h.Raw]
        if ($f) {
            # same written number seen again (e.g. in the overlap between read chunks): merge evidence
            if ($h.HasExpiry) { $f.HasExpiry = $true }
            if ($h.HasCvv)    { $f.HasCvv    = $true }
            if ($h.Score -gt $f.Score) { $f.Score = $h.Score; $f.Confidence = $h.Confidence }
        } else {
            # list every distinct written format (plain, spaced, dashed) of each card
            $f = [pscustomobject]@{
                Masked     = (Get-MaskedCard $h.Raw)
                Brand      = $h.Brand
                Confidence = $h.Confidence
                Issuer     = $h.Issuer
                Basis      = $h.Basis
                Score      = $h.Score
                HasExpiry  = $h.HasExpiry
                HasCvv     = $h.HasCvv
                Pan        = $h.Pan          # in memory only, for per-card totals - never written out
            }
            $script:findingByRaw[$h.Raw] = $f
            $script:findings.Add($f)
        }
        if ($script:seenCards.Add($h.Pan)) {
            [void]$script:brandsSeen.Add($h.Brand)
            if ($h.Issuer) { [void]$script:issuersSeen.Add($h.Issuer) }
            if ($script:seenCards.Count -ge $MaxCardsPerFile) { $script:limitHit = $true; break }
        }
    }
    Update-CardTotals
}

# Per-card totals: a card's evidence is combined across all the formats it was written in
function Update-CardTotals {
    $cards = @{}
    foreach ($f in $script:findings) {
        $c = $cards[$f.Pan]
        if (-not $c) { $c = @{ Score = 0; Expiry = $false; Cvv = $false }; $cards[$f.Pan] = $c }
        if ($f.Score -gt $c.Score) { $c.Score = $f.Score }
        if ($f.HasExpiry) { $c.Expiry = $true }
        if ($f.HasCvv)    { $c.Cvv    = $true }
    }
    $script:highCards = 0; $script:lowCards = 0
    $script:cardsWithExpiry = 0; $script:cardsWithCvv = 0; $script:maxScore = 0
    foreach ($c in $cards.Values) {
        if ($c.Score -ge $HighConfidenceScore) { $script:highCards++ } else { $script:lowCards++ }
        if ($c.Expiry) { $script:cardsWithExpiry++ }
        if ($c.Cvv)    { $script:cardsWithCvv++ }
        if ($c.Score -gt $script:maxScore) { $script:maxScore = $c.Score }
    }
}

# -------------------------------
# OCR (images) - Windows.Media.Ocr via WinRT, Windows PowerShell 5.1 only
# -------------------------------
$script:ocrReady  = $false
$script:ocrStatus = 'disabled'

function Initialize-Ocr {
    if (-not $EnableOcr) { return }
    if ($IsLinux -or $IsMacOS) { $script:ocrStatus = 'unavailable: Windows only'; return }
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        # PowerShell 7 (.NET 5+) dropped built-in WinRT projection, so the OCR types can't be loaded
        $script:ocrStatus = 'unavailable: run with Windows PowerShell 5.1 (powershell.exe), not pwsh'
        return
    }
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
        $null = [Windows.Storage.Streams.RandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
        $null = [Windows.Foundation.IAsyncOperation`1, Windows.Foundation, ContentType = WindowsRuntime]
        $null = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Foundation, ContentType = WindowsRuntime]
        $null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime]
        $null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
        $null = [Windows.Globalization.Language, Windows.Foundation, ContentType = WindowsRuntime]

        # Generic AsTask(IAsyncOperation<T>) - lets us wait on WinRT async calls with a timeout
        $script:asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() |
            Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
                           $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } |
            Select-Object -First 1

        # Explicit language first: when running as SYSTEM (scheduled task / GPO) there are
        # no user-profile languages, so TryCreateFromUserProfileLanguages() returns $null
        $lang = New-Object Windows.Globalization.Language $OcrLanguage
        if ([Windows.Media.Ocr.OcrEngine]::IsLanguageSupported($lang)) {
            $script:ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
        }
        if (-not $script:ocrEngine) {
            $script:ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
        }
        if (-not $script:ocrEngine) {
            $script:ocrStatus = "unavailable: no OCR language installed (Add-WindowsCapability -Online -Name 'Language.OCR~~~$OcrLanguage~0.0.1.0')"
            return
        }
        $script:ocrReady  = $true
        $script:ocrStatus = "enabled ($($script:ocrEngine.RecognizerLanguage.LanguageTag))"
    } catch {
        $script:ocrStatus = "unavailable: $($_.Exception.Message)"
    }
}

function Wait-WinRt {
    param ($AsyncOp, [Type]$ResultType)
    $task = $script:asTaskGeneric.MakeGenericMethod($ResultType).Invoke($null, @($AsyncOp))
    try {
        if (-not $task.Wait([int]($OcrTimeoutSeconds * 1000))) {
            throw (New-Object System.TimeoutException "OCR did not finish within $OcrTimeoutSeconds s")
        }
    } catch [System.TimeoutException] {
        throw
    } catch {
        # PowerShell wraps .NET errors (MethodInvocationException -> AggregateException -> real cause)
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        throw $ex
    }
    return $task.Result
}

# Returns the recognised text of an image (one line per OCR line), or $null if the image is too small
function Get-OcrText {
    param ([string]$FilePath)
    $file   = Wait-WinRt ([Windows.Storage.StorageFile]::GetFileFromPathAsync($FilePath)) ([Windows.Storage.StorageFile])
    $stream = Wait-WinRt ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    try {
        $decoder = Wait-WinRt ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        if ($decoder.PixelWidth -lt $OcrMinPixelWidth) {
            $script:imagesSkippedSmall++
            Write-Verbose "OCR skipped (only $($decoder.PixelWidth) px wide): $FilePath"
            return $null
        }
        $maxDim = [Windows.Media.Ocr.OcrEngine]::MaxImageDimension
        if ($decoder.PixelWidth -gt $maxDim -or $decoder.PixelHeight -gt $maxDim) {
            throw "image is $($decoder.PixelWidth)x$($decoder.PixelHeight) px, above the OCR limit of $maxDim px"
        }
        $bitmap = Wait-WinRt ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        try {
            $result = Wait-WinRt ($script:ocrEngine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
        } finally {
            $bitmap.Dispose()
        }
        return (@($result.Lines | ForEach-Object { $_.Text }) -join "`n")
    } finally {
        $stream.Dispose()
    }
}

# OCR commonly misreads digits as look-alike letters (O->0, I/l->1, S->5, B->8). Inside short
# groups that are otherwise digits (at most one look-alike), swap them back so the card regex
# can match. Luhn + BIN/scheme checks still guard against false positives.
$ocrGroupRegex = New-Object System.Text.RegularExpressions.Regex '(?<![0-9A-Za-z])[0-9OoIlSB]{3,6}(?![0-9A-Za-z])'
function ConvertFrom-OcrText {
    param ([string]$Text)
    $Text = $Text -replace '[ \t]+', ' '
    return $ocrGroupRegex.Replace($Text, {
        param ($m)
        $v = $m.Value
        if (($v -replace '[0-9]', '').Length -gt 1) { return $v }
        return ($v -replace '[Oo]', '0' -replace '[Il]', '1' -replace 'S', '5' -replace 'B', '8')
    })
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
        $carryLen = [Math]::Max(64, 2 * $ContextWindowChars + 40)   # card + its context on both sides
        if ($text.Length -gt $carryLen) { $carry = $text.Substring($text.Length - $carryLen) } else { $carry = $text }
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

Initialize-Ocr

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
OCR: $($script:ocrStatus)

"@
Save-OutputToFile $executionDetails

Write-JsonEvent -EventType "scan_started" -Data ([ordered]@{
    is_admin      = $isAdmin
    scan_scope    = @($ScanRoots)
    script_path   = $ScriptPath
    max_file_scan_seconds = $MaxFileScanSeconds
    max_cards_per_file    = $MaxCardsPerFile
    strict_card_grouping  = [bool]$StrictCardGrouping
    unmapped_bin_confidence = $UnmappedBinConfidence
    track_changes         = [bool]$TrackChanges
    local_bins            = $localBinCount
    foreign_bins          = $foreignBinCount
    foreign_bin_confidence = $ForeignBinConfidence
    context_window_chars  = $ContextWindowChars
    high_confidence_score = $HighConfidenceScore
    ocr_enabled           = $script:ocrReady
    ocr_status            = $script:ocrStatus
})

Write-Host "Card Scanning Started..." -ForegroundColor Cyan
Write-Host "Scan scope: $($ScanRoots -join ', ')" -ForegroundColor Cyan
if (-not $isAdmin -and -not ($IsLinux -or $IsMacOS)) {
    Write-Host "WARNING: not running as Administrator - other users' profiles and protected folders will be skipped." -ForegroundColor Yellow
}
if ($EnableOcr -and -not $script:ocrReady) {
    Write-Host "WARNING: OCR requested but $($script:ocrStatus) - images will not be scanned." -ForegroundColor Yellow
} elseif ($script:ocrReady) {
    Write-Host "OCR: $($script:ocrStatus)" -ForegroundColor Cyan
}
Write-Host "----------------------------------------" -ForegroundColor Cyan

# -------------------------------
# Scan files
# -------------------------------
$totalFiles = 0
$totalFilesWithMatches = 0
$totalFilesSkipped = 0
$totalCardsFound = 0
$totalHighCards = 0
$totalLowCards = 0
$totalFilesHigh = 0
$totalCvvCards = 0
$totalFilesCvv = 0
$totalExpiryCards = 0
$totalImagesOcr = 0
$script:imagesSkippedSmall = 0

# -------------------------------
# Change tracking state: file path -> "signature|first_seen". The signature is a SHA-256 of the
# file's masked findings, so no card data is kept in the state file.
# -------------------------------
$previousState = @{}
$currentState  = @{}
$skippedPaths  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
if ($TrackChanges -and (Test-Path -LiteralPath $LocalStateFile)) {
    try {
        $raw = Get-Content -LiteralPath $LocalStateFile -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($prop in $raw.PSObject.Properties) { $previousState[$prop.Name] = [string]$prop.Value }
    } catch {
        Write-Warning "Could not read change-tracking state ($LocalStateFile) - all findings will be reported as new: $($_.Exception.Message)"
    }
}
$sha256 = [System.Security.Cryptography.SHA256]::Create()
function Get-FindingSignature {
    param ($FileItem, $Findings)
    # findings only: re-saving a file with the same cards is not a new exposure
    $text = (@($Findings | ForEach-Object {
                "$($_.Masked)/$($_.Confidence)$(if ($_.HasExpiry) { '/exp' })$(if ($_.HasCvv) { '/cvv' })" }) | Sort-Object) -join ';'
    return [BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '')
}
$newFindings = 0; $changedFindings = 0; $unchangedFindings = 0
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
        $full = $_.FullName
        foreach ($pattern in $ExcludePathPatterns) {
            if ($full -like $pattern) { return $false }
        }

        if ([string]::IsNullOrEmpty($_.Extension)) { return $IncludeNoExtension }

        # images are only selected when OCR is working, and only within a plausible size range
        if ($ocrSet.Contains($_.Extension)) {
            if (-not $script:ocrReady) { return $false }
            if ($_.Length -lt ($OcrMinFileSizeKB * 1KB) -or $_.Length -gt ($OcrMaxFileSizeMB * 1MB)) {
                # counted and shown with -Verbose so a filtered test image isn't a silent mystery
                $script:imagesSkippedSmall++
                Write-Verbose "OCR skipped (size $([math]::Round($_.Length / 1KB, 1)) KB outside $OcrMinFileSizeKB KB - $OcrMaxFileSizeMB MB): $($_.FullName)"
                return $false
            }
            return $true
        }
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

        $scanMethod = 'raw'

        try {
            if ($ocrSet.Contains($extension)) {
                $scanMethod = 'ocr'
                $totalImagesOcr++
                $ocrText = Get-OcrText $filePath
                if ($ocrText) { Test-Text (ConvertFrom-OcrText $ocrText) }
            }
            elseif ($zipSet.Contains($extension)) {
                $scanMethod = 'zip'
                try {
                    Test-Zip $filePath
                } catch {
                    # Not a real archive (e.g. a CSV renamed to .xlsx/.ods): read it as plain bytes
                    # instead of skipping it, so renaming a file can't hide card data
                    if ($_.Exception.ToString() -notmatch 'InvalidDataException|Central Directory|not a valid') { throw }
                    $scanMethod = 'raw-fallback'
                    Reset-ScanState
                    $fs = [System.IO.File]::Open($filePath, [System.IO.FileMode]::Open,
                                                 [System.IO.FileAccess]::Read,
                                                 [System.IO.FileShare]::ReadWrite)
                    try { Test-Stream $fs } finally { $fs.Dispose() }
                }
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
        } catch [System.TimeoutException] {
            $script:timedOut = $true
        } catch {
            $errorMessage = $_.Exception.Message
        }

        if ($script:findings.Count -gt 0) {
            # cards found (even if the file later errored or timed out)
            $totalFilesWithMatches++
            $totalCardsFound += $script:seenCards.Count
            $totalHighCards  += $script:highCards
            $totalLowCards   += $script:lowCards
            $fileConfidence  = $(if ($script:highCards -gt 0) { 'high' } else { 'low' })
            if ($fileConfidence -eq 'high') { $totalFilesHigh++ }
            $totalCvvCards    += $script:cardsWithCvv
            $totalExpiryCards += $script:cardsWithExpiry
            if ($script:cardsWithCvv -gt 0) { $totalFilesCvv++ }

            # compare with the previous scan of this host
            $findingStatus = 'new'; $firstSeen = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            if ($TrackChanges) {
                $sig = Get-FindingSignature $fileItem $script:findings
                if ($previousState.ContainsKey($filePath)) {
                    $prevSig, $prevFirst = $previousState[$filePath] -split '\|', 2
                    if ($prevFirst) { $firstSeen = $prevFirst }
                    $findingStatus = $(if ($prevSig -eq $sig) { 'unchanged' } else { 'changed' })
                }
                $currentState[$filePath] = "$sig|$firstSeen"
            }
            switch ($findingStatus) { 'new' { $newFindings++ } 'changed' { $changedFindings++ } default { $unchangedFindings++ } }

            $countText = "$($script:seenCards.Count)"
            if ($script:limitHit) { $countText += "+ (limit reached, scan of file stopped)" }

            $lines = @("File: $filePath",
                       "  MATCH FOUND: Clear-text card data detected [confidence: $($fileConfidence.ToUpper())] [$findingStatus]$(if ($scanMethod -eq 'ocr') { ' (via OCR)' })",
                       "  Unique cards: $countText (high: $($script:highCards), low: $($script:lowCards)) | with expiry nearby: $($script:cardsWithExpiry) | with CVV nearby: $($script:cardsWithCvv)")
            if ($script:cardsWithCvv -gt 0) { $lines += "  WARNING: CVV/security code stored next to card number(s) - sensitive authentication data" }
            $script:findings | ForEach-Object {
                $issuerText = $(if ($_.Issuer) { ", $($_.Issuer)" } else { "" })
                $lines += "    - $($_.Masked)  [$($_.Brand), $($_.Confidence)$issuerText, score $($_.Score)$(Get-EvidenceText $_)]"
            }
            if ($script:timedOut)  { $lines += "  Note: timed out after $MaxFileScanSeconds s - rest of file not scanned" }
            if ($errorMessage)     { $lines += "  Note: read error before scan completed ($errorMessage)" }

            $msg = $lines -join "`n"
            Write-Host $msg -ForegroundColor $(if ($fileConfidence -eq 'high') { 'Green' } else { 'DarkYellow' })
            Save-OutputToFile $msg

            Write-JsonEvent -EventType "card_detected" -Data ([ordered]@{
                file_path       = $filePath
                file_name       = $fileItem.Name
                file_extension  = $extension
                file_size_bytes = $fileItem.Length
                file_modified   = $fileItem.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                file_owner      = (Get-FileOwner $filePath)
                scan_method     = $scanMethod
                confidence      = $fileConfidence
                finding_status  = $findingStatus
                first_seen      = $firstSeen
                unique_cards    = $script:seenCards.Count
                high_confidence_cards = $script:highCards
                low_confidence_cards  = $script:lowCards
                brands          = @($script:brandsSeen)
                issuers         = @($script:issuersSeen)
                confidence_score = $script:maxScore
                cards_with_expiry = $script:cardsWithExpiry
                cards_with_cvv  = $script:cardsWithCvv
                card_details    = @($script:findings | ForEach-Object {
                                      "$($_.Masked) | $($_.Brand) | $(if ($_.Issuer) { $_.Issuer } else { 'Unknown issuer' }) | $($_.Confidence) | score $($_.Score) | $(Get-EvidenceText $_ -Plain)" })
                formats_found   = $script:findings.Count
                masked_cards    = @($script:findings | ForEach-Object { $_.Masked })
                masked_cards_high = @($script:findings | Where-Object { $_.Confidence -eq 'high' } | ForEach-Object { $_.Masked })
                masked_cards_low  = @($script:findings | Where-Object { $_.Confidence -eq 'low' } | ForEach-Object { $_.Masked })
                limit_reached   = $script:limitHit
                scan_complete   = -not ($script:timedOut -or $errorMessage -or $script:limitHit)
                note            = $(if ($script:timedOut) { "timed out" } elseif ($errorMessage) { "read error: $errorMessage" } else { $null })
            })
        }
        elseif ($script:timedOut) {
            [void]$skippedPaths.Add($filePath)
            $totalFilesSkipped++
            Write-Host "  Skipped (read timeout): $filePath" -ForegroundColor Yellow
            $limitText = $(if ($scanMethod -eq 'ocr') { "$OcrTimeoutSeconds s OCR limit" } else { "$MaxFileScanSeconds s" })
            Save-OutputToFile "File: $filePath`n  Skipped (read timeout after $limitText)"
            Write-JsonEvent -EventType "file_skipped" -Data ([ordered]@{
                file_path       = $filePath
                file_size_bytes = $fileItem.Length
                scan_method     = $scanMethod
                reason          = "timeout"
                error_message   = "no result within $limitText"
            })
        }
        elseif ($errorMessage) {
            [void]$skippedPaths.Add($filePath)
            $totalFilesSkipped++
            Write-Host "  Skipped (read error): $filePath" -ForegroundColor Yellow
            Save-OutputToFile "File: $filePath`n  Skipped (read error: $errorMessage)"
            Write-JsonEvent -EventType "file_skipped" -Data ([ordered]@{
                file_path       = $filePath
                file_size_bytes = $fileItem.Length
                scan_method     = $scanMethod
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

# -------------------------------
# Change tracking: resolved findings + save state
# A previous finding counts as resolved only if its file was inside this scan's scope, was not
# skipped (timeout/read error), and is not an image skipped because OCR is off/unavailable.
# Anything outside this run's scope is carried over unchanged.
# -------------------------------
$resolvedFindings = 0
if ($TrackChanges) {
    foreach ($oldPath in @($previousState.Keys)) {
        if ($currentState.ContainsKey($oldPath)) { continue }
        $inScope = $false
        foreach ($root in $ScanRoots) {
            if ($oldPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { $inScope = $true; break }
        }
        $oldExt = [System.IO.Path]::GetExtension($oldPath)
        $ocrGap = $ocrSet.Contains($oldExt) -and -not $script:ocrReady
        if (-not $inScope -or $skippedPaths.Contains($oldPath) -or $ocrGap) {
            $currentState[$oldPath] = $previousState[$oldPath]      # not re-checked this run - keep it
            continue
        }
        $resolvedFindings++
        $stillExists = Test-Path -LiteralPath $oldPath
        $firstSeenOld = ($previousState[$oldPath] -split '\|', 2)[1]
        $resolvedMsg = "File: $oldPath`n  RESOLVED: no card data found any more$(if (-not $stillExists) { ' (file deleted/moved)' })"
        Write-Host $resolvedMsg -ForegroundColor Cyan
        Save-OutputToFile $resolvedMsg
        Write-JsonEvent -EventType "finding_resolved" -Data ([ordered]@{
            file_path    = $oldPath
            file_name    = [System.IO.Path]::GetFileName($oldPath)
            file_exists  = $stillExists
            first_seen   = $firstSeenOld
            resolution   = $(if ($stillExists) { 'cleaned' } else { 'deleted_or_moved' })
        })
    }
    try {
        $stateObj = [ordered]@{}
        foreach ($k in ($currentState.Keys | Sort-Object)) { $stateObj[$k] = $currentState[$k] }
        $stateJson = ConvertTo-Json -InputObject $stateObj -Compress
        [System.IO.File]::WriteAllText($LocalStateFile, $stateJson, (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        Write-Warning "Could not save change-tracking state to $LocalStateFile : $($_.Exception.Message)"
    }
}
$summary = @"
----------------------------------------
Scan Completed.
Scan Scope: $($ScanRoots -join ', ')
Duration: $([int]$duration.TotalHours)h $($duration.Minutes)m $($duration.Seconds)s
Total Files Scanned: $totalFiles
Total Files Containing Valid Card Data: $totalFilesWithMatches
Total Unique Card Numbers Found (per-file, masked in report): $totalCardsFound
  - High confidence (score >= $HighConfidenceScore): $totalHighCards
  - Low confidence (score < $HighConfidenceScore): $totalLowCards
  - With expiry date nearby: $totalExpiryCards
  - With CVV nearby: $totalCvvCards (in $totalFilesCvv file(s))
Files With High-Confidence Matches: $totalFilesHigh
OCR: $($script:ocrStatus) | Images OCR'd: $totalImagesOcr | Images skipped by size/width: $($script:imagesSkippedSmall) (details with -Verbose)
Findings vs previous scan: new $newFindings | changed $changedFindings | unchanged $unchangedFindings | resolved $resolvedFindings
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
    findings_new            = $newFindings
    findings_changed        = $changedFindings
    findings_unchanged      = $unchangedFindings
    findings_resolved       = $resolvedFindings
    files_scanned           = $totalFiles
    files_with_card_data    = $totalFilesWithMatches
    unique_cards_found      = $totalCardsFound
    high_confidence_cards   = $totalHighCards
    cards_with_expiry       = $totalExpiryCards
    cards_with_cvv          = $totalCvvCards
    files_with_cvv          = $totalFilesCvv
    low_confidence_cards    = $totalLowCards
    files_with_high_confidence = $totalFilesHigh
    images_ocr_scanned      = $totalImagesOcr
    images_ocr_skipped_size = $script:imagesSkippedSmall
    ocr_status              = $script:ocrStatus
    files_skipped           = $totalFilesSkipped
    folders_unreadable      = $script:deniedFolders.Count
    is_admin                = $isAdmin
})

if ($Host.Name -eq 'ConsoleHost') {
    Write-Host ""
    Write-Host "Scan finished. Press ENTER to close this window." -ForegroundColor White
    [void][System.Console]::ReadLine()
}
