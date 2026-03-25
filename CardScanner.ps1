# ===============================
# PowerShell Script to Detect Clear-Text Card Numbers in Files
# Author: @kripesh01
# Purpose: Identify and log clear-text card data for compliance audits
# ===============================

[CmdletBinding()]
param ()

# -------------------------------
# Configuration
# -------------------------------
$MaxFileScanSeconds = 120
$ExcelMaxRows       = 5000
$MaxFileSizeMB      = 200

# -------------------------------
# Internet connectivity check
# -------------------------------
function Test-InternetConnection {
    try {
        Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop
    } catch {
        $false
    }
}

# -------------------------------
# Ensure required module
# -------------------------------
function Ensure-Module {
    param ([string]$ModuleName)

    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        if (Test-InternetConnection) {
            try {
                Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
                return $true
            } catch {
                return $false
            }
        }
        return $false
    }
    return $true
}

# -------------------------------
# Import Excel module if possible
# -------------------------------
$excelModuleAvailable = Ensure-Module -ModuleName "ImportExcel"
if ($excelModuleAvailable) {
    Import-Module ImportExcel -Force
}

# -------------------------------
# Environment details
# -------------------------------
$HostName  = $env:COMPUTERNAME
$UserName  = "$($env:USERDOMAIN)\$($env:USERNAME)"
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$ScriptPath      = $MyInvocation.MyCommand.Definition
$ScriptDirectory = Split-Path -Parent $ScriptPath

$LocalOutputFile   = Join-Path $ScriptDirectory "output.txt"
$NetworkOutputFile = "P:\CARDSCAN\$HostName-$TimeStamp-output.txt"

if (Test-Path $LocalOutputFile) {
    Remove-Item $LocalOutputFile -ErrorAction SilentlyContinue
}

# -------------------------------
# Output writer
# -------------------------------
function Save-OutputToFile {
    param ([string]$Output)

    $Output | Out-File -FilePath $LocalOutputFile -Append -ErrorAction SilentlyContinue

    $netDir = Split-Path -Parent $NetworkOutputFile
    if (Test-Path $netDir) {
        $Output | Out-File -FilePath $NetworkOutputFile -Append -ErrorAction SilentlyContinue
    }
}

# -------------------------------
# Luhn validation
# -------------------------------
function Test-LuhnAlgorithm {
    param ([string]$CardNumber)

    $digits = $CardNumber.ToCharArray()
    $sum = 0
    $isEven = $false

    for ($i = $digits.Length - 1; $i -ge 0; $i--) {
        $d = [int]$digits[$i].ToString()
        if ($isEven) {
            $d *= 2
            if ($d -gt 9) { $d -= 9 }
        }
        $sum += $d
        $isEven = -not $isEven
    }
    return ($sum % 10 -eq 0)
}

# -------------------------------
# Execution header
# -------------------------------
$executionDetails = @"
Script executed on: $HostName
User: $UserName
Execution Time: $TimeStamp
Script Location: $ScriptPath

"@
Save-OutputToFile $executionDetails

Write-Host "Card Scanning Started..." -ForegroundColor Cyan
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
    "5483","5484","5486","5487","5543","5559","6365"
)

$validBins = @{}
$validBinsArray | ForEach-Object { $validBins[$_] = $true }

$skipCards = @(
    "4364442222222222",
    "4020100102020000",
    "4020100202020000"
)

# -------------------------------
# Scan files
# -------------------------------
$totalFiles = 0
$totalFilesWithMatches = 0

Get-ChildItem -Recurse -File -Include *.txt,*.log,*.docx,*.xlsx,*.csv,*.xml,*.json,*.doc,*.xls,*.sql,*.conf -ErrorAction SilentlyContinue |
Where-Object { $_.FullName -ne $LocalOutputFile } |
ForEach-Object {

    $totalFiles++
    $filePath  = $_.FullName
    $extension = $_.Extension.ToLower()

    Write-Host "Scanning: $filePath (started at $(Get-Date))" -ForegroundColor White
#    Save-OutputToFile "Scanning file: $filePath"

 #   if ($_.Length -gt ($MaxFileSizeMB * 1MB)) {
 #       Write-Host "  Skipped (file too large)" -ForegroundColor Yellow
 #       Save-OutputToFile "File: $filePath`n  Skipped (file size exceeds $MaxFileSizeMB MB)"
 #       return
 #   }

    $job = Start-Job {
        param ($path, $ext, $excelAvailable, $maxRows, $validBins, $skipCards)

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

        if ($ext -eq ".xlsx" -and $excelAvailable) {
            $cells = Import-Excel -Path $path -NoHeader -EndRow $maxRows |
                     ForEach-Object { $_.PSObject.Properties.Value }
            foreach ($cell in $cells) {
                if ($cell -match '\b(\d{4})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b') {
                    $card = $Matches[0] -replace '[-\s]', ''
                    if ($skipCards -contains $card) { continue }
                    if (-not $validBins.ContainsKey($card.Substring(0,4))) { continue }
                    if (Test-Luhn $card) { return $true }
                }
            }
            return $false
        }

        Get-Content -Path $path -ReadCount 500 | ForEach-Object {
            $chunk = $_ -join ' '
            $matches = [regex]::Matches($chunk, '\b(\d{4})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b')
            foreach ($m in $matches) {
                $card = $m.Value -replace '[-\s]', ''
                if ($skipCards -contains $card) { continue }
                if (-not $validBins.ContainsKey($card.Substring(0,4))) { continue }
                if (Test-Luhn $card) { return $true }
            }
        }
        return $false
    } -ArgumentList $filePath, $extension, $excelModuleAvailable, $ExcelMaxRows, $validBins, $skipCards

    if (-not (Wait-Job $job -Timeout $MaxFileScanSeconds)) {
        Stop-Job $job -Force
        Remove-Job $job
        Write-Host "  Skipped (read timeout)" -ForegroundColor Yellow
        Save-OutputToFile "File: $filePath`n  Skipped (read timeout)"
        return
    }

    $found = Receive-Job $job
    Remove-Job $job

    if ($found) {
        $totalFilesWithMatches++
        $msg = "File: $filePath`n  MATCH FOUND: Clear-text card data detected"
        Write-Host $msg -ForegroundColor Green
        Save-OutputToFile $msg
    }
    else {
        Write-Host "  No card numbers detected" -ForegroundColor Yellow
    }
}

# -------------------------------
# Summary
# -------------------------------
$summary = @"
----------------------------------------
Scan Completed.
Total Files Scanned: $totalFiles
Total Files Containing Valid Card Data: $totalFilesWithMatches
Results saved to:
  - $LocalOutputFile
----------------------------------------
"@

Write-Host $summary -ForegroundColor Cyan
Save-OutputToFile $summary

if ($Host.Name -eq 'ConsoleHost') {
    Write-Host ""
    Write-Host "Scan finished. Press ENTER to close this window." -ForegroundColor White
    [void][System.Console]::ReadLine()
}
