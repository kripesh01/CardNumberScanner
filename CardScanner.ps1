# ===============================
# PowerShell Script to Detect Clear-Text Card Numbers in Files
# Author: @kripesh01
# Purpose: Identify and log card numbers stored in clear text for compliance and security audits
# ===============================

# Define parameters to support verbose logging
[CmdletBinding()]
param ()
# Function to check internet connectivity
function Test-InternetConnection {
    Write-Verbose "Checking internet connectivity..."
    try {
        $result = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop
        Write-Verbose "Internet connectivity check result: $result"
        return $result
    } catch {
        Write-Verbose "Internet connectivity check failed: $_"
        return $false
    }
}
# Function to check and install required modules
function Ensure-Module {
    param (
        [string]$ModuleName
    )
    Write-Verbose "Checking for module '$ModuleName'..."
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Module '$ModuleName' not found." -ForegroundColor Yellow
        if (Test-InternetConnection) {
            Write-Host "Internet available. Attempting to install module '$ModuleName'..." -ForegroundColor Yellow
            try {
                Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
                Write-Host "Module '$ModuleName' installed successfully." -ForegroundColor Green
                return $true
            } catch {
                Write-Host "Failed to install module '$ModuleName': $_" -ForegroundColor Red
                Write-Verbose "Module installation failed. Will skip Excel file processing."
                return $false
            }
        } else {
            Write-Host "No internet connection. Skipping module '$ModuleName' installation." -ForegroundColor Yellow
            Write-Verbose "No internet. Module not installed. Will skip Excel file processing."
            return $false
        }
    } else {
        Write-Host "Module '$ModuleName' is already installed." -ForegroundColor Cyan
        return $true
    }
}
# Check for ImportExcel module and track its availability
$excelModuleAvailable = Ensure-Module -ModuleName "ImportExcel"
if ($excelModuleAvailable) {
    Import-Module ImportExcel -Force
}
# Get Host and User information
$HostName = $env:COMPUTERNAME
$UserName = $env:USERDOMAIN + "\" + $env:USERNAME
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
# Get the full path of the script location
$ScriptPath = $MyInvocation.MyCommand.Definition
$ScriptDirectory = Split-Path -Parent $ScriptPath
# Define output file locations
$NetworkOutputFile = "P:\CARDSCAN\$HostName-$TimeStamp-output.txt"  # Save results to network path
$LocalOutputFile = Join-Path -Path $ScriptDirectory -ChildPath "output.txt"  # Local output
# Remove the existing local output file if it exists
if (Test-Path $LocalOutputFile) {
    Write-Verbose "Removing existing local output file: $LocalOutputFile"
    Remove-Item -Path $LocalOutputFile -ErrorAction SilentlyContinue
}
# Array to store all matched card numbers for final display
$allMatches = @()
# Function to save output to both files (no console output unless verbose)
function Save-OutputToFile {
    param ([string]$Output)
    Write-Verbose "Saving output to files: $LocalOutputFile, $NetworkOutputFile"
    $Output | Out-File -FilePath $LocalOutputFile -Append -ErrorAction SilentlyContinue
    $networkDirectory = Split-Path -Parent $NetworkOutputFile
    if (Test-Path $networkDirectory) {
        $Output | Out-File -FilePath $NetworkOutputFile -Append -ErrorAction SilentlyContinue
    } else {
        Write-Verbose "Network path $networkDirectory is not reachable."
    }
}
# Function to validate card numbers using the Luhn Algorithm
function Test-LuhnAlgorithm {
    param ([string]$CardNumber)
    Write-Verbose "Validating card number ${CardNumber} with Luhn Algorithm..."
    $digits = $CardNumber -split '' | Where-Object { $_ -match '\d' }
    $sum = 0
    $isEven = $false
    for ($i = $digits.Count - 1; $i -ge 0; $i--) {
        $digit = [int]$digits[$i]
        if ($isEven) {
            $doubled = $digit * 2
            $sum += if ($doubled -gt 9) { $doubled - 9 } else { $doubled }
        } else {
            $sum += $digit
        }
        $isEven = -not $isEven
    }
    $result = ($sum % 10 -eq 0)
    Write-Verbose "Luhn validation result for ${CardNumber}: $result"
    return $result
}
# Record execution details (only to file)
$executionDetails = @"
Script executed on: $HostName
User: $UserName
Execution Time: $TimeStamp
Script Location: $ScriptPath
"@
Save-OutputToFile -Output $executionDetails
Write-Host "Card Scanning Started..." -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan
# File extensions to scan
$textRelatedExtensions = @(".txt", ".log", ".docx", ".xlsx", ".csv", ".xml", ".json", ".doc", ".xls", ".sql", ".conf")
# Valid BINs (Bank Identification Numbers)
$validBinsArray = @(
    "3771", "4020", "4024", "4029", "4030", "4031", "4037", "4050", "4055", "4056", "4061", "4067",
    "4089", "4090", "4101", "4107", "4135", "4162", "4181", "4182", "4189", "4206", "4211", "4214",
    "4226", "4232", "4235", "4284", "4317", "4336", "4359", "4363", "4364", "4368", "4373", "4390",
    "4391", "4393", "4404", "4424", "4430", "4438", "4500", "4504", "4511", "4520", "4574", "4577",
    "4579", "4581", "4587", "4595", "4610", "4617", "4619", "4622", "4624", "4637", "4660", "4662",
    "4689", "4705", "4709", "4748", "4775", "4813", "4837", "4848", "4862", "4895", "4897", "4922",
    "4924", "4938", "4987", "5116", "5181", "5210", "5218", "5246", "5399", "5421", "5434", "5436",
    "5483", "5484", "5486", "5487", "5543", "5559", "6365"
)
$validBins = @{}
$validBinsArray | ForEach-Object { $validBins[$_] = $true }
# Skip test card numbers
$skipCards = @("4364442222222222", "4020100102020000", "4020100202020000")
# Initialize counters
$matchFound = $false
$totalFiles = 0
$totalMatches = 0
# Function to process .xlsx files
function Get-ExcelContent {
    param ([string]$FilePath)
    Write-Verbose "Processing Excel file: $FilePath"
    try {
        $excelData = Import-Excel -Path $FilePath -NoHeader
        $content = ""
        foreach ($row in $excelData) {
            foreach ($cell in $row.PSObject.Properties.Value) {
                if ($cell) { $content += "$cell " }
            }
        }
        Write-Verbose "Excel content extracted successfully."
        return $content
    } catch {
        Write-Verbose "Failed to process Excel file: $_"
        return $null
    }
}
# Function to process .docx files
function Get-DocxContent {
    param ([string]$FilePath)
    Write-Verbose "Processing Word document: $FilePath"
    try {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $doc = $word.Documents.Open($FilePath)
        $content = $doc.Content.Text
        $doc.Close()
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        Write-Verbose "Word document content extracted successfully."
        return $content
    } catch {
        Write-Verbose "Failed to process Word document: $_"
        return $null
    }
}
# Begin scanning files recursively
try {
    Get-ChildItem -Recurse -File -Include *.txt, *.log, *.docx, *.xlsx, *.csv, *.xml, *.json, *.doc, *.xls, *.sql, *.conf -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -ne $LocalOutputFile } | 
    ForEach-Object {
        $totalFiles++
        $filePath = $_.FullName
        $extension = $_.Extension.ToLower()
        Write-Host "Scanning: $filePath" -ForegroundColor White
        Write-Verbose "Processing file: $filePath (Extension: $extension)"
        try {
            $fileContent = $null
            $fileMatches = 0  # Counter for matches in the current file
            $uniqueMatches = @{}  # Track unique card numbers in this file
            if ($extension -eq ".xlsx") {
                if ($excelModuleAvailable) {
                    $fileContent = Get-ExcelContent -FilePath $filePath
                } else {
                    Write-Host "  Skipping Excel file (ImportExcel module not available)" -ForegroundColor Yellow
                    Write-Verbose "ImportExcel module not available. Skipping $filePath."
                    Save-OutputToFile -Output "Skipped file: $filePath (ImportExcel module not available)"
                    continue
                }
            } elseif ($extension -eq ".docx") {
                $fileContent = Get-DocxContent -FilePath $filePath
            } else {
                Write-Verbose "Reading text file content for: $filePath"
                $fileContent = Get-Content -Path $filePath -Raw -ErrorAction Stop
            }
            if ($fileContent) {
                Write-Verbose "Content retrieved. Applying regex for card number detection."
                $matches = [regex]::Matches($fileContent, '\b(\d{4})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b')
                Write-Verbose "Found $($matches.Count) potential card number matches."
                foreach ($match in $matches) {
                    $firstFourDigits = $match.Groups[1].Value
                    $fullMatch = $match.Value -replace '[-\s]', ''
                    Write-Verbose "Processing match: $fullMatch (BIN: $firstFourDigits)"
                    if ($skipCards -contains $fullMatch) {
                        Write-Verbose "Skipping test card: $fullMatch"
                        continue
                    }
                    if ($validBins.ContainsKey($firstFourDigits)) {
                        Write-Verbose "Valid BIN detected: $firstFourDigits"
                        if (Test-LuhnAlgorithm -CardNumber $fullMatch) {
                            if (-not $uniqueMatches.ContainsKey($fullMatch)) {
                                $matchFound = $true
                                $totalMatches++
                                $fileMatches++
                                $matchOutput = "File: $filePath`n  Match: $fullMatch"
                                Write-Host $matchOutput -ForegroundColor Green
                                Save-OutputToFile -Output $matchOutput
                                $allMatches += $fullMatch
                                $uniqueMatches[$fullMatch] = $true
                                Write-Verbose "Valid card number confirmed: $fullMatch"
                            } else {
                                Write-Verbose "Duplicate card number $fullMatch in $filePath, skipping."
                            }
                        } else {
                            Write-Verbose "Card number $fullMatch failed Luhn validation."
                        }
                    } else {
                        Write-Verbose "Invalid BIN: $firstFourDigits"
                    }
                }
                if ($fileMatches -eq 0) {
                    Write-Host "  No card numbers detected" -ForegroundColor Yellow
                    Write-Verbose "No valid card numbers found in $filePath."
                }
            } else {
                Write-Host "  No card numbers detected" -ForegroundColor Yellow
                Write-Verbose "No content retrieved from $filePath."
            }
        } catch {
            $errorMsg = "Error reading file: $filePath - $_"
            Save-OutputToFile -Output $errorMsg
            Write-Host "  No card numbers detected" -ForegroundColor Yellow
            Write-Verbose $errorMsg
        }
        Write-Verbose "Completed processing file: $filePath"
    }
} catch {
    $errorMsg = "Error in file scanning loop: $_"
    Write-Host $errorMsg -ForegroundColor Red
    Save-OutputToFile -Output $errorMsg
} finally {
    # Final summary report
    $summary = @"
----------------------------------------
Scan Completed.
Total Files Scanned: $totalFiles
Total Valid Card Matches Found: $totalMatches
Results saved to:
  - $LocalOutputFile
----------------------------------------
"@
    Write-Host $summary -ForegroundColor Cyan
    Save-OutputToFile -Output $summary
    Write-Host "Press Enter to exit." -ForegroundColor White
    $null = Read-Host
}
