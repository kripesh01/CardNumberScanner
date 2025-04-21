# ===============================
# PowerShell Script to Detect Clear-Text Card Numbers in Files
# Author: @kripesh01
# Purpose: Identify and log card numbers stored in clear text for compliance and security audits
# ===============================

# Function to check and install required modules
function Ensure-Module {
    param (
        [string]$ModuleName
    )

    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Module '$ModuleName' not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
            Write-Host "Module '$ModuleName' installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Failed to install module '$ModuleName': $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Module '$ModuleName' is already installed." -ForegroundColor Cyan
    }
}

# Ensure required module is installed
Ensure-Module -ModuleName "ImportExcel"

# Import the module after ensuring it's available
Import-Module ImportExcel -Force

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
    Remove-Item -Path $LocalOutputFile -ErrorAction SilentlyContinue
}

# Function to save output to both files (only save to network if path exists)
function Save-OutputToFile {
    param ([string]$Output)

    # Always write to local output
    $Output | Out-File -FilePath $LocalOutputFile -Append -ErrorAction SilentlyContinue

    # Write to network location only if path is reachable
    $networkDirectory = Split-Path -Parent $NetworkOutputFile
    if (Test-Path $networkDirectory) {
        $Output | Out-File -FilePath $NetworkOutputFile -Append -ErrorAction SilentlyContinue
    }
}

# Function to validate card numbers using the Luhn Algorithm
function Test-LuhnAlgorithm {
    param ([string]$CardNumber)

    # Extract digits and initialize variables
    $digits = $CardNumber -split '' | Where-Object { $_ -match '\d' }
    $sum = 0
    $isEven = $false

    # Loop through digits from right to left
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

    return ($sum % 10 -eq 0)
}

# Record execution details
$executionDetails = @"
Script executed on: $HostName
User: $UserName
Execution Time: $TimeStamp
Script Location: $ScriptPath
"@
Save-OutputToFile -Output $executionDetails

Write-Host "Card Scanning Started..." -ForegroundColor Cyan
Write-Host "----------------------------------------"

# File extensions to scan (commonly used to store or export data)
$textRelatedExtensions = @(".txt", ".log", ".docx", ".xlsx", ".csv", ".xml", ".json", ".doc", ".xls", ".sql", ".conf")

# Valid BINs (Bank Identification Numbers) to filter potential card numbers
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
# Convert array to hashtable for faster lookup
$validBins = @{}
$validBinsArray | ForEach-Object { $validBins[$_] = $true }

# Skip test card numbers to avoid false positives
$skipCards = @("4364442222222222", "4020100102020000", "4020100202020000")

# Initialize counters
$matchFound = $false
$totalFiles = 0
$totalMatches = 0

# Function to process .xlsx files using ImportExcel
function Get-ExcelContent {
    param ([string]$FilePath)

    try {
        # Import the Excel file
        $excelData = Import-Excel -Path $FilePath -NoHeader
        $content = ""
        # Concatenate all cell values into a single string
        foreach ($row in $excelData) {
            foreach ($cell in $row.PSObject.Properties.Value) {
                if ($cell) { $content += "$cell " }
            }
        }
        return $content
    } catch {
        return $null
    }
}

# Function to process .docx files using Word COM object
function Get-DocxContent {
    param ([string]$FilePath)

    try {
        # Create Word COM object
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $doc = $word.Documents.Open($FilePath)
        $content = $doc.Content.Text
        $doc.Close()
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        return $content
    } catch {
        return $null
    }
}

# Begin scanning files recursively
Get-ChildItem -Recurse -File -Include *.txt, *.log, *.docx, *.xlsx, *.csv, *.xml, *.json, *.doc, *.xls, *.sql, *.conf -ErrorAction SilentlyContinue | 
Where-Object { $_.FullName -ne $LocalOutputFile } | 
ForEach-Object {
    $totalFiles++
    $filePath = $_.FullName
    $extension = $_.Extension.ToLower()

    # Display progress: Show the file being scanned
    Write-Host "Scanning: $filePath" -ForegroundColor White

    try {
        $fileContent = $null
        $fileMatches = 0  # Counter for matches in the current file

        # Handle file content based on extension
        if ($extension -eq ".xlsx") {
            $fileContent = Get-ExcelContent -FilePath $filePath
        } elseif ($extension -eq ".docx") {
            $fileContent = Get-DocxContent -FilePath $filePath
        } else {
            # Use Get-Content for text-based files
            $fileContent = Get-Content -Path $filePath -Raw -ErrorAction Stop
        }

        if ($fileContent) {
            # Match pattern for 16-digit numbers, capture the first 4 digits
            $matches = [regex]::Matches($fileContent, '\b(\d{4})\d{12}\b')

            foreach ($match in $matches) {
                $firstFourDigits = $match.Groups[1].Value
                $fullMatch = $match.Value

                # Skip known test cards
                if ($skipCards -contains $fullMatch) { continue }

                # Validate BIN and card number using Luhn algorithm
                if ($validBins.ContainsKey($firstFourDigits) -and (Test-LuhnAlgorithm -CardNumber $fullMatch)) {
                    $matchFound = $true
                    $totalMatches++
                    $fileMatches++
                    $matchOutput = "File: $filePath`n  Match: $fullMatch"
                    # Display in console (only for matches)
                    Write-Host $matchOutput -ForegroundColor Green
                    # Save to file
                    Save-OutputToFile -Output $matchOutput
                    # Store the match for final display
                    $allMatches += $fullMatch
                }
            }

            # If no matches were found in this file, display a message
            if ($fileMatches -eq 0) {
                Write-Host "  No card numbers detected" -ForegroundColor Yellow
            }
        } else {
            # If file content couldn't be read, treat as no matches
            Write-Host "  No card numbers detected" -ForegroundColor Yellow
        }
    } catch {
        # Handle file read errors (e.g., access denied, corrupted files)
        Save-OutputToFile -Output "Error reading file: $filePath - $_"
        Write-Host "  No card numbers detected" -ForegroundColor Yellow
    }
}

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

Write-Host "Press Enter to exit."
$null = Read-Host
