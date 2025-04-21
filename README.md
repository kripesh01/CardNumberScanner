## 🔍 PowerShell Script to Scan for Card Numbers in Clear Text Files — A Must-Have Security Tool

## 🚀 Overview

Storing card numbers in cleartext is a serious security risk — one that can lead to non-compliance, data breaches, and reputational damage. This PowerShell script was developed to **scan for unencrypted card numbers** across various file types on Windows systems.

Whether you're conducting a PCI-DSS compliance review, an internal audit, or proactively securing your infrastructure, this script will help you **identify and log any 16-digit card numbers found in plaintext**, verifying them with the Luhn algorithm and checking against a known set of valid BINs (Bank Identification Numbers).

---

## 📦 Features

- ✅ **Automatically installs required PowerShell modules**
- ✅ **Recursive directory scanning**
- ✅ **Supports multiple file types**: `.txt`, `.csv`, `.log`, `.json`, `.xml`, `.docx`, `.xlsx`, etc.
- ✅ **Validates card numbers using the Luhn algorithm**
- ✅ **Filters matches by real-world BINs to reduce false positives**
- ✅ **Skips common test cards**
- ✅ **Logs results both locally and to a specified network share**
- ✅ **Colored terminal output for matches and summary**

---

## 🛠️ Requirements

- OS: Windows 10/11, Server 2016+  
- PowerShell 5.1 or later  
- Sufficient permissions to scan files and write to `P:` drive (network path)

---

## 📂 File Output

The script generates two logs:

1. `output.txt` – A local file in the same directory as the script.
2. `\\P\CARDSCAN\<hostname>-<timestamp>-output.txt` – A backup/log copy on a mapped network share.

---

## 🧪 What It Scans

The script scans for **16-digit numeric strings** and performs the following checks:

- First 4 digits match a **known BIN**.
- Passes the **Luhn checksum**.
- Not in a **test card exclusion list**.

---

## ⚙️ How to Use

1. **Clone the repository** or download the `.ps1` file:

   ```powershell
   git clone https://github.com/kripesh01/CardNumberScanner.git
   cd CardNumberScanner

2. **Run PowerShell as Administrator** (optional but recommended).

3. **Execute the script**
    ```powershell
    .\CardScanner.ps1
    ```
4.  **View the results:**
- Output is printed to the console.
- Logs are saved in the current directory and to the network path `(P:\CARDSCAN).`

---
## 📊 Example Output
    Card Scanning Started...
    ----------------------------------------
    File: C:\Users\John\Documents\client_data.txt
    Match: 4020123456789012

    File: C:\HR\exports\july.csv
    Match: 5210123456784321

    ----------------------------------------
    Scan Completed.
    Total Files Scanned: 412
    Total Valid Card Matches Found: 2
    Results saved to:
    - output.txt
    - P:\CARDSCAN\HOSTNAME-20250411-output.txt
---
## 🧠 Why This Matters
**“Sensitive data should never live in plaintext.”**   
This script is part of a larger security hygiene effort — ensuring compliance with standards like PCI-DSS, ISO/IEC 27001, and general data minimization practices. It’s a quick win in your organization's internal audit checklist.

---
## 🧩 Customization
- ✏️ Add more file extensions to the `$textRelatedExtensions` array.
    ```powershell
    # File extensions to scan (commonly used to store or export data)

    $textRelatedExtensions = @(".txt", ".log", ".docx", ".xlsx", ".csv", ".xml", ".json", ".doc", ".xls", ".sql", ".conf")
    ```
- 🔒 Add more valid BINs to the `$validBinsArray` if your organization uses others.
    ```powershell
    #Valid BINs (Bank Identification Numbers) to filter potential card numbers

    $validBinsArray = @("3771", "4020", "4024", "4029", "4030", "4031", "4037", "4050", "4055", "4056", "4061", "4067", "4089", "4090", "4101", "4107", "4135", "4162", "4181", "4182", "4189", "4206", "4211", "4214", "4226", "4232", "4235", "4284", "4317", "4336", "4359", "4363", "4364", "4368", "4373", "4390", "4391", "4393", "4404", "4424", "4430", "4438", "4500", "4504", "4511", "4520", "4574", "4577", "4579", "4581", "4587", "4595", "4610", "4617", "4619", "4622", "4624", "4637", "4660", "4662", "4689", "4705", "4709", "4748", "4775", "4813", "4837", "4848", "4862", "4895", "4897", "4922", "4924", "4938", "4987", "5116", "5181", "5210", "5218", "5246", "5399", "5421", "5434", "5436", "5483", "5484", "5486", "5487", "5543", "5559", "6365")
    ```
- 🚫 Modify the `$skipCards` array to exclude internal test cards or whitelisted samples.
    ```powershell
    #Skip test card numbers to avoid false positives

    $skipCards = @("4364442222222222", "4020100102020000", "4020100202020000")
    ```
- 🗂️ Modify network log path via `$NetworkOutputFile` to customize destination directory.
    ```powershell
    # Define output file locations

    $NetworkOutputFile = "Drive:\CARDSCAN\$HostName-$TimeStamp-output.txt"  # Save results to network path
    ```
---
## 🧾 Tool Comparison
| Feature                              | 🛠️ PowerShell Script | 🕷️ CUPSPIDER | 🔍 PANfinder | 💼 Commercial Tools |
|--------------------------------------|:--------------------:|:------------:|:------------:|:-------------------:|
| Open Source                          | ✅ Yes                | ✅ Yes       | ✅ Yes       | ❌ No               |
| Text File Scanning                   | ✅ Yes                | ✅ Yes       | ✅ Yes       | ✅ Yes              |
| Office File Support (.docx, .xlsx)   | ✅ Yes                | ❌ No        | ❌ No        | ✅ Yes              |
| Luhn Algorithm Validation            | ✅ Yes                | ✅ Yes       | ✅ Yes       | ✅ Yes              |
| Valid BIN Filtering                  | ✅ Yes                | ❌ No        | ❌ No        | ✅ Yes              |
| Test Card Exclusion                  | ✅ Yes                | ❌ No        | ❌ No        | ✅ Yes              |
| Excel Export Support                 | ✅ Yes                | ❌ No        | ❌ No        | ✅ Yes              |
| Network Output Logging               | ✅ Yes                | ❌ No        | ❌ No        | ✅ Yes              |
| Fully Customizable                   | ✅ Script-Based       | ⚠️ Limited   | ⚠️ Limited   | ⚠️ GUI Configurable |
| OS Compatibility                     | ❌ Windows Only       | ✅ Cross-OS  | ✅ Cross-OS  | ✅ Mostly           |

## 🔍 Summary
- **For Internal Audits and PCI Compliance:** This script is a lightweight, fast, and reliable way to identify unsecured card data — especially useful in Windows-based enterprise environments.
- **Compared to Python tools:** While CUPSPIDER and PANfinder are powerful in Unix-style environments, they don’t support Office formats or network share logging.
- **Against commercial scanners:** Tools like Spirion or Ground Labs offer GUI dashboards, deep integrations, and advanced analytics — but at a cost. Your script offers a solid, free alternative with just the features you need.
---
## 🛡️ Disclaimer
This script is provided *as-is*. Always test in a safe environment before running on production machines. You are responsible for ensuring it aligns with your organization’s policies and regulations.
---
