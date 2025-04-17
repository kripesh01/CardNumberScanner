## 🔍 PowerShell Script to Scan for Card Numbers in Clear Text Files — A Must-Have Tool for Banks

## 🚀 Overview

Storing card numbers in cleartext is a serious security risk — one that can lead to non-compliance, data breaches, and reputational damage. This PowerShell script was developed to **scan for unencrypted card numbers** across various file types on Windows systems.

Whether you're conducting a PCI-DSS compliance review, an internal audit, or proactively securing your infrastructure, this script will help you **identify and log any 16-digit card numbers found in plaintext**, verifying them with the Luhn algorithm and checking against a known set of valid BINs (Bank Identification Numbers).

---

## 📦 Features

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
- 🔒 Add more valid BINs to the `$validBinsArray` if your organization uses others.
- 🚫 Modify the `$skipCards` array to exclude internal test cards or whitelisted samples.

---
## 🛡️ Disclaimer
This script is provided *as-is*. Always test in a safe environment before running on production machines. You are responsible for ensuring it aligns with your organization’s policies and regulations.

---
