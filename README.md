🔍 PowerShell Script to Scan for Card Numbers in Clear Text Files — A Must-Have Tool for Banks

💡 Why This Script Matters
Handling card data securely is a critical responsibility for any financial institution. With increasing regulations like PCI-DSS, banks are required to ensure that cardholder data is not stored in clear text — whether intentionally or by accident.
However, in real-world operations, sensitive card numbers sometimes find their way into text files, logs, reports, or exported spreadsheets due to system misconfigurations or human error. That’s where this PowerShell script comes in.
This script automates the detection of clear-text card numbers across files within a system. It helps identify compliance violations, detect potential data leaks, and strengthen internal security posture.

🛠️ What Does the Script Do?
    ✅ Scans recursively through text-based files (.txt, .csv, .log, .xml, .docx, .xlsx, etc.).
    ✅ Detects potential card numbers using pattern matching and validates them with the Luhn algorithm.
    ✅ Filters only valid BIN numbers used by actual cards.
    ✅ Skips known test card numbers to avoid false positives.
    ✅ Saves all scan results to both a local file and a network path.
    ✅ Provides a summary report at the end.

🔐 Why It’s Important for Banks
    🔎 Helps in auditing stored files for sensitive data exposure.
    📋 Ensures compliance with PCI-DSS requirements.
    🚨 Acts as a preventive measure to reduce risks of data leakage or breaches.
    📁 Makes regular card data scanning a simple, automated task.
    🧑‍💻 Can be scheduled to run periodically or used on-demand during audits or incident response.

🚀 How to Run the Script
This script is written in PowerShell and designed for use in a Windows environment.

🔹 Step-by-step Instructions:
    1. Open PowerShell as Administrator (Recommended).
    2. Save the script into a .ps1 file, for example: CardScan.ps1.
    3. Make sure the drive P:\CARDSCAN\ exists or update the path accordingly in the script.
    4. Run the script:
        .\CardScan.ps1
    5. The script will:
    - Start scanning the current directory and its subfolders.
    - Log execution details and results.
    - Show valid card matches on the screen.
    - Save a full output in:
    - The script directory (output.txt)
    - A network folder (P:\CARDSCAN\HOSTNAME-TIMESTAMP-output.txt)

🧠 How It Works (Behind the Scenes)
    The script gets the host and user details, plus the location where it is run.
    It defines common text-based file extensions where card data might be stored.
    It looks for 16-digit numbers starting with approved BINs.
    Uses the Luhn algorithm to validate if the number could be a legitimate card.
    If it finds any matches, it logs the file path and the number, helping the auditor investigate further.

✅ Conclusion
This card scan script offers a simple yet powerful way to enhance card data security within a bank’s internal systems. It's especially useful for compliance checks, security audits, or preparing for regulatory inspections.
Regular use of this script ensures that your team is actively looking for and eliminating any stored cardholder data that could lead to security breaches or regulatory penalties.
    Start scanning your systems today and take a proactive step in protecting sensitive customer data.test
