# SQL Injection Scanner 🚨

## 🚀 Overview

The **SQL Injection Scanner** is a powerful tool designed to detect SQL injection vulnerabilities on websites by scanning and testing their forms. With its simple and easy-to-use interface, this tool automatically checks for potential weaknesses in web applications that could be exploited by attackers.

### 🔍 Key Features:
- **Form Detection**: Identifies all forms on a target website.
- **SQL Injection Testing**: Tests forms for common SQL injection vulnerabilities.
- **Detailed Output**: Provides a detailed report on which forms are vulnerable and which are not.
- **HTTP Methods Supported**: Supports both `GET` and `POST` request methods for form submissions.
  
This project is designed for penetration testers, cybersecurity enthusiasts, and developers to quickly identify security holes in their web applications.

---

### 🔧 How It Works
Form Detection: The tool scans the given URL and automatically detects all available forms.

Input Field Analysis: It examines input fields (like text, password, hidden) in the forms.

SQL Injection Testing: For each form, the script submits test data with SQL injection characters (', "), and checks if the server responds with error messages typical of SQL injection vulnerabilities.

Results: It outputs whether any of the forms are vulnerable to SQL injection.

---

### 💡 Vulnerability Detection

The SQL Injection Scanner looks for specific error messages that indicate the presence of SQL injection vulnerabilities, including:

SQL syntax errors: "You have an error in your SQL syntax"

MySQL-related errors: "Warning: mysql_fetch_array()"

Unterminated quotes: "Unclosed quotation mark after the character string"

If any of these are found, the scanner flags the form as vulnerable.

---

## Disclaimer

This project is intended for **educational purposes only**.

By using this tool, you agree to the following:

- You are solely responsible for how you use this script.
- You will not use it to scan or probe any network, device, or system without **explicit permission**.
- The author is **not liable** for any misuse, damage, legal consequences, or ethical violations resulting from the use of this software.

Port scanning can be flagged as malicious activity. **Unauthorized use is illegal** in many countries and can result in **criminal charges**.

Use it responsibly. Use it legally.

---

### 📚 Requirements
This script requires the following Python libraries:

requests: To send HTTP requests to the target website.

beautifulsoup4: To parse and extract HTML content from the website.

urllib3: For handling URL-related tasks.

---

## 🛠️ Installation

To run the SQL Injection Scanner, you need to have Python installed along with a few libraries. Follow these steps to set it up:

### 1. Clone the Repository

```bash
git clone https://github.com/BLA573/sql-injection-scanner.git
cd sql-injection-scanner

pip install -r requirements.txt

