<div align="center">

# MailEnable XSS Scanner 🚀

<a href="https://github.com/the-smart-shadow">
  <img alt="Developer" src="https://img.shields.io/badge/Developed%20by-The%20Smart%20Shadow-004D40?style=for-the-badge&logo=github">
</a>

<p align="center">
  <img alt="Language" src="https://img.shields.io/badge/Python-3.7+-blue.svg?style=flat-square&logo=python&logoColor=white">
  <img alt="Status" src="https://img.shields.io/badge/Status-Active-green.svg?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square">
</p>

</div>

An advanced and high-speed scanner for detecting the persistent Cross-Site Scripting (XSS) vulnerability in `MailEnable v10`, identified as . This tool is designed to be effective, with a rich user interface, and flexible enough to meet the needs of security researchers and penetration testers.

---

### 🌟 Key Features

* **⚡️ Blazing Fast:** Utilizes multi-threading to scan hundreds of targets in record time.
* **🎨 Rich User Interface:** A visually appealing and interactive command-line interface powered by the `rich` library, featuring colors, a progress bar, and organized tables.
* **🎯 Multi-Target Support:** You can scan a single target or a whole list of targets from a text file.
* **⚙️ Flexible Configuration:** Full control over the number of threads, connection timeout, and the output file for results.
* **🧠 Smart URL Handling:** The tool automatically cleans and parses URLs to extract the base domain, ensuring accurate scanning.
* **💾 Automatic Reporting:** All vulnerable targets are automatically saved to a text file, with a detailed summary table displayed at the end of the scan.

---

### 📸 Screenshot

<div align="center">

![Screenshot of the tool in action](https://filebin.net/pkdetlsic17k3zz8/photo_2025-07-04_23-58-08.jpg)

</div>

---

### 🛠️ Installation

To get the tool up and running, follow these simple steps:

**1. Clone the repository:**
```bash
git clone [https://github.com/alifirasshadow/Advanced-XSS-Scanner.git](https://github.com/alifirasshadow/Advanced-XSS-Scanner.git)
cd mailenable-scanner
```

**2. Create the requirements file:**
Create a new file named `requirements.txt` and add the following libraries to it:
```
requests
rich
urllib3
```

**3. Install dependencies:**
```bash
pip install -r requirements.txt
```

---

### 🚀 How to Use

The tool is easy to use and supports several scenarios:

**1. Scan a single target:**
```bash
python3 xxss.py [http://target-domain.com](http://target-domain.com)
```

**2. Scan a list of targets from a file:**
```bash
# Create a targets.txt file and place each target on a new line.
python3 xxss.py targets.txt
```

**3. Use advanced options:**
You can customize the scan to fit your needs.
```bash
# Use 100 threads, a 15-second timeout, and save results to results.txt
python3 xxss.py targets.txt -t 100 --timeout 15 -o results.txt
```

**Help Menu:**
To display all available options:
```bash
python3 xxss.py -h
```

---

### ⚖️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. The developer (`The Smart Shadow`) is not responsible for any illegal or malicious use of this tool. Use it at your own risk and only on systems you have explicit permission to test.

---
<div align="center">
Made with ❤️ by The Smart Shadow
</div>
