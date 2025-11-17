# NodeHawk

**NodeHawk** is a lightweight, cross-platform command-line web reconnaissance tool written in Python. Despite the name, it is **not a Node.js scanner**—it is designed to gather basic information about websites, making it ideal for security enthusiasts, developers, and researchers who want to perform quick website reconnaissance.

---

## **Features**

* **Website Status Check**
  Checks if a website is online by sending an HTTP request and printing the status code. Uses **colorama** to highlight results in color:

  * Green ✅ for online
  * Yellow ⚠ for other statuses
  * Red ❌ for errors

* **Link Crawling**
  Fetches the homepage HTML, parses it using **BeautifulSoup**, and extracts unique links found on the page (default limit: 20).

* **Vulnerability Scanning (Placeholder)**
  Includes a basic framework for future security checks such as SQL Injection, XSS, or insecure headers. Currently, this feature is a placeholder and does not perform actual vulnerability checks.

---

## **Installation**

1. **Clone the repository**

```bash
git clone https://github.com/wsuits6/nodehawk.git
cd nodehawk
```

2. **Create a virtual environment (recommended)**

```bash
python -m venv venv
```

3. **Activate the virtual environment**

* Windows (PowerShell):

```powershell
.\venv\Scripts\Activate.ps1
```

* Windows (CMD):

```cmd
.\venv\Scripts\activate.bat
```

* Linux / macOS:

```bash
source venv/bin/activate
```

4. **Install dependencies**

```bash
pip install -r requirements.txt
```

---

## **Usage**

Run NodeHawk from the command line:

```bash
python -m nodehawk.cli.main
```

Follow the prompt and enter the website URL. NodeHawk will:

1. Check the website status.
2. Crawl the homepage and extract links.
3. Run the placeholder vulnerability check.

---

## **Folder Structure**

```
NodeHawk/
├── nodehawk/
│   ├── core/           # Scanner, crawler, vulnerability checker, utils
│   ├── cli/            # Command-line interface
│   ├── config/         # Default settings
│   └── output/         # Logs and scan results
├── examples/           # Example scripts
├── tests/              # Unit tests
├── README.md
├── requirements.txt
├── LICENSE
└── setup.py
```

---

## **Future Plans**

* Implement real vulnerability scanning modules (SQLi, XSS, insecure headers).
* Expand crawling to multiple pages and deeper site mapping.
* Add logging and report generation for scan results.
* Optional GUI for easier usage.

---

## **Contributing**

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch for your feature/fix
3. Submit a pull request describing your changes

---

## **License**

NodeHawk is released under the MIT License. See [LICENSE](LICENSE) for deta
