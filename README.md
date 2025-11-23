# Reflected XSS Scanner

A small **Python-based reflected XSS scanner** designed for web-application security testing.  
This tool injects context-aware payloads, detects reflections using marker-based matching, attempts auto-context detection, and produces both terminal and HTML reports.

**Use only on targets you own or have explicit permission to test. Unauthorized scanning may be illegal.**

---

## Features

- **PayloadGenerator** class that generates **context-aware payloads**, including :
  - `tag_name`
  - `attr_name` (attribute-name injection)
  - `attr_value`
  - `text`
  - `js`
  - `json` (for JSON POST bodies)

- **Reflection detection** via substring marker matching.

- **Supports GET and POST** requests (form or JSON).

- **Context auto-detection** (heuristic) :
  - tag-name
  - attribute-name
  - attribute-value
  - text node
  - JS block

- **Produces reports** :
  - Terminal output
  - HTML report (`xss_report.html`)

- **Optional features**
  - Parallel scanning (ThreadPoolExecutor)
  - Custom headers, cookies, and JSON-body scanning
  - Randomized marker-based payloads for simple WAF bypass

---

## 🛠️ Installation

Clone or download the script :
```
git clone https://github.com/your-repo/xss-scanner.git
cd xss-scanner
```
