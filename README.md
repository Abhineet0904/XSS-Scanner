# XSS-Scanner

A lightweight, educational **reflected-XSS scanner** that performs context-aware payload generation, context inference, parallel scanning, and HTML report generation.
**Use only on targets you own or have explicit permission to test. Unauthorized scanning may be illegal.**


---


## Features :
- Context-aware payload generation (tag-name, attribute-name, attribute-value, text, JS, JSON).
- Reflection detection with heuristic context inference.
- GET/POST support with optional JSON request bodies.
- Thread-pool–based parallel scanning.
- Auto-generated HTML report.
- Safe marker-based payload tracking.
- Clean terminal output with color formatting.

## Assumptions :
This tool is intended for educational use and makes the following assumptions :
- Target accepts GET/POST parameters directly as key-value pairs.
- Reflected XSS only is being tested — not stored or DOM-based XSS.
- The response is server-rendered HTML or textual content.
- Reflections appear in the raw response body, not after JavaScript execution.
- Site does not require:
  - CSRF tokens that must be dynamically extracted
  - JavaScript-based token generation
  - Multi-step authentication flows
- Parameters provided via --params are expected to be injectable.
- JSON testing assumes the server echoes some JSON or stringified data.


---


## How PayloadGenerator Chooses Payloads (Context-Aware Design) :
The scanner uses a marker-based system (e.g., XSS-1a2b3c4d) to uniquely track reflections.
Each context generates payloads designed to influence how the server outputs them :

1. **tag_name Context**
Used when a user-controlled value appears in tag names :
- `</XSS-xxxx>` attempts premature closing.
- `<XSS-xxxx` tests tag injection.
- Variants test malformed tag parsing.

2. **attr_name Context**
Used when the parameter is reflected inside an attribute name :
- `onXSS-xxxx=alert(1)` tests event-injection.
- `XSS-xxxx=1` checks attribute creation.
- `XSSxxxx-evt` tests malformed attributes.

3. **attr_value Context**
Used when the parameter appears inside an attribute value:
- `"XSS-xxxx"` basic quote breaking.
- `" onmouseover=alert(1)` event injection inside attributes.
- `'> <img…>` attempts value termination followed by payload.

4. **text Context**
Used when parameter appears inside HTML text. Targets HTML parsing :
- `<script>alert('marker')</script>`
- `<img onerror=alert(marker)>`
- `<svg onload=alert(marker)>`
- `<iframe srcdoc=...>`
- `<meta refresh=javascript:...>`
- `<form action='javascript:'>`
These cover many high-impact XSS vectors.

5. **js Context**
Used when the reflection is inside a <script> block :
- `';alert(marker);//`
- `");alert(marker);//`
These attempt literal, string, or statement-breaking injections.

6. **json Context**
Used when server echoes JSON :
- `"marker": "marker"`
- Escaped script tags : `\u003Cscript\u003E...`
- Raw HTML (`<img onerror>`), useful when JSON is printed into HTML later.


---


## Installation

1. Prerequisites :
```
python3 -m pip install requests beautifulsoup4 colorama
```

2. Clone or download the script :
```
git clone https://github.com/Abhineet0904/XSS-Scanner.git
cd xss-scanner
```


---


## Execution :
