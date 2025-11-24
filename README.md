# XSS-Scanner

A lightweight, educational **reflected-XSS scanner** that performs context-aware payload generation, context inference, parallel scanning, and HTML report generation.
**Use only on targets you own or have explicit permission to test. Unauthorized scanning may be illegal.**


---

---


## I. Features :
- Context-aware payload generation (tag-name, attribute-name, attribute-value, text, JS, JSON).
- Reflection detection with heuristic context inference.
- GET/POST support with optional JSON request bodies.
- Thread-pool–based parallel scanning.
- Auto-generated HTML report.
- Safe marker-based payload tracking.
- Clean terminal output with color formatting.

## II. Assumptions :
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

---


## III. How PayloadGenerator Chooses Payloads (Context-Aware Design) :
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

---


## IV. Code Quality & Design Choices :

1. **Marker-Based Payload Tracking**
Each payload embeds a unique UUID marker, enabling :
- Precise reflection tracking
- Handling HTML/JSON/script encoding differences
- Avoiding ambiguous substring matches

2. **Modular Architecture**
- `PayloadGenerator` : responsible only for payloads.
- `detect_context_heuristic` : pure function for inference.
- `XSSScanner` : networking, scanning logic, reporting.
- `main()` : user interface and argument parsing.
This separation keeps code maintainable and testable.

3. **ThreadPoolExecutor for Speed**
Scanning uses parallel threads (default 8, max 15) :
- Greatly reduces scan duration across multiple params & contexts.
- Optional `--no-parallel` for environments where parallelism may break functionality.

4. **Safe Defaults**
- Timeouts prevent hanging requests.
- GET requests don’t add unintended parameters.
- Cookies/headers must be explicitly passed.

5. **Clean HTML Output**
- `<pre>` blocks for payloads.
- Escaping via html.escape to prevent breaking the report itself.
- UTC timestamp for reproducibility.

6. **Simplicity over Full Accuracy**
This is an educational tool, so :
- No headless browser or DOM evaluation.
- No JavaScript execution.
- No advanced CSRF/session handling.
- No stored or DOM-XSS detection.


---

---


## V. Installation :

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

---


## VI. Execution :

1. Basic GET scan :
```
python xss_scanner.py --url "http://example.com/search" --params q
```

2. POST form :
```
python xss_scanner.py --url "http://site.com" --params username message --method POST
```

3. POST JSON :
```
python xss_scanner.py --url "http://api.com/v1" --params query --method POST --json
```

4. Custom headers/cookies :
```
python xss_scanner.py --url http://test --params q --headers "User-Agent:Scanner,Referer:Test" --cookies "session:abcd1234"
```

5. Disable parallel scanning :
```
python xss_scanner.py --url http://test --params q --no-parallel
```

6. Specify output file :
```
python xss_scanner.py --url http://test --params q --out report.html
```


**Note : Time taken to build this was 7 hours**
