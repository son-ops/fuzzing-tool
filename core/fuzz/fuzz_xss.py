from ..requester import requester
from ..inject import injectPayload
from bs4 import BeautifulSoup
from bs4.element import Comment
import json
from ..utils import reader, generate_marker, formater
from ..analyzers.xss import reflected_xss
import logging

logger = logging.getLogger("webfuzz")

def find_context(response, marker):
    findings = []
    dom = BeautifulSoup(response, "lxml")
    for node in dom.find_all(string=lambda x: isinstance(x, str) and marker in x):
        if isinstance(node, Comment):
            continue
        parent = node.parent
        if parent and parent.name in ("script", "style"):
            continue
        findings.append({
            "context":"html_text",
            "tag": parent.name if parent else None
        })
    for tag in dom.find_all(True):
        for attr_name,attr_value in tag.attrs.items():
            attr_text = " ".join(attr_value) if isinstance(attr_value, list) else attr_value
            if marker in attr_text:
                if attr_name.lower().startswith("on"):
                    context = "js_in_attr"
                elif attr_name == "href":
                    context = "href"
                else:
                    context = "html_attr"
                findings.append({
                    "context": context,
                    "attr": attr_name
                })
    scripts = dom.find_all("script")
    for script in scripts:
        if script.get_text() and marker in script.get_text():
            findings.append({
                "context":"html_script",
                "tag": "script"
            })
    out = []
    seen = set()
    for f in findings:
        key = (f.get("context"), f.get("tag"), f.get("attr"))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

def get_payload(context):
    with open("wordlists/xss.txt","r", encoding="utf-8") as f:
        XSS_PAYLOADS = json.load(f)
    return XSS_PAYLOADS.get(context, [])

def fuzz_xss(wordlist, location, url, headers, data, method):
    MAX_SHOW = 4
    hits = 0
    marker = generate_marker()
    new_url, new_headers, new_data = injectPayload(location, url, headers, data, marker)
    response = requester(new_url, new_headers, new_data, method)
    res = reflected_xss(marker, response.text)
    if res == None:
        logger.info(f"XSS marker not reflected marker={marker} -> skip XSS fuzz")
        return 
    else:
        findings = find_context(response.text, marker)
        logger.info(f"Marker: {marker} is reflected. Continue testing")
        logger.newline()

    for finding in findings:
        _context = finding.get("context")
        payloads = get_payload(_context)
        if wordlist:
            payloads += reader(wordlist)
        for payload in payloads:
            new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
            response = requester(new_url, new_headers, new_data, method)
            res = reflected_xss(payload, response.text)
            if res != None:
                msg = formater("XSS.hit", payload=payload, evidence="Reflected", context=_context, status=response.status_code)
                if hits < MAX_SHOW:
                    hits += 1
                    logger.vuln(msg)
                else:
                    hits += 1
                    logger.vuln_to_file(msg)

    if hits:
        logger.newline()
        logger.info(f"XSS: {hits} hits (showing {MAX_SHOW if hits > MAX_SHOW else hits})")
    elif hits == 0:
        logger.info("Reflected XSS: no payload matched (0 hits)")
    
    if hits > MAX_SHOW:
        print("[INFO] See --log-file for full list hit payloads")



        
        
