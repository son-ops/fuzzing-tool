import argparse
from core.utils import extractHeaders, countFUZZ, findFuzzLocation, injection_point_to_str
from core.fuzz.fuzz_xss import fuzz_xss
from core.fuzz.fuzz_sqli import fuzz_sqli
from core.fuzz.fuzz_traversal import fuzz_traversal
from core.logger import setup_logger
import logging

parse = argparse.ArgumentParser(prog='webfuzz', description='Simple web fuzzer (sqli/xss/...)')
parse.add_argument('-u', '--url',required=True, help='url')
parse.add_argument('-w', dest='wordlist', help='Load payloads from a file')
parse.add_argument('-H', dest='headers', action='append', default=[], help='Add headers')
parse.add_argument('--log-file', dest='log_file', help='Name of the file to log')
parse.add_argument('--method', dest='method', default='GET', choices=['GET','POST'], help='HTTP Method (default: GET)')
parse.add_argument('--data', help='POST form body, e.g. "a=1&b=FUZZ"')
parse.add_argument('--vul', default='all', choices=['sqli','xss','path_traversal', 'all'], help='Vulnerability that you want to fuzz (default: all)')
parse.add_argument('--time-delay', default=3000.0, dest='delay', help='Using to determine delay time when fuzzing sqli time-based (ms) (default=3000.0)')
args = parse.parse_args()

url = args.url
wordlist = args.wordlist
headers = extractHeaders(args.headers)
log_file = args.log_file
data = args.data
method = 'POST' if data is not None else args.method
vul = args.vul
delay_time = args.delay

logger = setup_logger(log_file)

INTRO = r"""
   ____  __     __    ______                 
  / __ \/ /__  / /_  / ____/_  _____________ 
 / / / / / _ \/ __ \/ /_  / / / / ___/ ___/ 
/ /_/ / /  __/ /_/ / __/ / /_/ / /  (__  )  
\____/_/\___/_.___/_/    \__,_/_/  /____/   
             Simple Fuzzing Web

---------------------------------------------------------
 Modes      : XSS (reflected) | SQLi (error/union/time) | Traversal
 Pipeline   : inject -> request -> analyze -> report
 Marker     : FUZZ (exactly 1 per run)
---------------------------------------------------------
"""
print(INTRO)

n = countFUZZ(url, headers, data)
if n != 1:
    logger.error(f"You must provide exactly 1 FUZZ marker, found {n}")
    quit()

loc = findFuzzLocation(url, headers, data)
if loc is None:
    logger.error("FUZZ point is invalid. Only locate in url_path, url_query, headers and body_form")
    quit()

try:
    delay_time = float(args.delay)
except Exception:
    delay_time = 3000.0
    logger.warning('Invalid time format. Set default to 3000.0 ms')
    logger.newline()

print(f"[Target] {url}")
print(f"[Mode]   {vul} | method={method} | inject={injection_point_to_str(loc)}\n")
print("----------------------Start Fuzzing----------------------\n")

if log_file:
    logger.log_to_file(logging.INFO, f"===== RUN START target={url} mode={vul} method={method} =====")
    logger.newline_file()

if vul == 'xss':
    logger.info("Fuzzing Reflected XSS Vulnerability")
    logger.newline()
    res = fuzz_xss(wordlist, loc, url, headers, data, method)
elif vul == 'sqli':
    logger.info("Fuzzing SQLi Vulnerability")
    logger.newline()
    res = fuzz_sqli(wordlist, loc, url, headers, data, method, delay_time)
elif vul == 'path_traversal':
    logger.info("Fuzzing Path Traversal Vulnerability")
    logger.newline()
    res = fuzz_traversal(wordlist, loc, url, headers, data, method)
elif vul == 'all':
    logger.info("Fuzzing Reflected XSS Vulnerability")
    logger.newline()
    res = fuzz_xss(wordlist, loc, url, headers, data, method)
    logger.newline()
    logger.info("Fuzzing SQLi Vulnerability")
    logger.newline()
    res = fuzz_sqli(wordlist, loc, url, headers, data, method, delay_time)
    logger.newline()
    logger.info("Fuzzing Path Traversal Vulnerability")
    logger.newline()
    res = fuzz_traversal(wordlist, loc, url, headers, data, method)

print("\n-------------------------RUN END-------------------------\n")

if log_file:
    logger.newline_file()
    logger.log_to_file(logging.INFO, f"===== RUN END =====")
    logger.newline_file(n=3)




