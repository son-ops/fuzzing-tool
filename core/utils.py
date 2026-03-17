from urllib.parse import urlsplit, parse_qsl
from .config import InjectionPoint
import string
import random
from difflib import SequenceMatcher
import logging

logger = logging.getLogger("webfuzz")

def extractHeaders(headers):
    res = {}
    for header in headers:
        if ':' in header:
            k,v = header.split(':', 1)
            res[k.strip()] = v.strip()
        else:
            logger.warning(f'Invalid header format (ignored): {header}')
    return res

def countFUZZ(url, headers, data):
    c = 0
    c += url.count('FUZZ') if url else 0
    c += data.count('FUZZ') if data else 0
    for k,v in headers.items():
        c += k.count('FUZZ')
        c += v.count('FUZZ')
    return c

def findFuzzLocation(url, headers, data):
    if 'FUZZ' in url:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        for k, v in query:
            if "FUZZ" in k or "FUZZ" in v:
                return InjectionPoint(kind="url_query", key=k)
        paths = parts.path.split("/")
        for i, path in enumerate(paths):
            if "FUZZ" in path:
                return InjectionPoint(kind="url_path", index=i)
        return None
    elif data and "FUZZ" in data:
        data = parse_qsl(data, keep_blank_values=True)
        for k, v in data:
            if "FUZZ" in k or "FUZZ" in v:
                return InjectionPoint(kind="body_form", key=k)
        return None
    for k, v in headers.items():
        if "FUZZ" in k or "FUZZ" in v:
            return InjectionPoint(kind="header", key=k)
    return None

def reader(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.rstrip('\n') for line in f]
    except Exception as e:
        raise SystemExit(f'[-] Read File Error: {e}')
    
def generate_marker(length=10):
    char = string.digits + string.ascii_letters
    marker = ''.join(random.choices(char, k=length))
    return marker

def norm(response):
    return " ".join((response or "").split())

def similar(base_res, res):
    return SequenceMatcher(None, norm(base_res), norm(res)).ratio()

def injection_point_to_str(point: InjectionPoint | None):
    if point is None:
        return 'unknown'
    if point.kind == 'url_query':
        return f'url_query:{point.key}' if point.key else 'url_query'
    if point.kind == 'url_path':
        return f'url_path:{point.index}' if point.index is not None else 'url_path'
    if point.kind == 'body_form':
        return f'body_form:{point.key}' if point.key else 'form'
    if point.kind == 'header':
        return f'header:{point.key}'
    return point.kind

def formater(event, **kv):
    mess = " | ".join(f"[{k}]={v}" for k,v in kv.items() if v is not None)
    return f"[{event}] {mess}".rstrip()