from .config import InjectionPoint
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

def injectPayload(point: InjectionPoint, url, headers, data, payload):
    new_url = url
    new_headers = dict(headers)
    new_data = data
    parts = urlsplit(url)
    if point.kind == "url_query":
        query = parse_qsl(parts.query, keep_blank_values=True)
        out = []
        for k, v in query:
            k = k.replace("FUZZ", payload) if "FUZZ" in k else k
            v = v.replace("FUZZ", payload) if "FUZZ" in v else v
            out.append((k,v))
        new_query = urlencode(out, doseq=True)
        new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    elif point.kind == "url_path":
        new_path = parts.path.replace("FUZZ", payload) if "FUZZ" in parts.path else parts.path
        new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
    elif point.kind == "body_form":
        data = data.replace("FUZZ", payload) if "FUZZ" in data else data
        new_data = dict(parse_qsl(data, keep_blank_values=True))
    elif point.kind == "header":
        if point.key:
            if "FUZZ" in point.key:
                v = new_headers.pop(point.key)
                new_headers[point.key.replace("FUZZ", payload)] = v
            else:
                new_headers[point.key] = new_headers.get(point.key).replace("FUZZ", payload)
    return new_url, new_headers, new_data


        
