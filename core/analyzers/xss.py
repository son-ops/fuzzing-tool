def reflected_xss(payload, response):
    if response and payload in response:
        return {
            "vul": "Potential XSS Vulnerability",
            "evidence": "Reflected"
        }
    return None




