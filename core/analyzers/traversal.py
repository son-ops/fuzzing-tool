import re

PASSWD_RE = re.compile(r"(?m)^(root|daemon|bin|sys|sync|games):x:\d+:\d+:", re.I)
WIN_INI_RE = re.compile(r"(?is)^\s*\[(fonts|extensions|files)\]\s*$", re.I | re.M)
HOSTS_RE = re.compile(r"(?im)^\s*(127\.0\.0\.1|::1)\s+localhost\b")
PROC_SELF_ENVIRON_RE = re.compile(r"(?s)\b(?:PATH=|USER=|HOME=|SHELL=|PWD=)")

ERROR_RE = re.compile(
    r"(?is)"
    r"(no such file or directory|file not found|cannot find the file|"
    r"failed to open stream|open_basedir restriction|permission denied|invalid argument)"
)

def analyze_traversal(response):
    if PASSWD_RE.search(response):
        return {"vul": "traversal", "evidence": "read_/etc/passwd"}
    if WIN_INI_RE.search(response):
        return {"vul": "traversal", "evidence": "read_win.ini"}
    if HOSTS_RE.search(response):
        return {"vul": "traversal", "evidence": "read_hosts"}
    if PROC_SELF_ENVIRON_RE.search(response):
        return {"vul": "traversal", "evidence": "read_eviron"}
    if ERROR_RE.search(response):
        return {"vul": "traversal", "evidence": "suspicious_error"}
    return None