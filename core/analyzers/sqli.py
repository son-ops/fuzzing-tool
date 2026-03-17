import re

_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",                            # MySQL
    r"The used SELECT statements have a different number of columns",   # Union Error      
    r"Unknown column",                                                  # select column not exists
    r"XPATH syntax error",                                              # error message with extracvalue
    r"warning:\s*mysql",                                                # PHP mysql
    r"mysql_fetch|mysqli_fetch|mysqli?_query",                          # mysql/mysqli
    r"unclosed quotation mark",                                         # MSSQL
    r"quoted string not properly terminated",                           # Oracle/MSSQL
    r"sqlstate\[\w+\]",                                                 # SQLSTATE
    r"odbc.*driver",                                                    # ODBC
    r"postgresql.*error|pg_query\(",                                    # PostgreSQL
    r"sqlite.*(error|exception)",                                       # SQLite
    r"syntax error.*at or near",                                        # PostgreSQL-ish
    r"conversion failed",
]

ERROR_RE = re.compile("|".join(f"(?:{p})" for p in _ERROR_PATTERNS), re.I)

def error_based(response):
    if not response:
        return None
    res = ERROR_RE.search(response)
    if res:
        return res
    return None

def time_based(elapsed_ms, baseline_time_ms, threshold=3000):
    time = elapsed_ms - baseline_time_ms
    if time >= threshold:
        return {
            "vul": "sqli",
            "technique": "time-based",
            "evidence": f"delayed: {time:.1f}ms"
        }
    return None

def marker_union_based(marker, response):
    if marker and response and marker in response:
        return {
            "vul": "sqli",
            "technique": "union-based",
            "evidence": f"marker reflected dectect: {marker}"
        }
    return None


