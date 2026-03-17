import logging

VULN_LEVEL = 35
logging.addLevelName(VULN_LEVEL, "VULN")

def _vuln(self, msg, *args, **kwargs):
    if self.isEnabledFor(VULN_LEVEL):
        self._log(VULN_LEVEL, msg, args, **kwargs)

def _newline(self, n=1):
    for h in self.handlers:
        h.stream.write("\n"*n)
        h.flush()

def _log_to_file(self, level, msg, *args, **kwargs):
    fh = getattr(self, "_file_handler", None)
    if not fh:
        return
    record = self.makeRecord(self.name, level, "", 0, msg, args, None, **kwargs)
    fh.handle(record)

def _vuln_to_file(self, msg, *args, **kwargs):
    _log_to_file(self, VULN_LEVEL, msg, *args, **kwargs)

def _newline_file(self, n=1):
    fh = getattr(self, "_file_handler", None)
    if not fh:
        return
    fh.stream.write("\n"*n)
    fh.flush()

if not hasattr(logging.Logger, "newline_file"):
    logging.Logger.newline_file = _newline_file

if not hasattr(logging.Logger, "log_to_file"):
    logging.Logger.log_to_file = _log_to_file

if not hasattr(logging.Logger, "vuln_to_file"):
    logging.Logger.vuln_to_file = _vuln_to_file

if not hasattr(logging.Logger, "vuln"):
    logging.Logger.vuln = _vuln
    
if not hasattr(logging.Logger, "newline"):
    logging.Logger.newline = _newline

def setup_logger(log_file=None):
    logger = logging.getLogger("webfuzz")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(levelname)s] %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        logger._file_handler = fh
    return logger
