import requests
import logging

logger = logging.getLogger("webfuzz")

session = requests.Session()

def requester(url, headers, data, method, timeout=10):
    try:
        if method == 'GET':
            response = session.get(url, headers=headers, timeout=timeout)
        else:
            if data is not None:
                response = session.post(url, data=data, headers=headers, timeout=timeout)
            else:
                response = session.post(url, headers=headers, timeout=timeout)
        return response
    except Exception as e:
        logger.warning("Unable to connect to the target")
        return None

