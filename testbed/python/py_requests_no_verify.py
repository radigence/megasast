# rule: megasast/py-requests-no-verify
import requests
requests.get(url, verify=False)
