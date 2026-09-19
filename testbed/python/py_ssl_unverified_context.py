# rule: megasast/py-ssl-unverified-context
import ssl
ssl._create_unverified_context()
