eval("bad")
exec("bad")
import os
os.system("ls")
import pickle
pickle.load(b'')
import yaml
yaml.load(b'')
import subprocess
subprocess.Popen("ls", shell=True)
# megasast:ignore megasast/py-eval
eval("ignored")
