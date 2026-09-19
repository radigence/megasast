# rule: megasast/py-pickle-load
import pickle
with open("data.pkl", "rb") as f:
    obj = pickle.load(f)
