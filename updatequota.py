import requests
import sys

key, quota_amount = sys.argv[1], sys.argv[2]

data = {"key": key, "binding_quota": 0}

resp = requests.post("http://shamanovski.pythonanywhere.com/updatequota", data=data)
print(resp.text)
