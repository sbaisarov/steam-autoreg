import requests
import sys

key, quota_amount = sys.argv[1:]

data = {"key": key, "binding_quota": 0}
resp = requests.post("http://shamanovski.pythonanywhere.com/addquota", data=data, auth=("shamanovsky" ,"beka9982"))
print(resp.text)
