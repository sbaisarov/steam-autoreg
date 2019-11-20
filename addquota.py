import requests
import sys

feature, key, quota_amount = sys.argv[1:]

data = {"key": key, "binding_quota": 0}
if feature == "binding":
    data["binding_quota"] = quota_amount
else:
    raise ValueError("The feature doesn't exist")


resp = requests.post("http://shamanovski.pythonanywhere.com/addquota", data=data, auth=("shamanovsky" ,"beka9982"))
print(resp.text)
