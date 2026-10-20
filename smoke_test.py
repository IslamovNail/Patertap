"""HTTP smoke test. Start app.py in another terminal, then run python smoke_test.py."""
import json, urllib.request, urllib.error, datetime
BASE="http://127.0.0.1:5000"
def req(path,method="GET",data=None,token=None):
    headers={"Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    body=json.dumps(data).encode() if data is not None else None
    r=urllib.request.Request(BASE+path,data=body,headers=headers,method=method)
    try:
        with urllib.request.urlopen(r,timeout=5) as res: return res.status,json.loads(res.read())
    except urllib.error.HTTPError as e: return e.code,json.loads(e.read())
stamp=datetime.datetime.now().strftime("%H%M%S%f")
status,user=req("/api/auth/register","POST",{"email":f"smoke{stamp}@example.test","password":"CorrectHorse123!","name":"Smoke Tester","birth_date":"2000-01-01"})
assert status==201,(status,user)
token=user["token"]
status,listing=req("/api/listings","POST",{"title":"Smoke room","description":"test listing","district":"Алмалинский","price":90000,"type":"Комната","available_from":"2026-11-01"},token)
assert status==201,(status,listing)
status,results=req("/api/listings?district=Алмалинский&max_price=100000")
assert status==200 and any(x["id"]==listing["id"] for x in results["items"])
print("PASS: register, create listing, filter listings")
