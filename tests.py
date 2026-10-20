import os, tempfile, unittest
os.environ["PATERTAP_DB"]=os.path.join(tempfile.gettempdir(),"patertap-test-%s.sqlite3"%os.getpid())
import app as module
from app import app
class PaterTapTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  app.config["TESTING"]=True
 def setUp(self):
  with app.app_context():
   c=module.db()
   for t in ["reports","blocks","messages","participants","conversations","favorites","listings","sessions","users"]:
    c.execute("DELETE FROM "+t)
   c.commit()
  self.client=app.test_client()
 def register(self,email="one@example.test",name="Test User"):
  return self.client.post("/api/auth/register",json={"email":email,"password":"CorrectHorse123!","name":name,"birth_date":"2000-01-01"})
 def auth(self,r):
  return {"Authorization":"Bearer "+r.json["token"]}
 def test_register_and_login(self):
  r=self.register();self.assertEqual(r.status_code,201)
  login=self.client.post("/api/auth/login",json={"email":"one@example.test","password":"CorrectHorse123!"})
  self.assertEqual(login.status_code,200);self.assertIn("token",login.json)
 def test_age_gate(self):
  r=self.client.post("/api/auth/register",json={"email":"young@example.test","password":"CorrectHorse123!","name":"Young","birth_date":"2015-01-01"})
  self.assertEqual(r.status_code,403)
 def test_listing_owner_access(self):
  a=self.register();b=self.register("two@example.test","Second")
  h=self.auth(a)
  made=self.client.post("/api/listings",headers=h,json={"title":"Room","description":"Nice room","district":"Алмалинский","price":70000,"type":"Комната","available_from":"2026-11-01"})
  self.assertEqual(made.status_code,201)
  lid=made.json["id"]
  denied=self.client.put(f"/api/listings/{lid}",headers=self.auth(b),json={"title":"Hack"})
  self.assertEqual(denied.status_code,403)
 def test_conversation_private(self):
  a=self.register();b=self.register("two@example.test","Second");c=self.register("three@example.test","Third")
  created=self.client.post("/api/conversations",headers=self.auth(a),json={"other_user_id":b.json["user"]["id"]})
  cid=created.json["id"]
  sent=self.client.post(f"/api/conversations/{cid}/messages",headers=self.auth(a),json={"body":"Hello"})
  self.assertEqual(sent.status_code,201)
  denied=self.client.get(f"/api/conversations/{cid}/messages",headers=self.auth(c))
  self.assertEqual(denied.status_code,403)
 def test_listing_filters(self):
  a=self.register()
  self.client.post("/api/listings",headers=self.auth(a),json={"title":"Affordable Room","description":"test","district":"Алмалинский","price":70000,"type":"Комната","available_from":"2026-11-01"})
  r=self.client.get("/api/listings?district=Алмалинский&max_price=80000")
  self.assertTrue(any(x["title"]=="Affordable Room" for x in r.json["items"]))
if __name__=="__main__": unittest.main()
