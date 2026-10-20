"""Create fictional local-development users and listings. Run: python seed.py"""
import os, sqlite3, secrets, hashlib
from datetime import datetime, timezone
DB=os.environ.get("PATERTAP_DB",os.path.join(os.path.dirname(__file__),"patertap.sqlite3"))
def pw(p):
 s=secrets.token_bytes(16);return s.hex()+":"+hashlib.pbkdf2_hmac("sha256",p.encode(),s,310000).hex()
c=sqlite3.connect(DB);c.execute("PRAGMA foreign_keys=ON")
# Schema is created by importing app once.
import app
users=[("demo1@patertap.local","Демо Алия","2003-03-11","Студент",120000,"Рано ложусь","Очень важно","Иногда","Не курю","Тишина","Баланс"),
("demo2@patertap.local","Демо Тимур","2001-07-21","Работаю",140000,"Гибкий","Умеренно","Редко","Не курю","Умеренно","Баланс")]
for email,name,birth,status,budget,sleep,clean,guests,smoking,noise,privacy in users:
 c.execute("INSERT OR IGNORE INTO users(email,password_hash,name,birth_date,status,budget,sleep,cleanliness,guests,smoking,noise,privacy,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(email,pw("DemoPass123!"),name,birth,status,budget,sleep,clean,guests,smoking,noise,privacy,datetime.now(timezone.utc).isoformat()))
c.commit()
ids={r[0]:r[1] for r in c.execute("SELECT email,id FROM users")}
for email,title,district,price,typ,amenities in [
("demo1@patertap.local","Комната в светлой квартире","Бостандыкский",85000,"Комната","Мебель · Wi-Fi"),
("demo2@patertap.local","Подселение рядом с парком","Алмалинский",70000,"Подселение","Кухня · стиральная машина")]:
 c.execute("INSERT OR IGNORE INTO listings(owner_id,title,description,district,price,type,available_from,amenities,created_at) SELECT ?,?,?,?, ?,?,'2026-11-01',?,? WHERE NOT EXISTS(SELECT 1 FROM listings WHERE title=?)",(ids[email],title,"Вымышленное объявление для локального тестирования.",district,price,typ,amenities,datetime.now(timezone.utc).isoformat(),title))
c.commit();c.close()
print("Seed data ready. Demo accounts use password DemoPass123! (local only).")
