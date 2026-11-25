import os,json,sqlite3,secrets,hashlib,hmac,time,re
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from decimal import Decimal
DB=os.environ.get("DB_PATH","loan.db")
def db():
    c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute("pragma foreign_keys=on");return c
SCHEMA="""
create table if not exists users(id integer primary key,username text unique not null,pw text not null,role text not null check(role in('admin','customer')),first text,last text,phone text,email text,cid text unique,status text not null default 'ACTIVE',credit integer not null default 0,created text default current_timestamp);
create table if not exists sessions(h text primary key,uid integer references users(id),exp real);
create table if not exists loans(id integer primary key,uid integer not null references users(id),amount integer not null check(amount>0),rate real not null,term integer not null,status text not null default 'PENDING',paid integer not null default 0,notes text,by text,decided text,created text default current_timestamp);
create table if not exists payments(id integer primary key,loan integer not null references loans(id),amount integer not null check(amount>0),method text,ref text,by text,created text default current_timestamp);
create table if not exists notifs(id integer primary key,uid integer references users(id),msg text,read integer default 0,created text default current_timestamp);
create table if not exists audit(id integer primary key,actor text,action text,detail text,ts text default current_timestamp);
create index if not exists i_loans on loans(uid);create index if not exists i_pay on payments(loan);
"""
def hp(p,s=None):
    s=s or secrets.token_hex(16);return s+"$"+hashlib.scrypt(p.encode(),salt=s.encode(),n=2**14,r=8,p=1).hex()
def vp(p,h):return hmac.compare_digest(hp(p,h.split("$")[0]),h)
def S(x):
    v=Decimal(str(x))
    if v<0:raise E("จำนวนเงินไม่ถูกต้อง")
    return int(v*100)
class E(Exception):
    def __init__(s,m,c=400):s.m=m;s.c=c
def strong(p):
    if not(isinstance(p,str) and len(p)>=8 and re.search(r"[A-Za-z]",p) and re.search(r"\d",p)):raise E("รหัสผ่านต้องยาว 8+ ตัว มีตัวอักษรและตัวเลข")
def aud(c,a,act,d=""):c.execute("insert into audit(actor,action,detail)values(?,?,?)",(a,act,d))
def note(c,uid,m):c.execute("insert into notifs(uid,msg)values(?,?)",(uid,m))
def lv(r):
    d=dict(r);tot=round(d["amount"]*(1+d["rate"]/100*d["term"]/12));d["total"]=tot/100;d["outstanding"]=(tot-d["paid"])/100
    d["amount"]/=100;d["paid"]/=100;return d,tot
def used(c,uid):return c.execute("select coalesce(sum(amount),0) from loans where uid=? and status in('PENDING','ACTIVE')",(uid,)).fetchone()[0]
tries={}
def api(c,p,b,u):
    if p=="register":
        for k in("first","last","username","phone","email"):
            if not str(b.get(k,"")).strip():raise E("กรอกข้อมูลไม่ครบ")
        if not re.fullmatch(r"[A-Za-z0-9_]{4,20}",b["username"]):raise E("Username 4-20 ตัวอักษร/ตัวเลข")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",b["email"]):raise E("Email ไม่ถูกต้อง")
        strong(b.get("password"))
        n=c.execute("select count(*) from users").fetchone()[0]+1
        try:c.execute("insert into users(username,pw,role,first,last,phone,email,cid)values(?,?,'customer',?,?,?,?,?)",(b["username"],hp(b["password"]),b["first"][:60],b["last"][:60],b["phone"][:20],b["email"][:100],"CUS%05d"%n))
        except sqlite3.IntegrityError:raise E("Username ซ้ำ")
        aud(c,b["username"],"REGISTER");return {}
    if p=="login":
        k=b.get("username","");t=tries.get(k,(0,0))
        if t[0]>=5 and time.time()-t[1]<300:raise E("ลองผิดหลายครั้ง กรุณารอ 5 นาที",429)
        r=c.execute("select * from users where username=?",(k,)).fetchone()
        if not r or not vp(str(b.get("password","")),r["pw"]):tries[k]=(t[0]+1,time.time());raise E("Username หรือรหัสผ่านไม่ถูกต้อง",401)
        if r["status"]!="ACTIVE":raise E("บัญชีถูกระงับ",403)
        tries.pop(k,None);tok=secrets.token_urlsafe(32)
        c.execute("insert into sessions values(?,?,?)",(hashlib.sha256(tok.encode()).hexdigest(),r["id"],time.time()+3600*8));aud(c,k,"LOGIN");return {"_tok":tok,"role":r["role"]}
    if not u:raise E("กรุณาเข้าสู่ระบบ",401)
    adm=u["role"]=="admin";me=u["username"]
    if p=="logout":return {"_tok":""}
    if p=="changepw":
        if not vp(b.get("old",""),u["pw"]):raise E("รหัสผ่านเดิมไม่ถูกต้อง")
        strong(b.get("new"));c.execute("update users set pw=? where id=?",(hp(b["new"]),u["id"]));aud(c,me,"CHANGE_PW");return {}
    if p=="data":
        if adm:
            m=[dict(r)|{"used":used(c,r["id"])/100,"credit":r["credit"]/100} for r in c.execute("select id,username,first,last,phone,email,cid,status,credit,created from users where role='customer' order by id desc")]
            L=[lv(r)[0]|{"name":r["n"]} for r in c.execute("select l.*,u.first||' '||u.last n from loans l join users u on u.id=l.uid order by l.id desc")]
            P=[dict(r)|{"amount":r["amount"]/100} for r in c.execute("select * from payments order by id desc limit 100")]
            A=[dict(r) for r in c.execute("select * from audit order by id desc limit 100")]
            st={"members":len(m),"active":sum(x["status"]=="ACTIVE" for x in m),"credit":sum(x["credit"] for x in m),"pending":sum(x["status"]=="PENDING" for x in L),"approved":sum(x["status"] in("ACTIVE","PAID") for x in L),"rejected":sum(x["status"]=="REJECTED" for x in L),"outstanding":sum(x["outstanding"] for x in L if x["status"]=="ACTIVE"),"payments":sum(x["amount"] for x in P)}
            return {"role":"admin","me":me,"members":m,"loans":L,"payments":P,"audit":A,"stats":st}
        L=[lv(r)[0] for r in c.execute("select * from loans where uid=? order by id desc",(u["id"],))]
        P=[dict(r)|{"amount":r["amount"]/100} for r in c.execute("select p.* from payments p join loans l on l.id=p.loan where l.uid=? order by p.id desc",(u["id"],))]
        N=[dict(r) for r in c.execute("select * from notifs where uid=? order by id desc",(u["id"],))]
        us=used(c,u["id"]);return {"role":"customer","me":me,"name":u["first"]+" "+u["last"],"cid":u["cid"],"status":u["status"],"credit":u["credit"]/100,"available":(u["credit"]-us)/100,"loans":L,"payments":P,"notifs":N,"paid":sum(x["amount"] for x in P),"outstanding":sum(x["outstanding"] for x in L if x["status"]=="ACTIVE")}
    if p=="apply" and not adm:
        a=S(b.get("amount",0));rate=float(b.get("rate",12));term=int(b.get("term",0))
        if a<=0 or term<1 or term>120:raise E("ข้อมูลไม่ถูกต้อง")
        if a>u["credit"]-used(c,u["id"]):raise E("เกินวงเงินที่ใช้ได้")
        c.execute("insert into loans(uid,amount,rate,term)values(?,?,?,?)",(u["id"],a,12.0,term));aud(c,me,"APPLY_LOAN",str(a/100));return {}
    if p=="read" and not adm:c.execute("update notifs set read=1 where uid=?",(u["id"],));return {}
    if not adm:raise E("ไม่มีสิทธิ์",403)
    if p=="setlimit":
        c.execute("update users set credit=? where id=? and role='customer'",(S(b["credit"]),int(b["id"])));aud(c,me,"SET_LIMIT","user %s=%s"%(b["id"],b["credit"]));note(c,int(b["id"]),"วงเงินของคุณถูกปรับเป็น %s บาท"%b["credit"]);return {}
    if p=="setstatus":
        if b["status"] not in("ACTIVE","SUSPENDED"):raise E("สถานะไม่ถูกต้อง")
        c.execute("update users set status=? where id=? and role='customer'",(b["status"],int(b["id"])));aud(c,me,"MEMBER_"+b["status"],str(b["id"]));return {}
    if p=="resetpw":
        t=secrets.token_urlsafe(9)+"a1";c.execute("update users set pw=? where id=? and role='customer'",(hp(t),int(b["id"])));aud(c,me,"RESET_PW",str(b["id"]));return {"temp":t}
    if p=="decide":
        l=c.execute("select * from loans where id=?",(int(b["id"]),)).fetchone()
        if not l or l["status"]!="PENDING":raise E("รายการนี้ดำเนินการแล้ว")
        if b["ok"]:
            u2=c.execute("select credit from users where id=?",(l["uid"],)).fetchone()
            if l["amount"]>u2["credit"]-used(c,l["uid"])+l["amount"]:raise E("เกินวงเงินลูกค้า")
            c.execute("update loans set status='ACTIVE',by=?,decided=datetime('now') where id=?",(me,l["id"]));note(c,l["uid"],"สินเชื่อ #%d ได้รับการอนุมัติ"%l["id"])
        else:
            r=str(b.get("reason","")).strip()
            if not r:raise E("ต้องระบุเหตุผล")
            c.execute("update loans set status='REJECTED',by=?,decided=datetime('now'),notes=? where id=?",(me,r,l["id"]));note(c,l["uid"],"สินเชื่อ #%d ไม่ได้รับอนุมัติ: %s"%(l["id"],r))
        aud(c,me,"APPROVE" if b["ok"] else "REJECT","loan %d"%l["id"]);return {}
    if p=="pay":
        l=c.execute("select * from loans where id=?",(int(b["id"]),)).fetchone()
        if not l or l["status"]!="ACTIVE":raise E("สินเชื่อไม่อยู่ในสถานะ ACTIVE")
        a=S(b["amount"]);_,tot=lv(l)
        if a<=0 or l["paid"]+a>tot:raise E("ยอดชำระเกินยอดคงค้าง")
        c.execute("insert into payments(loan,amount,method,ref,by)values(?,?,?,?,?)",(l["id"],a,str(b.get("method","cash"))[:20],str(b.get("ref",""))[:40],me))
        np=l["paid"]+a;c.execute("update loans set paid=?,status=? where id=?",(np,"PAID" if np>=tot else "ACTIVE",l["id"]))
        note(c,l["uid"],"บันทึกการชำระ %.2f บาท สำหรับสินเชื่อ #%d"%(a/100,l["id"]));aud(c,me,"PAYMENT","loan %d %.2f"%(l["id"],a/100));return {}
    raise E("ไม่พบ API",404)
HTML=open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"index.html"),encoding="utf-8").read() if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),"index.html")) else ""
class H(BaseHTTPRequestHandler):
    def send(s,code,body,ct="application/json",ck=None):
        b=body if isinstance(body,bytes) else body.encode();s.send_response(code);s.send_header("Content-Type",ct+"; charset=utf-8");s.send_header("Content-Length",str(len(b)))
        for h,v in{"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Content-Security-Policy":"default-src 'self' 'unsafe-inline'"}.items():s.send_header(h,v)
        if ck is not None:s.send_header("Set-Cookie",ck)
        s.end_headers();s.wfile.write(b)
    def do_GET(s):s.send(200,open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"index.html"),"rb").read(),"text/html") if s.path=="/" else s.send(404,"{}")
    def do_POST(s):
        c=db()
        try:
            if s.headers.get("X-Req")!="1" or not s.path.startswith("/api/"):raise E("คำขอไม่ถูกต้อง",403)
            b=json.loads(s.rfile.read(min(int(s.headers.get("Content-Length",0)),100000)) or b"{}")
            u=None;ck=re.search(r"sid=([\w-]+)",s.headers.get("Cookie",""))
            if ck:
                r=c.execute("select u.* from sessions s join users u on u.id=s.uid where s.h=? and s.exp>? and u.status='ACTIVE'",(hashlib.sha256(ck.group(1).encode()).hexdigest(),time.time())).fetchone();u=r
            res=api(c,s.path[5:],b,u);c.commit();tok=res.pop("_tok",None)
            cookie=None if tok is None else("sid=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s"%(tok,28800 if tok else 0,"; Secure" if os.environ.get("HTTPS")=="1" else ""))
            s.send(200,json.dumps(res),ck=cookie)
        except E as e:c.rollback();s.send(e.c,json.dumps({"error":e.m}))
        except Exception as e:c.rollback();s.send(500,json.dumps({"error":"เกิดข้อผิดพลาดภายในระบบ"}))
        finally:c.close()
    def log_message(s,*a):pass
def init():
    c=db();c.executescript(SCHEMA)
    if not c.execute("select 1 from users where role='admin'").fetchone():
        a,p=os.environ.get("ADMIN_USER"),os.environ.get("ADMIN_PASS")
        if not(a and p):raise SystemExit("ตั้งค่า ADMIN_USER และ ADMIN_PASS ก่อนรันครั้งแรก")
        strong(p);c.execute("insert into users(username,pw,role,first,last,cid)values(?,?,'admin','Admin','System','ADMIN')",(a,hp(p)))
    c.commit();c.close()
if __name__=="__main__":
    init();port=int(os.environ.get("PORT",8000));print("LOAN FINANCE PORTAL on :%d"%port);ThreadingHTTPServer(("0.0.0.0",port),H).serve_forever()
