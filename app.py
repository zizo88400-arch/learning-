import os, random, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "CHANGE-ME-BEFORE-DEPLOYING")
uri = os.getenv("DATABASE_URL", "sqlite:///zouz_local.db")
if uri.startswith("postgres://"): uri = uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

def utcnow(): return datetime.utcnow()

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(100),nullable=False)
    phone=db.Column(db.String(20),unique=True,nullable=False); role=db.Column(db.String(20),default="student")
    grade=db.Column(db.String(30)); governorate=db.Column(db.String(60)); subject=db.Column(db.String(100))
    bio=db.Column(db.String(300)); approved=db.Column(db.Boolean,default=True); created=db.Column(db.DateTime,default=utcnow)
class OTP(db.Model):
    id=db.Column(db.Integer,primary_key=True); phone=db.Column(db.String(20),index=True)
    code_hash=db.Column(db.String(220)); expires=db.Column(db.DateTime); attempts=db.Column(db.Integer,default=0)
class Resource(db.Model):
    id=db.Column(db.Integer,primary_key=True); title=db.Column(db.String(180)); kind=db.Column(db.String(30))
    grade=db.Column(db.String(30)); subject=db.Column(db.String(100)); url=db.Column(db.String(1000))
    description=db.Column(db.String(500)); owner_id=db.Column(db.Integer,db.ForeignKey("user.id"))
    approved=db.Column(db.Boolean,default=False); owner=db.relationship("User")
class Post(db.Model):
    id=db.Column(db.Integer,primary_key=True); title=db.Column(db.String(180)); body=db.Column(db.Text)
    user_id=db.Column(db.Integer,db.ForeignKey("user.id")); created=db.Column(db.DateTime,default=utcnow)
    user=db.relationship("User")
class Reply(db.Model):
    id=db.Column(db.Integer,primary_key=True); post_id=db.Column(db.Integer,db.ForeignKey("post.id"))
    body=db.Column(db.Text); user_id=db.Column(db.Integer,db.ForeignKey("user.id"))
    created=db.Column(db.DateTime,default=utcnow); user=db.relationship("User")
class News(db.Model):
    id=db.Column(db.Integer,primary_key=True); title=db.Column(db.String(180)); body=db.Column(db.Text)
    audience=db.Column(db.String(20),default="all"); created=db.Column(db.DateTime,default=utcnow)
class Quiz(db.Model):
    id=db.Column(db.Integer,primary_key=True); title=db.Column(db.String(180)); grade=db.Column(db.String(30))
    subject=db.Column(db.String(100)); questions=db.Column(db.Text); active=db.Column(db.Boolean,default=True)
class Result(db.Model):
    id=db.Column(db.Integer,primary_key=True); quiz_id=db.Column(db.Integer,db.ForeignKey("quiz.id"))
    user_id=db.Column(db.Integer,db.ForeignKey("user.id")); score=db.Column(db.Integer); total=db.Column(db.Integer)
    quiz=db.relationship("Quiz")

def me(): return db.session.get(User,session.get("uid")) if session.get("uid") else None
@app.context_processor
def inject(): return {"me":me()}
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not me(): return redirect(url_for("login"))
        return f(*a,**k)
    return w
def roles(*rs):
    def deco(f):
        @wraps(f)
        @login_required
        def w(*a,**k):
            if me().role not in rs: abort(403)
            return f(*a,**k)
        return w
    return deco
def admin_phone(p): return bool(os.getenv("ADMIN_PHONE")) and p==os.getenv("ADMIN_PHONE")
def send_sms(phone,code):
    sid,token,from_no=[os.getenv(x,"") for x in ("TWILIO_SID","TWILIO_TOKEN","TWILIO_FROM")]
    if not all((sid,token,from_no)): return False
    try:
        r=requests.post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
          auth=(sid,token),data={"To":"+20"+phone[1:],"From":from_no,"Body":f"كود منصة الزوز: {code}"},timeout=15)
        return r.ok
    except requests.RequestException: return False

@app.route("/")
@login_required
def home():
    u=me()
    resources=Resource.query.filter_by(approved=True).order_by(Resource.id.desc()).limit(6).all()
    news=News.query.filter(News.audience.in_(["all",u.role])).order_by(News.id.desc()).limit(4).all()
    quizzes=Quiz.query.filter_by(active=True).all()
    return render_template("home.html",resources=resources,news=news,quizzes=quizzes)

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        p="".join(c for c in request.form.get("phone","") if c.isdigit())
        if p.startswith("20") and len(p)==12: p="0"+p[2:]
        role=request.form.get("role","student")
        if not request.form.get("name","").strip() or len(p)!=11 or not p.startswith("01") or role not in ("student","teacher"):
            flash("راجع الاسم ورقم الموبايل ونوع الحساب.","error")
        elif User.query.filter_by(phone=p).first():
            flash("الرقم مسجل بالفعل. سجل الدخول.","error")
        else:
            session["signup"]={"name":request.form["name"].strip()[:100],"phone":p,"role":role,
             "grade":request.form.get("grade",""),"governorate":request.form.get("governorate",""),
             "subject":request.form.get("subject","")}
            session["auth_phone"]=p
            return redirect(url_for("send_code"))
    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        p="".join(c for c in request.form.get("phone","") if c.isdigit())
        if p.startswith("20") and len(p)==12: p="0"+p[2:]
        if not User.query.filter_by(phone=p).first():
            flash("الرقم غير مسجل. أنشئ حسابًا جديدًا.","error")
            return redirect(url_for("register"))
        session["auth_phone"]=p
        return redirect(url_for("send_code"))
    return render_template("login.html")

@app.route("/send-code")
def send_code():
    p=session.get("auth_phone")
    if not p: return redirect(url_for("login"))
    OTP.query.filter_by(phone=p).delete()
    code=f"{random.randint(0,999999):06d}"
    db.session.add(OTP(phone=p,code_hash=generate_password_hash(code),expires=utcnow()+timedelta(minutes=5)))
    db.session.commit()
    if not send_sms(p,code):
        flash("لم يتم إرسال SMS. اضبط بيانات Twilio في إعدادات الاستضافة أولًا.","error")
        return redirect(url_for("login"))
    return render_template("verify.html",phone=p)

@app.route("/verify",methods=["POST"])
def verify():
    p=session.get("auth_phone")
    row=OTP.query.filter_by(phone=p).order_by(OTP.id.desc()).first() if p else None
    if not row or row.expires<utcnow() or row.attempts>=5:
        flash("الكود انتهى. اطلب كودًا جديدًا.","error"); return redirect(url_for("login"))
    row.attempts+=1
    if not check_password_hash(row.code_hash,request.form.get("code","").strip()):
        db.session.commit(); flash("الكود غير صحيح.","error"); return redirect(url_for("send_code"))
    db.session.delete(row)
    signup=session.pop("signup",None)
    if signup:
        u=User(**signup,approved=(signup["role"]=="student"))
        if admin_phone(p): u.role="admin"; u.approved=True
        db.session.add(u); db.session.commit()
    u=User.query.filter_by(phone=p).first()
    if not u: return redirect(url_for("login"))
    if not u.approved:
        session.clear(); flash("طلب المعلم قيد مراجعة الإدارة.","info"); return redirect(url_for("login"))
    session.clear(); session["uid"]=u.id
    return redirect(url_for("home"))

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/library")
@login_required
def library():
    q=Resource.query.filter_by(approved=True)
    kind=request.args.get("kind",""); grade=request.args.get("grade","")
    if kind in ("book","summary","video","other"): q=q.filter_by(kind=kind)
    if grade: q=q.filter_by(grade=grade)
    return render_template("library.html",items=q.order_by(Resource.id.desc()).all(),kind=kind,grade=grade)

@app.route("/resource/new",methods=["GET","POST"])
@roles("teacher","admin")
def resource_new():
    if request.method=="POST":
        url=request.form.get("url","").strip()
        if not url.startswith(("http://","https://")): flash("الرابط غير صحيح.","error")
        else:
            u=me(); item=Resource(title=request.form.get("title","")[:180],kind=request.form.get("kind","other"),
              grade=request.form.get("grade",""),subject=request.form.get("subject",""),url=url,
              description=request.form.get("description","")[:500],owner_id=u.id,approved=u.role=="admin")
            db.session.add(item); db.session.commit(); flash("تم إرسال المحتوى للمراجعة." if not item.approved else "تم النشر.","success")
            return redirect(url_for("library"))
    return render_template("resource_new.html")

@app.route("/forum",methods=["GET","POST"])
@login_required
def forum():
    if request.method=="POST":
        title=request.form.get("title","").strip()[:180]; body=request.form.get("body","").strip()[:3000]
        if title and body: db.session.add(Post(title=title,body=body,user_id=me().id)); db.session.commit()
        return redirect(url_for("forum"))
    return render_template("forum.html",posts=Post.query.order_by(Post.id.desc()).all())

@app.route("/forum/<int:i>",methods=["GET","POST"])
@login_required
def post(i):
    p=db.session.get(Post,i) or abort(404)
    if request.method=="POST":
        body=request.form.get("body","").strip()[:2000]
        if body: db.session.add(Reply(post_id=i,body=body,user_id=me().id)); db.session.commit()
        return redirect(url_for("post",i=i))
    return render_template("post.html",post=p,replies=Reply.query.filter_by(post_id=i).order_by(Reply.id).all())

@app.route("/profile",methods=["GET","POST"])
@login_required
def profile():
    u=me()
    if request.method=="POST":
        u.name=request.form.get("name",u.name)[:100]; u.bio=request.form.get("bio","")[:300]; db.session.commit()
        flash("تم تحديث الملف الشخصي.","success")
    return render_template("profile.html",user=u,results=Result.query.filter_by(user_id=u.id).all())

@app.route("/news")
@login_required
def news():
    u=me(); items=News.query.filter(News.audience.in_(["all",u.role])).order_by(News.id.desc()).all()
    return render_template("news.html",items=items)

@app.route("/quizzes")
@login_required
def quizzes(): return render_template("quizzes.html",items=Quiz.query.filter_by(active=True).all())

@app.route("/quiz/<int:i>",methods=["GET","POST"])
@login_required
def quiz(i):
    qz=db.session.get(Quiz,i) or abort(404); qs=json.loads(qz.questions)
    if request.method=="POST":
        score=sum(1 for n,q in enumerate(qs) if request.form.get(f"q{n}")==str(q["answer"]))
        db.session.add(Result(quiz_id=i,user_id=me().id,score=score,total=len(qs))); db.session.commit()
        return render_template("result.html",quiz=qz,score=score,total=len(qs))
    return render_template("quiz.html",quiz=qz,questions=qs)

@app.route("/ai",methods=["GET","POST"])
@login_required
def ai():
    answer=None
    if request.method=="POST":
        key=os.getenv("ANTHROPIC_API_KEY",""); prompt=request.form.get("prompt","")[:2500]
        if not key: answer="المساعد الذكي يحتاج مفتاح API حتى يعمل."
        else:
            try:
                r=requests.post("https://api.anthropic.com/v1/messages",headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
                  json={"model":os.getenv("AI_MODEL","claude-3-5-haiku-latest"),"max_tokens":700,
                  "system":"أنت مساعد دراسي لطلاب الثانوية العامة في مصر. اشرح بالعربية المبسطة وبخطوات واضحة.",
                  "messages":[{"role":"user","content":prompt}]},timeout=35)
                r.raise_for_status(); answer="".join(x.get("text","") for x in r.json().get("content",[]))
            except requests.RequestException: answer="حصلت مشكلة في الاتصال بالمساعد."
    return render_template("ai.html",answer=answer)

@app.route("/admin")
@roles("admin")
def admin():
    return render_template("admin.html",teachers=User.query.filter_by(role="teacher",approved=False).all(),
      pending=Resource.query.filter_by(approved=False).all(),users=User.query.order_by(User.id.desc()).limit(30).all())

@app.route("/admin/teacher/<int:i>/<action>",methods=["POST"])
@roles("admin")
def teacher_review(i,action):
    u=db.session.get(User,i) or abort(404)
    if action=="approve": u.approved=True
    elif action=="reject": db.session.delete(u)
    else: abort(400)
    db.session.commit(); return redirect(url_for("admin"))

@app.route("/admin/resource/<int:i>/<action>",methods=["POST"])
@roles("admin")
def resource_review(i,action):
    r=db.session.get(Resource,i) or abort(404)
    if action=="approve": r.approved=True
    elif action=="reject": db.session.delete(r)
    else: abort(400)
    db.session.commit(); return redirect(url_for("admin"))

@app.route("/admin/news",methods=["POST"])
@roles("admin")
def add_news():
    title=request.form.get("title","").strip(); body=request.form.get("body","").strip(); audience=request.form.get("audience","all")
    if title and body and audience in ("all","student","teacher"):
        db.session.add(News(title=title[:180],body=body[:3000],audience=audience)); db.session.commit()
    return redirect(url_for("admin"))

@app.route("/admin/quiz",methods=["POST"])
@roles("admin")
def add_quiz():
    title=request.form.get("title","").strip(); question=request.form.get("question","").strip()
    choices=[request.form.get(f"c{i}","").strip() for i in range(1,5)]; answer=request.form.get("answer","1")
    if title and question and all(choices) and answer in ("1","2","3","4"):
        data=[{"question":question,"choices":choices,"answer":int(answer)}]
        db.session.add(Quiz(title=title[:180],grade=request.form.get("grade",""),subject=request.form.get("subject",""),questions=json.dumps(data,ensure_ascii=False)))
        db.session.commit()
    return redirect(url_for("admin"))

@app.errorhandler(403)
def forbidden(e): return render_template("error.html",code=403,msg="ليس لديك صلاحية لهذه الصفحة."),403
@app.errorhandler(404)
def missing(e): return render_template("error.html",code=404,msg="الصفحة غير موجودة."),404

with app.app_context(): db.create_all()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))
