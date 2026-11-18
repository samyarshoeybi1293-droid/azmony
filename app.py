import os, sqlite3, secrets, csv, io
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash

ROOT=os.path.dirname(os.path.abspath(__file__))
DB=os.getenv('AZMOONI_DB', os.path.join(ROOT,'azmooni.sqlite3'))
app=Flask(__name__)
app.config['SECRET_KEY']=os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY']=True
app.config['MAX_CONTENT_LENGTH']=1024*1024
if os.getenv('RENDER') and (not os.getenv('SECRET_KEY') or not os.getenv('ADMIN_PASSWORD') or os.getenv('ADMIN_PASSWORD')=='Azmooni@1405!'):
    raise RuntimeError('Set SECRET_KEY and a unique ADMIN_PASSWORD before deployment')

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['Cache-Control']='no-store'
    return response
app.config['SESSION_COOKIE_SAMESITE']='Lax'
app.config['SESSION_COOKIE_SECURE']=os.getenv('COOKIE_SECURE','0')=='1'

SCHEMA='''
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT NOT NULL, last_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','student')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exams (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, subject TEXT NOT NULL, description TEXT DEFAULT '', duration_minutes INTEGER NOT NULL DEFAULT 30, published INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS questions (id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE, body TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL, c TEXT NOT NULL, d TEXT NOT NULL, correct INTEGER NOT NULL CHECK(correct BETWEEN 0 AND 3), points INTEGER NOT NULL DEFAULT 1 CHECK(points >= 1));
CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER NOT NULL REFERENCES exams(id), student_id INTEGER NOT NULL REFERENCES users(id), started_at TEXT NOT NULL, submitted_at TEXT, score INTEGER, total INTEGER, UNIQUE(exam_id, student_id));
CREATE TABLE IF NOT EXISTS answers (attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE, question_id INTEGER NOT NULL REFERENCES questions(id), selected INTEGER CHECK(selected BETWEEN 0 AND 3), PRIMARY KEY(attempt_id,question_id));
'''

@contextmanager
def db():
    conn=sqlite3.connect(DB,timeout=15)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=15000')
    try:
        with conn: yield conn
    finally: conn.close()

def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB)),exist_ok=True)
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(SCHEMA)
        if not con.execute("SELECT id FROM users WHERE role='admin'").fetchone():
            username=os.getenv('ADMIN_USERNAME','admin')
            password=os.getenv('ADMIN_PASSWORD','Azmooni@1405!')
            con.execute('INSERT INTO users(first_name,last_name,username,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',('مدیر','سامانه',username,generate_password_hash(password),'admin',now()))

def now(): return datetime.now(timezone.utc).isoformat()
def require_role(role):
    def outer(fn):
        @wraps(fn)
        def inner(*args,**kwargs):
            if 'uid' not in session: return redirect(url_for('login',role=role))
            if session.get('role') != role: abort(403)
            return fn(*args,**kwargs)
        return inner
    return outer

def token():
    if '_csrf' not in session: session['_csrf']=secrets.token_urlsafe(32)
    return session['_csrf']

@app.context_processor
def globals_(): return {'csrf_token':token,'who':session.get('name'),'role':session.get('role')}

@app.before_request
def protect():
    if request.method=='POST' and (not session.get('_csrf') or not secrets.compare_digest(str(session.get('_csrf','')), str(request.form.get('_csrf','')))): abort(400,'درخواست نامعتبر است؛ صفحه را تازه‌سازی کنید.')

@app.route('/')
def home():
    if session.get('role')=='admin': return redirect(url_for('admin_dashboard'))
    if session.get('role')=='student': return redirect(url_for('student_dashboard'))
    return render_template('home.html',page='home')

@app.route('/login/<role>',methods=['GET','POST'])
def login(role):
    if role not in ('admin','student'): abort(404)
    if request.method=='POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        with db() as con: u=con.execute('SELECT * FROM users WHERE username=? AND role=?',(username,role)).fetchone()
        if u and check_password_hash(u['password_hash'],password):
            session.clear(); session.update(uid=u['id'],role=u['role'],name=u['first_name']+' '+u['last_name'])
            return redirect(url_for('admin_dashboard' if role=='admin' else 'student_dashboard'))
        flash('نام کاربری یا رمز عبور نادرست است.','error')
    return render_template('login.html',page='login',login_role=role)

@app.post('/logout')
def logout():
    session.clear(); return redirect(url_for('home'))

@app.route('/admin')
@require_role('admin')
def admin_dashboard():
    with db() as con:
        counts={'students':con.execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0], 'exams':con.execute('SELECT COUNT(*) FROM exams').fetchone()[0], 'attempts':con.execute('SELECT COUNT(*) FROM attempts WHERE submitted_at IS NOT NULL').fetchone()[0]}
        exams=con.execute('''SELECT e.*, (SELECT count(*) FROM questions q WHERE q.exam_id=e.id) qcount, (SELECT count(*) FROM attempts a WHERE a.exam_id=e.id AND submitted_at IS NOT NULL) submitted FROM exams e ORDER BY e.id DESC''').fetchall()
    return render_template('admin.html',page='admin',counts=counts,exams=exams)

@app.route('/admin/students',methods=['GET','POST'])
@require_role('admin')
def students():
    if request.method=='POST':
        first=request.form.get('first_name','').strip(); last=request.form.get('last_name','').strip(); username=request.form.get('username','').strip(); password=request.form.get('password','')
        if not all([first,last,username]) or len(password)<8:
            flash('نام، نام خانوادگی، نام کاربری و رمز حداقل ۸ کاراکتری لازم است.','error')
        else:
            try:
                with db() as con:
                    con.execute('INSERT INTO users(first_name,last_name,username,password_hash,role,created_at) VALUES(?,?,?,?,?,?)',(first,last,username,generate_password_hash(password),'student',now()))
                flash('حساب دانش‌آموز ساخته شد.','success');return redirect(url_for('students'))
            except sqlite3.IntegrityError: flash('این نام کاربری قبلاً استفاده شده است.','error')
    with db() as con: data=con.execute("SELECT id,first_name,last_name,username,created_at FROM users WHERE role='student' ORDER BY id DESC").fetchall()
    return render_template('students.html',page='students',students=data)

@app.route('/admin/students/<int:student_id>/password',methods=['POST'])
@require_role('admin')
def student_password(student_id):
    password=request.form.get('password','')
    if len(password)<8: flash('رمز جدید باید حداقل ۸ کاراکتر باشد.','error')
    else:
        with db() as con: con.execute("UPDATE users SET password_hash=? WHERE id=? AND role='student'",(generate_password_hash(password),student_id))
        flash('رمز دانش‌آموز تغییر کرد.','success')
    return redirect(url_for('students'))

@app.route('/admin/exams/new',methods=['GET','POST'])
@require_role('admin')
def new_exam():
    if request.method=='POST':
        title=request.form.get('title','').strip(); subject=request.form.get('subject','').strip(); desc=request.form.get('description','').strip()
        try: duration=int(request.form.get('duration','30'))
        except ValueError: duration=0
        if not title or not subject or duration<1 or duration>240: flash('عنوان، درس و زمان معتبر (۱ تا ۲۴۰ دقیقه) لازم است.','error')
        else:
            with db() as con:
                cur=con.execute('INSERT INTO exams(title,subject,description,duration_minutes,published,created_at) VALUES(?,?,?,?,0,?)',(title,subject,desc,duration,now()))
                exam_id=cur.lastrowid
            return redirect(url_for('edit_exam',exam_id=exam_id))
    return render_template('new_exam.html',page='exams')

@app.route('/admin/exams/<int:exam_id>',methods=['GET','POST'])
@require_role('admin')
def edit_exam(exam_id):
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        e=con.execute('SELECT * FROM exams WHERE id=?',(exam_id,)).fetchone()
        if not e: abort(404)
        attempt_exists=con.execute('SELECT 1 FROM attempts WHERE exam_id=? LIMIT 1',(exam_id,)).fetchone() is not None
        if request.method=='POST':
            action=request.form.get('action')
            if action=='add' and not attempt_exists:
                body=request.form.get('body','').strip(); opts=[request.form.get(x,'').strip() for x in ('a','b','c','d')]
                try: correct=int(request.form.get('correct','-1'));points=int(request.form.get('points','1'))
                except ValueError: correct=-1;points=0
                if not body or not all(opts) or correct not in range(4) or not 1<=points<=100:
                    flash('صورت سؤال، هر چهار گزینه، پاسخ درست و امتیاز معتبر را وارد کنید.','error')
                else:
                    con.execute('INSERT INTO questions(exam_id,body,a,b,c,d,correct,points) VALUES(?,?,?,?,?,?,?,?)',(exam_id,body,*opts,correct,points))
                    flash('سؤال اضافه شد.','success')
            elif action=='delete_question' and not attempt_exists:
                con.execute('DELETE FROM questions WHERE id=? AND exam_id=?',(request.form.get('question_id'),exam_id))
                flash('سؤال حذف شد.','success')
            elif action=='toggle':
                qcount=con.execute('SELECT COUNT(*) FROM questions WHERE exam_id=?',(exam_id,)).fetchone()[0]
                if not e['published'] and not qcount: flash('برای انتشار آزمون، حداقل یک سؤال لازم است.','error')
                else:
                    con.execute('UPDATE exams SET published=? WHERE id=?',(0 if e['published'] else 1,exam_id))
                    flash('وضعیت انتشار تغییر کرد.','success')
            else: flash('پس از شروع شرکت در آزمون، سؤال‌ها قابل ویرایش نیستند.','error')
            return redirect(url_for('edit_exam',exam_id=exam_id))
        qs=con.execute('SELECT * FROM questions WHERE exam_id=? ORDER BY id',(exam_id,)).fetchall()
    return render_template('edit_exam.html',page='exams',exam=e,questions=qs,locked=attempt_exists)

@app.route('/student')
@require_role('student')
def student_dashboard():
    with db() as con:
        exams=con.execute('''SELECT e.*, (SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id) qcount, a.id attempt_id, a.submitted_at FROM exams e LEFT JOIN attempts a ON a.exam_id=e.id AND a.student_id=? WHERE e.published=1 OR a.id IS NOT NULL ORDER BY e.id DESC''',(session['uid'],)).fetchall()
    return render_template('student.html',page='student',exams=exams)

@app.route('/student/exams/<int:exam_id>',methods=['GET','POST'])
@require_role('student')
def take_exam(exam_id):
    uid=session['uid']
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        e=con.execute('SELECT * FROM exams WHERE id=?',(exam_id,)).fetchone()
        if not e: abort(404)
        a=con.execute('SELECT * FROM attempts WHERE exam_id=? AND student_id=?',(exam_id,uid)).fetchone()
        if a and a['submitted_at']: return redirect(url_for('result',exam_id=exam_id))
        if not e['published'] and not a: abort(404)
        qs=con.execute('SELECT id,body,a,b,c,d,points FROM questions WHERE exam_id=? ORDER BY id',(exam_id,)).fetchall()
        if not qs: abort(404)
        if not a:
            try:
                cur=con.execute('INSERT INTO attempts(exam_id,student_id,started_at) VALUES(?,?,?)',(exam_id,uid,now()))
                attempt_id=cur.lastrowid
            except sqlite3.IntegrityError:
                attempt_id=con.execute('SELECT id FROM attempts WHERE exam_id=? AND student_id=?',(exam_id,uid)).fetchone()[0]
            a=con.execute('SELECT * FROM attempts WHERE id=?',(attempt_id,)).fetchone()
        remaining=seconds_left(a,e)
        if request.method=='POST' or remaining<=0:
            if remaining>0: save_choices(con,a['id'],qs)
            finish(con,a['id'],exam_id)
            return redirect(url_for('result',exam_id=exam_id))
        saved={r['question_id']:r['selected'] for r in con.execute('SELECT * FROM answers WHERE attempt_id=?',(a['id'],))}
    return render_template('take_exam.html',page='student',exam=e,questions=qs,remaining=remaining,saved=saved)

def seconds_left(a,e):
    import math
    return max(0,math.ceil(datetime.fromisoformat(a['started_at']).timestamp()+e['duration_minutes']*60-datetime.now(timezone.utc).timestamp()))

def save_choices(con,aid,qs):
    for q in qs:
        key='q_'+str(q['id'])
        if key not in request.form: continue
        try: v=int(request.form[key])
        except ValueError: continue
        if v in range(4): con.execute('INSERT OR REPLACE INTO answers VALUES(?,?,?)',(aid,q['id'],v))

def finish(con,aid,eid):
    score,total=con.execute('SELECT COALESCE(SUM(CASE WHEN a.selected=q.correct THEN q.points ELSE 0 END),0),COALESCE(SUM(q.points),0) FROM questions q LEFT JOIN answers a ON a.question_id=q.id AND a.attempt_id=? WHERE q.exam_id=?',(aid,eid)).fetchone()
    con.execute('UPDATE attempts SET submitted_at=?,score=?,total=? WHERE id=? AND submitted_at IS NULL',(now(),score,total,aid))

@app.post('/student/exams/<int:exam_id>/save')
@require_role('student')
def autosave(exam_id):
    with db() as con:
        con.execute('BEGIN IMMEDIATE')
        a=con.execute('SELECT * FROM attempts WHERE exam_id=? AND student_id=?',(exam_id,session['uid'])).fetchone()
        e=con.execute('SELECT * FROM exams WHERE id=?',(exam_id,)).fetchone()
        if not a or not e: abort(404)
        if a['submitted_at']: return jsonify(status='finished'),409
        if seconds_left(a,e)<=0:
            finish(con,a['id'],exam_id)
            return jsonify(status='finished'),409
        save_choices(con,a['id'],con.execute('SELECT id FROM questions WHERE exam_id=?',(exam_id,)).fetchall())
    return jsonify(status='saved')

@app.post('/admin/password')
@require_role('admin')
def admin_password():
    with db() as con:
        u=con.execute('SELECT * FROM users WHERE id=?',(session['uid'],)).fetchone()
        new=request.form.get('new_password','')
        if not check_password_hash(u['password_hash'],request.form.get('old_password','')) or len(new)<12:
            flash('رمز فعلی یا رمز جدید (حداقل ۱۲ نویسه) معتبر نیست.','error')
        else:
            con.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),u['id']))
            flash('رمز مدیر تغییر کرد.','success')
    return redirect(url_for('admin_dashboard'))

@app.get('/admin/exams/<int:exam_id>/csv')
@require_role('admin')
def export_results(exam_id):
    with db() as con: rows=ranking(con,exam_id)
    out=io.StringIO(); w=csv.writer(out); w.writerow(['رتبه','نام','نام خانوادگی','نمره','کل','درصد'])
    def safe(v): return "'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v
    for r in rows: w.writerow([r['rank'],safe(r['first_name']),safe(r['last_name']),r['score'],r['total'],r['percent']])
    return Response('\ufeff'+out.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename=exam-{exam_id}.csv'})


def ranking(con,exam_id):
    rows=con.execute('''SELECT a.student_id,a.score,a.total,a.submitted_at,u.first_name,u.last_name FROM attempts a JOIN users u ON u.id=a.student_id WHERE a.exam_id=? AND a.submitted_at IS NOT NULL ORDER BY (1.0*a.score/NULLIF(a.total,0)) DESC, a.score DESC, a.submitted_at ASC, a.student_id ASC''',(exam_id,)).fetchall()
    ranked=[];prev=None;rank=0
    for idx,r in enumerate(rows):
        key=(r['score'],r['total'])
        if key!=prev:rank=idx+1;prev=key
        ranked.append(dict(r)|{'rank':rank,'percent':round(100*r['score']/r['total'],1) if r['total'] else 0})
    return ranked

@app.route('/student/exams/<int:exam_id>/result')
@require_role('student')
def result(exam_id):
    with db() as con:
        exam=con.execute('SELECT * FROM exams WHERE id=?',(exam_id,)).fetchone()
        attempt=con.execute('SELECT * FROM attempts WHERE exam_id=? AND student_id=? AND submitted_at IS NOT NULL',(exam_id,session['uid'])).fetchone()
        if not exam or not attempt: abort(404)
        ranked=ranking(con,exam_id)
        my=next((r for r in ranked if r['student_id']==session['uid']),None)
    return render_template('result.html',page='student',exam=exam,attempt=attempt,ranked=[dict(r, first_name=r['first_name'] if r['student_id']==session['uid'] else 'دانش‌آموز', last_name=r['last_name'] if r['student_id']==session['uid'] else str(r['student_id'])) for r in ranked[:10]] if len(ranked)>=10 else [],my=my,count=len(ranked))

@app.route('/admin/exams/<int:exam_id>/results')
@require_role('admin')
def admin_results(exam_id):
    with db() as con:
        exam=con.execute('SELECT * FROM exams WHERE id=?',(exam_id,)).fetchone()
        if not exam: abort(404)
        ranked=ranking(con,exam_id)
    return render_template('admin_results.html',page='exams',exam=exam,ranked=ranked)

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def error(e): return render_template('error.html',page='error',message=getattr(e,'description','صفحه پیدا نشد.')),e.code

@app.get("/health")
def health():
    with db() as con: con.execute("SELECT 1").fetchone()
    return {"status":"ok"}

init_db()

if __name__=='__main__':
    app.run(host='127.0.0.1',port=int(os.getenv('PORT','5000')),debug=False)
