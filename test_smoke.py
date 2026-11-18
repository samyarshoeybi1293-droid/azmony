import os,tempfile,unittest,re
from datetime import datetime,timezone,timedelta
os.environ['AZMOONI_DB']=os.path.join(tempfile.mkdtemp(),'test.sqlite3')
from app import app,db
from werkzeug.security import generate_password_hash
class Flow(unittest.TestCase):
 def test_flow(self):
  c=app.test_client()
  def post(path,**data):
   with c.session_transaction() as s: data['_csrf']=s.get('_csrf','')
   return c.post(path,data=data)
  self.assertEqual(c.get('/health').status_code,200)
  self.assertEqual(c.post('/login/admin',data={}).status_code,400)
  c.get('/login/admin');self.assertEqual(post('/login/admin',username='admin',password='Azmooni@1405!').status_code,302)
  self.assertEqual(c.get('/admin').status_code,200)
  post('/admin/students',first_name='Test',last_name='Student',username='student',password='testpass123')
  post('/admin/exams/new',title='Math',subject='Math',duration='5')
  post('/admin/exams/1',action='add',body='1+1',a='2',b='3',c='4',d='5',correct='0',points='2')
  post('/admin/exams/1',action='toggle');post('/logout');c.get('/login/student');post('/login/student',username='student',password='testpass123')
  self.assertEqual(c.get('/student/exams/1').status_code,200)
  self.assertEqual(post('/student/exams/1/save',q_1='0').status_code,200)
  self.assertIn(b'checked',c.get('/student/exams/1').data)
  with db() as con: con.execute('UPDATE attempts SET started_at=?',((datetime.now(timezone.utc)-timedelta(minutes=6)).isoformat(),))
  self.assertEqual(c.get('/student/exams/1').status_code,302)
  self.assertEqual(c.get('/student/exams/1/result').status_code,200)
  with db() as con: self.assertEqual(con.execute('SELECT score FROM attempts').fetchone()[0],2)
  self.assertEqual(c.get('/admin').status_code,403)
  post('/logout');c.get('/login/admin');post('/login/admin',username='admin',password='Azmooni@1405!')
  self.assertEqual(c.get('/admin/exams/1/csv').status_code,200)
if __name__=='__main__':unittest.main()
