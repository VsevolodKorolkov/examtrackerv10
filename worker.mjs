import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import HTML from './page.html';
const COOKIE='__Host-exam_session';
const TTL=60*60*24*7;
const SCRYPT_OPTIONS={N:16384,r:8,p:5,maxmem:32*1024*1024};
const json=(data,status=200,extra={})=>Response.json(data,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...extra}});
const hash=v=>createHash('sha256').update(v).digest('hex');
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
function passwordHash(password,salt=randomBytes(16).toString('hex')){
 return `scrypt$16384-8-5$${salt}$${scryptSync(password,salt,32,SCRYPT_OPTIONS).toString('hex')}`;
}
function verify(password,stored){
 const [kind,n,salt,digest]=stored.split('$');
 if(kind!=='scrypt'||n!=='16384-8-5'||!/^[a-f0-9]{32}$/.test(salt)||!/^[a-f0-9]{64}$/.test(digest))return false;
 const actual=scryptSync(password,salt,32,SCRYPT_OPTIONS);
 return timingSafeEqual(actual,Uint8Array.from(digest.match(/../g),x=>parseInt(x,16)));
}
function token(request){return request.headers.get('Cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||'';}
function cookie(value,age=TTL){return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;}
async function body(request){
 if(!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json'))fail(415,'JSON request required.');
 if(Number(request.headers.get('Content-Length'))>16384)fail(413,'Request too large.');
 const reader=request.body?.getReader(); if(!reader)fail(400,'Request body required.');
 let size=0;const chunks=[];
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384){await reader.cancel();fail(413,'Request too large.');}chunks.push(value);}
 const data=new Uint8Array(size);let offset=0;for(const c of chunks){data.set(c,offset);offset+=c.length;}
 try{const result=JSON.parse(new TextDecoder().decode(data));if(!result||typeof result!=='object'||Array.isArray(result))fail(400,'Invalid JSON object.');return result;}catch{fail(400,'Invalid JSON object.');}
}
async function currentUser(request,db){
 const t=token(request);if(!/^[a-f0-9]{64}$/.test(t))return null;
 return db.prepare('SELECT u.id,u.username FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(hash(t),Date.now()).first();
}
async function session(request,db,user){
 const t=randomBytes(32).toString('hex');const old=token(request);
 await db.batch([
 db.prepare('DELETE FROM sessions WHERE expires_at<=? OR token_hash=?').bind(Date.now(),hash(old)),
 db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(hash(t),user.id,Date.now()+TTL*1000)
 ]);
 return json({user:{id:user.id,username:user.username}},200,{'Set-Cookie':cookie(t)});
}
async function throttle(db,key,limit){
 const window=Math.floor(Date.now()/900000);
 const row=await db.prepare('INSERT INTO auth_limits(key,window,hits) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN window=excluded.window THEN hits+1 ELSE 1 END,window=excluded.window RETURNING hits').bind(hash(key),window).first();
 if(row.hits>limit)fail(429,'Too many attempts. Please try again in 15 minutes.');
}
function progressRow(row){
 if(!row||!Number.isInteger(row.topic_id)||row.topic_id<0||row.topic_id>33||!['NotStarted','InProgress','Mastered','NeedsReview'].includes(row.status))fail(400,'Invalid topic.');
 const reviewed=row.last_reviewed??null;
 if(reviewed!==null&&(typeof reviewed!=='string'||reviewed.length>40||!Number.isFinite(Date.parse(reviewed))))fail(400,'Invalid review date.');
 return {topic_id:row.topic_id,status:row.status,last_reviewed:reviewed};
}
async function api(request,env){
 const url=new URL(request.url),path=url.pathname,method=request.method,db=env.DB;
 if(!['GET','POST','PUT','DELETE'].includes(method))return json({error:'Method not allowed.'},405);
 const origin=request.headers.get('Origin');
 if((origin&&origin!==url.origin)||request.headers.get('Sec-Fetch-Site')==='cross-site')fail(403,'Cross-site request rejected.');
 if(method!=='GET'&&origin!==url.origin)fail(403,'Same-origin request required.');
 if((path==='/api/signup'||path==='/api/login')&&method==='POST'){
  await throttle(db,'ip:'+request.headers.get('CF-Connecting-IP'),30);
  const b=await body(request);
  const username=typeof b.username==='string'?b.username.trim().toLowerCase():'';
  const password=b.password;
  if(!/^[a-z0-9][a-z0-9_.@+-]{2,63}$/.test(username)||typeof password!=='string'||password.length>128)fail(400,'Use a username of 3–64 letters, numbers or . _ @ + -.');
  await throttle(db,'user:'+username,15);
  if(path==='/api/signup'){
   if(password.length<15)fail(400,'Use a password of at least 15 characters.');
   const encoded=passwordHash(password);
   const user=await db.prepare('INSERT INTO users(username,password_hash) VALUES(?,?) ON CONFLICT(username) DO NOTHING RETURNING id,username').bind(username,encoded).first();
   if(!user)fail(409,'This username is unavailable.');
   return session(request,db,user);
  }
  const user=await db.prepare('SELECT id,username,password_hash FROM users WHERE username=?').bind(username).first();
  const dummy=`scrypt$16384-8-5$${'0'.repeat(32)}$${'0'.repeat(64)}`;
  const valid=verify(password,user?.password_hash||dummy);
  if(!user||!valid)fail(401,'Incorrect username or password.');
  return session(request,db,user);
 }
 if(path==='/api/session'&&method==='GET')return json({user:await currentUser(request,db)});
 if(path==='/api/logout'&&method==='POST'){
  await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(hash(token(request))).run();
  return json({ok:true},200,{'Set-Cookie':cookie('',0)});
 }
 const user=await currentUser(request,db);if(!user)fail(401,'Please log in.');
 if(path==='/api/state'&&method==='GET'){
  const results=await db.batch([db.prepare('SELECT topic_id,status,last_reviewed FROM topic_progress WHERE user_id=?').bind(user.id),db.prepare('SELECT exam_date FROM exam_settings WHERE user_id=?').bind(user.id)]);
  return json({progress:results[0].results,exam_date:results[1].results[0]?.exam_date||''});
 }
 if(path==='/api/progress'&&method==='PUT'){
  const b=await body(request);if(!Array.isArray(b.topics)||!b.topics.length||b.topics.length>34)fail(400,'Invalid topics.');
  const rows=b.topics.map(progressRow);
  await db.batch(rows.map(r=>db.prepare('INSERT INTO topic_progress(user_id,topic_id,status,last_reviewed) VALUES(?,?,?,?) ON CONFLICT(user_id,topic_id) DO UPDATE SET status=excluded.status,last_reviewed=excluded.last_reviewed').bind(user.id,r.topic_id,r.status,r.last_reviewed)));
  return json({ok:true});
 }
 if(path==='/api/exam-date'&&method==='PUT'){
  const b=await body(request);const date=b.exam_date;
  if(typeof date!=='string'||(date!==''&&(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(date)||!Number.isFinite(Date.parse(date)))))fail(400,'Invalid exam date.');
  await db.prepare('INSERT INTO exam_settings(user_id,exam_date) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET exam_date=excluded.exam_date').bind(user.id,date).run();
  return json({ok:true});
 }
 if(path==='/api/state'&&method==='DELETE'){
  await db.batch([db.prepare('DELETE FROM topic_progress WHERE user_id=?').bind(user.id),db.prepare('DELETE FROM exam_settings WHERE user_id=?').bind(user.id)]);
  return json({ok:true});
 }
 return json({error:'Not found.'},404);
}
export default {
 async fetch(request,env){
  const path=new URL(request.url).pathname;
  try{
   if(path.startsWith('/api/'))return await api(request,env);
   if((path==='/'||path==='/index.html')&&['GET','HEAD'].includes(request.method))return new Response(request.method==='HEAD'?null:HTML,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}});
   return new Response('Not found',{status:404});
  }catch(e){
   if(e.status)return json({error:e.message},e.status);
   console.error('request_failed',{path,error:e.message});return json({error:'Could not complete the request. Please try again.'},500);
  }
 }
};
