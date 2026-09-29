
const enc = new TextEncoder();

export function json(data,status=200,headers={}){
 return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
}
export function cookie(name,value,maxAge){
 const parts=[`${name}=${value}`,'Path=/','HttpOnly','Secure','SameSite=Lax'];
 if(maxAge!==undefined) parts.push(`Max-Age=${maxAge}`);
 return parts.join('; ');
}
export function getCookie(request,name){
 const raw=request.headers.get('Cookie')||'';
 for(const part of raw.split(';')){
  const [k,...v]=part.trim().split('=');
  if(k===name)return v.join('=');
 }
 return '';
}
export function randomToken(){
 const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);
 return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
}
export async function hashText(text){
 const digest=await crypto.subtle.digest('SHA-256',enc.encode(text));
 return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
}
export async function passwordHash(password,salt){
 const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
 const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:150000,hash:'SHA-256'},material,256);
 return Array.from(new Uint8Array(bits),b=>b.toString(16).padStart(2,'0')).join('');
}
export async function currentUser(context){
 const token=getCookie(context.request,'aet_session');
 if(!token)return null;
 const tokenHash=await hashText(token);
 const row=await context.env.DB.prepare(
  `SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id
   WHERE s.token_hash=? AND s.expires_at > datetime('now') LIMIT 1`
 ).bind(tokenHash).first();
 return row||null;
}
export async function requireUser(context){
 const user=await currentUser(context);
 if(!user) return {response:json({error:'Not signed in'},401)};
 return {user};
}
