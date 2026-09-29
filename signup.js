
import {json,cookie,randomToken,hashText,passwordHash} from '../_lib.js';
export async function onRequestPost(context){
 try{
  const {email,password}=await context.request.json();
  const clean=String(email||'').trim().toLowerCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) return json({error:'Enter a valid email.'},400);
  if(String(password||'').length<6) return json({error:'Password must be at least 6 characters.'},400);
  const exists=await context.env.DB.prepare('SELECT id FROM users WHERE email=? LIMIT 1').bind(clean).first();
  if(exists)return json({error:'An account with this email already exists.'},409);
  const id=crypto.randomUUID(),salt=randomToken(),hash=await passwordHash(password,salt);
  await context.env.DB.prepare('INSERT INTO users (id,email,password_hash,password_salt,created_at) VALUES (?,?,?,?,datetime(\\'now\\'))').bind(id,clean,hash,salt).run();
  const token=randomToken(),tokenHash=await hashText(token);
  await context.env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,datetime('now','+30 days'),datetime('now'))").bind(tokenHash,id).run();
  return json({ok:true,user:{id,email:clean}},201,{'set-cookie':cookie('aet_session',token,2592000)});
 }catch(e){return json({error:'Sign up failed: '+e.message},500);}
}
