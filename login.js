
import {json,cookie,randomToken,hashText,passwordHash} from '../_lib.js';
export async function onRequestPost(context){
 try{
  const {email,password}=await context.request.json();
  const clean=String(email||'').trim().toLowerCase();
  const user=await context.env.DB.prepare('SELECT id,email,password_hash,password_salt FROM users WHERE email=? LIMIT 1').bind(clean).first();
  if(!user)return json({error:'Incorrect email or password.'},401);
  const hash=await passwordHash(String(password||''),user.password_salt);
  if(hash!==user.password_hash)return json({error:'Incorrect email or password.'},401);
  const token=randomToken(),tokenHash=await hashText(token);
  await context.env.DB.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
  await context.env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,datetime('now','+30 days'),datetime('now'))").bind(tokenHash,user.id).run();
  return json({ok:true,user:{id:user.id,email:user.email}},200,{'set-cookie':cookie('aet_session',token,2592000)});
 }catch(e){return json({error:'Login failed: '+e.message},500);}
}
