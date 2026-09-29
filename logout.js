
import {json,cookie,getCookie,hashText} from '../_lib.js';
export async function onRequestPost(context){
 try{
  const token=getCookie(context.request,'aet_session');
  if(token){const h=await hashText(token);await context.env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(h).run();}
  return json({ok:true},200,{'set-cookie':cookie('aet_session','',0)});
 }catch(e){return json({ok:true},200,{'set-cookie':cookie('aet_session','',0)});}
}
