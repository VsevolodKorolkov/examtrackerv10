
import {json,requireUser} from '../_lib.js';
export async function onRequestPost(context){
 const auth=await requireUser(context);if(auth.response)return auth.response;
 const {examDate}=await context.request.json();
 const value=examDate?new Date(examDate).toISOString():null;
 await context.env.DB.prepare(
  `INSERT INTO exam_settings (user_id,exam_date,updated_at) VALUES (?,?,datetime('now'))
   ON CONFLICT(user_id) DO UPDATE SET exam_date=excluded.exam_date,updated_at=datetime('now')`
 ).bind(auth.user.id,value).run();
 return json({ok:true});
}
