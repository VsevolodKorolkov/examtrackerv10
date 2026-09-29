
import {json,requireUser} from '../_lib.js';
const valid=new Set(['NotStarted','InProgress','NeedsReview','Mastered']);
export async function onRequestGet(context){
 const auth=await requireUser(context);if(auth.response)return auth.response;
 const {results}=await context.env.DB.prepare('SELECT topic_id,status,last_reviewed FROM topic_progress WHERE user_id=? ORDER BY topic_id').bind(auth.user.id).all();
 const settings=await context.env.DB.prepare('SELECT exam_date FROM exam_settings WHERE user_id=? LIMIT 1').bind(auth.user.id).first();
 return json({progress:results||[],examDate:settings?.exam_date||null});
}
export async function onRequestPost(context){
 const auth=await requireUser(context);if(auth.response)return auth.response;
 const body=await context.request.json(),topicId=Number(body.topicId),status=String(body.status||'');
 if(!Number.isInteger(topicId)||topicId<0||topicId>1000||!valid.has(status))return json({error:'Invalid progress data.'},400);
 await context.env.DB.prepare(
  `INSERT INTO topic_progress (user_id,topic_id,status,last_reviewed,updated_at)
   VALUES (?,?,?,?,datetime('now'))
   ON CONFLICT(user_id,topic_id) DO UPDATE SET status=excluded.status,last_reviewed=excluded.last_reviewed,updated_at=datetime('now')`
 ).bind(auth.user.id,topicId,status,body.lastReviewed||null).run();
 return json({ok:true});
}
export async function onRequestDelete(context){
 const auth=await requireUser(context);if(auth.response)return auth.response;
 await context.env.DB.batch([
  context.env.DB.prepare('DELETE FROM topic_progress WHERE user_id=?').bind(auth.user.id),
  context.env.DB.prepare('DELETE FROM exam_settings WHERE user_id=?').bind(auth.user.id)
 ]);
 return json({ok:true});
}
