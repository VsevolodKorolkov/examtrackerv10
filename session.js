
import {json,currentUser} from '../_lib.js';
export async function onRequestGet(context){
 const user=await currentUser(context);
 return user?json({user}):json({error:'Not signed in'},401);
}
