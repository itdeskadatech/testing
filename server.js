require('dotenv').config();
const express=require('express'),helmet=require('helmet'),{Pool}=require('pg'),fs=require('fs'),path=require('path');
const pool=new Pool(process.env.DATABASE_URL?{connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='false'?false:{rejectUnauthorized:false}}:{host:process.env.PGHOST||'localhost',port:+process.env.PGPORT||5432,database:process.env.PGDATABASE||'SalesDataManager',user:process.env.PGUSER||'postgres',password:process.env.PGPASSWORD});
const app=express();
app.set('trust proxy',1);
const Q=(s,p)=>pool.query(s,p), I=c=>'"'+c.replace(/"/g,'""')+'"';
const wrap=f=>(req,res)=>f(req,res).catch(e=>{console.error(e.message);res.status(500).json({error:e.message})});

app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:'1mb'}));

const crypto=require('crypto'),prod=process.env.NODE_ENV==='production';
const hash=pw=>new Promise((ok,no)=>{const salt=crypto.randomBytes(16);crypto.scrypt(pw,salt,64,(e,k)=>e?no(e):ok(salt.toString('hex')+':'+k.toString('hex')))});
const verify=(pw,st)=>new Promise(ok=>{const[a,b]=st.split(':');crypto.scrypt(pw,Buffer.from(a,'hex'),64,(e,d)=>ok(!e&&crypto.timingSafeEqual(d,Buffer.from(b,'hex'))))});
const sha=t=>crypto.createHash('sha256').update(t).digest('hex');
const getCookie=(req,n)=>{for(const c of(req.headers.cookie||'').split(';')){const i=c.indexOf('=');if(c.slice(0,i).trim()===n)return c.slice(i+1).trim()}return null};
const PUBLIC=new Set(['/api/health','/login.html','/api/auth/login']),fails=new Map();
app.use(async(req,res,next)=>{try{
 if(PUBLIC.has(req.path))return next();
 const t=getCookie(req,'sid');
 if(t){const r=await Q(`SELECT u.id,u.username,u.role FROM sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active`,[sha(t)]);
  if(r.rows[0]){req.user=r.rows[0];return next()}}
 if(req.path.startsWith('/api/'))return res.status(401).json({error:'Please sign in.'});
 res.redirect('/login.html')}catch(e){next(e)}});
app.use(express.static(path.join(__dirname,'public')));
app.post('/api/auth/login',wrap(async(req,res)=>{
 const k=req.ip,f=fails.get(k),fresh=f&&Date.now()-f.t<9e5;
 if(fresh&&f.n>=8)return res.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
 const u=String(req.body.username||'').trim().toLowerCase(),r=(await Q(`SELECT * FROM app_users WHERE username=$1 AND active`,[u])).rows[0];
 if(!r||!(await verify(String(req.body.password||''),r.password_hash))){fails.set(k,{n:(fresh?f.n:0)+1,t:Date.now()});return res.status(401).json({error:'Wrong username or password.'})}
 fails.delete(k);await Q(`DELETE FROM sessions WHERE expires_at<now()`);
 const tok=crypto.randomBytes(32).toString('hex');
 await Q(`INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '7 days')`,[sha(tok),r.id]);
 res.set('Set-Cookie',`sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${prod?'; Secure':''}`).json({ok:true})}));
app.post('/api/auth/logout',wrap(async(req,res)=>{const t=getCookie(req,'sid');if(t)await Q(`DELETE FROM sessions WHERE token_hash=$1`,[sha(t)]);
 res.set('Set-Cookie','sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0').json({ok:true})}));
app.get('/api/auth/me',(req,res)=>res.json(req.user));
const adm=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Admin only.'});
app.get('/api/users',adm,wrap(async(req,res)=>res.json((await Q(`SELECT id,username,role,active,created_at FROM app_users ORDER BY id`)).rows)));
app.post('/api/users',adm,wrap(async(req,res)=>{
 const u=String(req.body.username||'').trim().toLowerCase(),pw=String(req.body.password||''),role=req.body.role==='admin'?'admin':'member';
 if(!/^[a-z0-9._-]{3,32}$/.test(u))return res.status(400).json({error:'Username: 3-32 letters, numbers, dot, dash or underscore.'});
 if(pw.length<10)return res.status(400).json({error:'Password must be at least 10 characters.'});
 try{await Q(`INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,$3)`,[u,await hash(pw),role]);res.json({ok:true})}
 catch(e){if(e.code==='23505')return res.status(409).json({error:'That username already exists.'});throw e}}));
app.patch('/api/users/:id',adm,wrap(async(req,res)=>{
 const id=+req.params.id,b=req.body,set=[],p=[id];
 if(id===req.user.id&&(b.active===false||(b.role&&b.role!=='admin')))return res.status(400).json({error:'You cannot disable or demote your own account.'});
 if(b.role){p.push(b.role==='admin'?'admin':'member');set.push(`role=$${p.length}`)}
 if(typeof b.active==='boolean'){p.push(b.active);set.push(`active=$${p.length}`)}
 if(b.password!==undefined){if(String(b.password).length<10)return res.status(400).json({error:'Password must be at least 10 characters.'});p.push(await hash(String(b.password)));set.push(`password_hash=$${p.length}`)}
 if(!set.length)return res.status(400).json({error:'Nothing to update.'});
 await Q(`UPDATE app_users SET ${set.join(',')} WHERE id=$1`,p);
 if(b.password!==undefined||b.active===false)await Q(`DELETE FROM sessions WHERE user_id=$1`,[id]);
 res.json({ok:true})}));
const EXP=path.join(__dirname,'exports');fs.mkdirSync(EXP,{recursive:true});
const T='sales_leads',FILT=['university','course','state','city','source','usage_status','call_status','import_batch'];
let COLS=[];
function where(qs){const w=[],p=[];
 for(const f of FILT){if(!COLS.includes(f)||!qs[f])continue;const v=[].concat(qs[f]).filter(x=>x!=='');
  if(v.length){p.push(v.map(x=>String(x).trim().toLowerCase()));w.push(`lower(btrim(${I(f)}::text)) = ANY($${p.length})`)}}
 if(qs.search){const sc=['first_name','last_name','phone_number','email'].filter(c=>COLS.includes(c));
  if(sc.length){p.push('%'+qs.search+'%');w.push('('+sc.map(c=>`${I(c)}::text ILIKE $${p.length}`).join(' OR ')+')')}}
 return{sql:w.length?'WHERE '+w.join(' AND '):'',p}}
async function init(){
 const r=await Q(`SELECT column_name FROM information_schema.columns WHERE table_name=$1 ORDER BY ordinal_position`,[T]);
 COLS=r.rows.map(x=>x.column_name);
 await Q(`CREATE TABLE IF NOT EXISTS status_audit(id SERIAL PRIMARY KEY,lead_id BIGINT,field TEXT,old_value TEXT,new_value TEXT,changed_at TIMESTAMPTZ DEFAULT now())`);
 await Q(`ALTER TABLE status_audit ADD COLUMN IF NOT EXISTS changed_by TEXT`);
 await Q(`ALTER TABLE IF EXISTS extraction_jobs ADD COLUMN IF NOT EXISTS mark_value TEXT, ADD COLUMN IF NOT EXISTS marked INT DEFAULT 0, ADD COLUMN IF NOT EXISTS created_by TEXT`).catch(()=>{});
 await Q(`CREATE TABLE IF NOT EXISTS extraction_jobs(id SERIAL PRIMARY KEY,filters JSONB,fields TEXT[],format TEXT DEFAULT 'csv',requested INT,exported INT DEFAULT 0,failed INT DEFAULT 0,mark_value TEXT,marked INT DEFAULT 0,created_by TEXT,status TEXT DEFAULT 'queued',file_name TEXT,file_size BIGINT,error TEXT,created_at TIMESTAMPTZ DEFAULT now(),completed_at TIMESTAMPTZ)`);
 await Q(`CREATE TABLE IF NOT EXISTS app_users(id SERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'member',active BOOLEAN DEFAULT true,created_at TIMESTAMPTZ DEFAULT now())`);
 await Q(`CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INT REFERENCES app_users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL)`);
 if(!(await Q('SELECT 1 FROM app_users LIMIT 1')).rows.length){const pw=process.env.ADMIN_PASSWORD;
  if(!pw||pw.length<10)throw new Error('Add ADMIN_PASSWORD (10+ characters) to your .env or environment variables to create the first admin.');
  const u=(process.env.ADMIN_USER||'admin').trim().toLowerCase();
  await Q(`INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,'admin')`,[u,await hash(pw)]);console.log('First admin created: '+u)}
}
app.get('/api/health',wrap(async(req,res)=>{await Q('SELECT 1');res.json({ok:true})}));
app.get('/api/filters',wrap(async(req,res)=>{const o={};
 for(const f of FILT)if(COLS.includes(f))o[f]=(await Q(`SELECT DISTINCT lower(btrim(${I(f)}::text)) v FROM ${T} WHERE btrim(${I(f)}::text)<>'' ORDER BY 1 LIMIT 500`)).rows.map(x=>x.v);
 res.json({filters:o,columns:COLS})}));
app.get('/api/dashboard/stats',wrap(async(req,res)=>{const{sql,p}=where(req.query);
 const has=c=>COLS.includes(c);
 const k=(await Q(`SELECT count(*)::int total${has('phone_number')?',count(DISTINCT phone_number)::int unique_phones,count(phone_number)::int with_phone':''}${has('import_batch')?',count(DISTINCT import_batch)::int batches':''} FROM ${T} ${sql}`,p)).rows[0];
 if(k.with_phone!==undefined)k.duplicate_records=k.with_phone-k.unique_phones;
 const charts={};
 for(const f of FILT)if(has(f))charts[f]=(await Q(`SELECT COALESCE(NULLIF(lower(btrim(${I(f)}::text)),''),'(missing)') label,count(*)::int n FROM ${T} ${sql} GROUP BY 1 ORDER BY 2 DESC LIMIT 15`,p)).rows;
 res.json({kpi:k,charts})}));
app.get('/api/leads',wrap(async(req,res)=>{const{sql,p}=where(req.query);
 const size=[25,50,100,250].includes(+req.query.pageSize)?+req.query.pageSize:25,page=Math.max(1,+req.query.page||1);
 const sort=COLS.includes(req.query.sort)?req.query.sort:(COLS.includes('id')?'id':COLS[0]),dir=req.query.dir==='desc'?'DESC':'ASC';
 const total=(await Q(`SELECT count(*)::int n FROM ${T} ${sql}`,p)).rows[0].n;
 const rows=(await Q(`SELECT * FROM ${T} ${sql} ORDER BY ${I(sort)} ${dir} LIMIT ${size} OFFSET ${(page-1)*size}`,p)).rows;
 res.json({total,page,pageSize:size,columns:COLS,rows})}));
app.get('/api/leads/:id',wrap(async(req,res)=>{const r=await Q(`SELECT * FROM ${T} WHERE id=$1`,[req.params.id]);r.rows[0]?res.json(r.rows[0]):res.status(404).json({error:'Not found'})}));
app.post('/api/leads/status',wrap(async(req,res)=>{
 const f=req.body.field,v=String(req.body.value||'').trim().toLowerCase();
 if(!['usage_status','call_status'].includes(f)||!COLS.includes(f))return res.status(400).json({error:'Invalid status field.'});
 if(!v)return res.status(400).json({error:'Enter a status value.'});
 let sql,p;
 if(req.body.all){({sql,p}=where(req.body.filters||{}))}
 else{const ids=[].concat(req.body.ids||[]).map(Number).filter(Number.isInteger);if(!ids.length)return res.status(400).json({error:'No leads selected.'});sql='WHERE id = ANY($1)';p=[ids]}
 const n=p.length,c=await pool.connect();
 try{await c.query('BEGIN');
  await c.query(`INSERT INTO status_audit(lead_id,field,old_value,new_value,changed_by) SELECT id,$${n+1}::text,${I(f)}::text,$${n+2}::text,$${n+3}::text FROM ${T} ${sql}`,[...p,f,v,req.user.username]);
  const r=await c.query(`UPDATE ${T} SET ${I(f)}=$${n+1} ${sql}`,[...p,v]);
  await c.query('COMMIT');res.json({updated:r.rowCount})}
 catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}));
const esc=v=>{if(v==null)return'';if(v instanceof Date)v=v.toISOString();v=String(v);return/[",\n\r]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v};
async function runExport(jobId,filters,fields,mark,user){
 const{sql,p}=where(filters),file=`extraction_${jobId}.csv`,fp=path.join(EXP,file);
 try{await Q(`UPDATE extraction_jobs SET status='running' WHERE id=$1`,[jobId]);
  const out=fs.createWriteStream(fp);out.write('\ufeff'+fields.join(',')+'\n');
  let done=0;const ids=[],idc=COLS.includes('id');const cols=[...new Set([...fields,...(idc?['id']:[])])].map(I).join(',');
  for(let off=0;;off+=5000){
   const r=(await Q(`SELECT ${cols} FROM ${T} ${sql} ORDER BY ${idc?'id':I(COLS[0])} LIMIT 5000 OFFSET ${off}`,p)).rows;
   if(!r.length)break;
   const ok=out.write(r.map(x=>fields.map(f=>esc(x[f])).join(',')).join('\n')+'\n');
   if(!ok)await new Promise(s=>out.once('drain',s));
   done+=r.length;if(idc)r.forEach(x=>ids.push(x.id));
  }
  await new Promise(s=>out.end(s));
  let marked=0;
  if(mark&&idc&&ids.length){const c=await pool.connect();
   try{await c.query('BEGIN');
    await c.query(`INSERT INTO status_audit(lead_id,field,old_value,new_value,changed_by) SELECT id,'usage_status',usage_status::text,$2::text,$3::text FROM ${T} WHERE id=ANY($1)`,[ids,mark,user]);
    marked=(await c.query(`UPDATE ${T} SET usage_status=$2 WHERE id=ANY($1)`,[ids,mark])).rowCount;
    await c.query('COMMIT')}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}
  await Q(`UPDATE extraction_jobs SET status='completed',exported=$2,file_name=$3,file_size=$4,marked=$5,completed_at=now() WHERE id=$1`,[jobId,done,file,fs.statSync(fp).size,marked]);
 }catch(e){await Q(`UPDATE extraction_jobs SET status='failed',error=$2,completed_at=now() WHERE id=$1`,[jobId,e.message])}}
app.post('/api/extractions',wrap(async(req,res)=>{
 const filters=req.body.filters||{},fields=(req.body.fields||[]).filter(f=>COLS.includes(f));
 if(req.body.format&&req.body.format!=='csv')return res.status(400).json({error:'Only CSV export is supported in this version.'});
 if(!fields.length)return res.status(400).json({error:'Select at least one field.'});
 const mark=req.body.mark?String(req.body.mark).trim().toLowerCase():null;
 if(mark&&!COLS.includes('usage_status'))return res.status(400).json({error:'No usage_status column to update.'});
 const{sql,p}=where(filters),n=(await Q(`SELECT count(*)::int n FROM ${T} ${sql}`,p)).rows[0].n;
 const j=(await Q(`INSERT INTO extraction_jobs(filters,fields,requested,mark_value,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *`,[filters,fields,n,mark,req.user.username])).rows[0];
 runExport(j.id,filters,fields,mark,req.user.username);res.status(202).json(j)}));
app.get('/api/extractions',wrap(async(req,res)=>res.json((await Q(`SELECT * FROM extraction_jobs ORDER BY id DESC LIMIT 100`)).rows)));
app.get('/api/extractions/:id',wrap(async(req,res)=>{const r=await Q(`SELECT * FROM extraction_jobs WHERE id=$1`,[+req.params.id||0]);r.rows[0]?res.json(r.rows[0]):res.status(404).json({error:'Not found'})}));
app.get('/api/extractions/:id/download',wrap(async(req,res)=>{
 const r=(await Q(`SELECT * FROM extraction_jobs WHERE id=$1 AND status='completed'`,[+req.params.id||0])).rows[0];
 if(!r)return res.status(404).json({error:'File not ready'});
 res.download(path.join(EXP,path.basename(r.file_name)))}));
init().then(()=>app.listen(process.env.PORT||3000,()=>console.log('Sales Data Manager running at http://localhost:'+(process.env.PORT||3000)+'  columns: '+COLS.join(', '))))
 .catch(e=>{console.error('Startup failed:',e.message);process.exit(1)});
