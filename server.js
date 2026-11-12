// Sone Sathi license server + admin panel
const express=require('express'),crypto=require('crypto'),fs=require('fs'),path=require('path'),zlib=require('zlib');
const D=__dirname,DB=path.join(D,'data.json'),KF=path.join(D,'keys.json'),BK=path.join(D,'backups');
const PASS=process.env.ADMIN_PASSWORD||'admin123',PORT=process.env.PORT||3000,DAY=864e5;
let keys;
if(fs.existsSync(KF))keys=JSON.parse(fs.readFileSync(KF));
else{const k=crypto.generateKeyPairSync('ed25519');keys={pub:k.publicKey.export({type:'spki',format:'pem'}),priv:k.privateKey.export({type:'pkcs8',format:'pem'})};fs.writeFileSync(KF,JSON.stringify(keys))}
const appDir=path.join(D,'..','shop-app');
if(fs.existsSync(appDir))fs.writeFileSync(path.join(appDir,'public.pem'),keys.pub);
const load=()=>fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB)):{shops:[]};
const save=d=>fs.writeFileSync(DB,JSON.stringify(d,null,1));
const sign=p=>{const b=Buffer.from(JSON.stringify(p));return b.toString('base64')+'.'+crypto.sign(null,b,crypto.createPrivateKey(keys.priv)).toString('base64')};
const mkKey=()=>'SONE-'+[1,2,3].map(()=>crypto.randomBytes(2).toString('hex').toUpperCase()).join('-');
const app=express();app.use(express.json({limit:'50mb'}));

// ---- shop app calls this ----
app.post('/api/license/check',(req,res)=>{
  const {key,deviceId,recoveryKey}=req.body||{},d=load(),s=d.shops.find(x=>x.key===key);
  if(!s)return res.status(404).json({error:'Key galat hai'});
  if(s.status==='suspended')return res.status(403).json({error:'Account band hai. Provider se baat karein'});
  if(!s.deviceId)s.deviceId=deviceId;
  if(s.deviceId!==deviceId)return res.status(409).json({error:'Ye key doosre computer par lagi hai'});
  s.lastSeen=Date.now();
  if(recoveryKey && typeof recoveryKey === 'string' && recoveryKey.trim()){
    s.recoveryKey = recoveryKey.trim().toUpperCase();
  }
  save(d);
  if(s.paidUntil<Date.now())return res.status(402).json({error:'Monthly payment baaki hai'});
  res.json({
    token:sign({key,name:s.name,paidUntil:s.paidUntil,deviceId,checkBy:Date.now()+7*DAY}),
    logo:s.logo||null,
    address:s.address||'',
    phone:s.phone||'',
    gstin:s.gstin||'',
    name:s.name
  });
});

app.post('/api/license/recovery-key',(req,res)=>{
  const {key,deviceId,recoveryKey}=req.body||{},d=load(),s=d.shops.find(x=>x.key===key);
  if(!s)return res.status(404).json({error:'Shop nahi mili'});
  if(s.status==='suspended')return res.status(403).json({error:'Account band hai'});
  if(s.deviceId && s.deviceId!==deviceId)return res.status(409).json({error:'Ye key is computer par nahi lagi'});
  if(recoveryKey && typeof recoveryKey === 'string' && recoveryKey.trim()){
    s.recoveryKey = recoveryKey.trim().toUpperCase();
    save(d);
  }
  res.json({ok:1});
});


// ---- cloud backup: shop app yahan poora data bhejta hai ----
const BN=/^(latest|\d{4}-\d{2}-\d{2})\.json\.gz$/;
const bkList=s=>{const dir=path.join(BK,s.id);if(!fs.existsSync(dir))return[];
  return fs.readdirSync(dir).filter(f=>BN.test(f)).map(f=>{const st=fs.statSync(path.join(dir,f));return{name:f,size:st.size,time:st.mtimeMs,label:f==='latest.json.gz'?'Sabse naya':f.replace('.json.gz','')}}).sort((a,b)=>b.time-a.time)};
const shopAuth=(q,r)=>{const {key,deviceId}=q.body||{},s=load().shops.find(x=>x.key===key);
  if(!s){r.status(404).json({error:'Key galat hai'});return null}
  if(s.status==='suspended'){r.status(403).json({error:'Account band hai'});return null}
  if(!s.deviceId||s.deviceId!==deviceId){r.status(409).json({error:'Ye key is computer par nahi lagi'});return null}
  return s};
app.post('/api/backup/upload',(q,r)=>{const s=shopAuth(q,r);if(!s)return;const {gz,deviceId,force,recoveryKey}=q.body;
  if(typeof gz!=='string'||gz.length<10)return r.status(400).json({error:'Data nahi mila'});
  if(s.bkDevice&&s.bkDevice!==deviceId&&!force)return r.status(409).json({error:'NEEDS_RESTORE'}); // naya computer purana cloud data galti se na mita de
  const dir=path.join(BK,s.id),buf=Buffer.from(gz,'base64');fs.mkdirSync(dir,{recursive:true});
  fs.writeFileSync(path.join(dir,'latest.json.gz'),buf);fs.writeFileSync(path.join(dir,new Date().toISOString().slice(0,10)+'.json.gz'),buf);
  fs.readdirSync(dir).filter(f=>/^\d{4}-/.test(f)).sort().slice(0,-30).forEach(f=>fs.unlinkSync(path.join(dir,f))); // pichhle 30 din
  const d=load(),x=d.shops.find(y=>y.id===s.id);x.bkDevice=deviceId;
  if(recoveryKey && typeof recoveryKey === 'string' && recoveryKey.trim()){
    x.recoveryKey = recoveryKey.trim().toUpperCase();
  }
  save(d);r.json({ok:1})});
app.post('/api/backup/list',(q,r)=>{const s=shopAuth(q,r);if(s)r.json({shop:s.name,list:bkList(s)})});
app.post('/api/backup/download',(q,r)=>{const s=shopAuth(q,r);if(!s)return;const f=String(q.body.name||'');if(!BN.test(f))return r.sendStatus(400);
  const p=path.join(BK,s.id,f);if(!fs.existsSync(p))return r.status(404).json({error:'Backup nahi mila'});
  const d=load(),x=d.shops.find(y=>y.id===s.id);x.bkDevice=q.body.deviceId;save(d); // restore karne wala computer ab "asli" ban gaya
  r.json({gz:fs.readFileSync(p).toString('base64')})});

// ---- admin (password protected) ----
const auth=(req,res,next)=>{const h=Buffer.from((req.headers.authorization||'').split(' ')[1]||'','base64').toString();
  if(h.slice(h.indexOf(':')+1)===PASS)return next();res.set('WWW-Authenticate','Basic realm="Admin"').status(401).send('Login chahiye')};
app.use('/admin',auth,express.static(path.join(D,'admin')));
app.use('/api/admin',auth);
app.get('/api/admin/shops',(q,r)=>r.json(load().shops.map(s=>({...s,bk:bkList(s)[0]||null}))));
app.get('/api/admin/shops/:id/backup/:name',(q,r)=>{const s=load().shops.find(x=>x.id===q.params.id);if(!s||!BN.test(q.params.name))return r.sendStatus(404);const p=path.join(BK,s.id,q.params.name);if(!fs.existsSync(p))return r.sendStatus(404);
  r.set('Content-Type','application/json').set('Content-Disposition','attachment; filename="'+s.name.replace(/[^\w]/g,'_')+'-'+q.params.name.replace('.gz','')+'"').send(zlib.gunzipSync(fs.readFileSync(p)))});
app.post('/api/admin/shops',(q,r)=>{const d=load(),m=Number(q.body.months)||0;
  d.shops.push({
    id:Date.now().toString(36),
    name:q.body.name||'Shop',
    phone:q.body.phone||'',
    address:q.body.address||'',
    gstin:q.body.gstin||'',
    logo:q.body.logo||null,
    key:mkKey(),
    status:'active',
    deviceId:null,
    lastSeen:null,
    paidUntil:Date.now()+m*30*DAY
  });save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/logo',(q,r)=>{
  const d=load(),s=d.shops.find(x=>x.id===q.params.id);
  if(!s)return r.sendStatus(404);
  s.logo=q.body.logo||null;
  save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/extend',(q,r)=>{const d=load(),s=d.shops.find(x=>x.id===q.params.id);if(!s)return r.sendStatus(404);
  s.paidUntil=Math.max(s.paidUntil,Date.now())+(Number(q.body.months)||1)*30*DAY;save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/recovery-key',(q,r)=>{const d=load(),s=d.shops.find(x=>x.id===q.params.id);if(!s)return r.sendStatus(404);s.recoveryKey=String(q.body.recoveryKey||'').trim().toUpperCase()||null;save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/:act',(q,r)=>{const d=load(),s=d.shops.find(x=>x.id===q.params.id);if(!s)return r.sendStatus(404);
  const a=q.params.act;if(a==='suspend')s.status='suspended';else if(a==='resume')s.status='active';else if(a==='reset')s.deviceId=null;else return r.sendStatus(400);save(d);r.json({ok:1})});
app.delete('/api/admin/shops/:id',(q,r)=>{const d=load();d.shops=d.shops.filter(x=>x.id!==q.params.id);save(d);r.json({ok:1})});
app.listen(PORT,()=>console.log('Server chal raha: http://localhost:'+PORT+'/admin  (password: '+(process.env.ADMIN_PASSWORD?'set':'admin123 - badal do!')+')'));
