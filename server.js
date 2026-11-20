// Sone Sathi license server + admin panel
const express=require('express'),crypto=require('crypto'),fs=require('fs'),path=require('path'),zlib=require('zlib');
const { MongoClient } = require('mongodb');
const D=__dirname,DB=path.join(D,'data.json'),KF=path.join(D,'keys.json'),BK=path.join(D,'backups');
const PASS=process.env.ADMIN_PASSWORD||'admin123',PORT=process.env.PORT||3000,DAY=864e5;
const MONGODB_URI=process.env.MONGODB_URI||process.env.MONGO_URL||'';
let mongoDb=null,mongoClient=null;

let keys;
if(fs.existsSync(KF))keys=JSON.parse(fs.readFileSync(KF));
else{const k=crypto.generateKeyPairSync('ed25519');keys={pub:k.publicKey.export({type:'spki',format:'pem'}),priv:k.privateKey.export({type:'pkcs8',format:'pem'})};fs.writeFileSync(KF,JSON.stringify(keys))}
const appDir=path.join(D,'..','shop-app');
if(fs.existsSync(appDir))fs.writeFileSync(path.join(appDir,'public.pem'),keys.pub);

let dataCache = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB)) : { shops: [] };
const load = () => dataCache;

function save(d) {
  dataCache = d;
  try { fs.writeFileSync(DB, JSON.stringify(d, null, 1)); } catch (_) {}
  if (mongoDb) {
    (async () => {
      try {
        const confCol = mongoDb.collection('config');
        const shopsCol = mongoDb.collection('shops');
        if (d.announcement !== undefined) {
          await confCol.updateOne({ _id: 'announcement' }, { $set: { data: d.announcement } }, { upsert: true });
        }
        if (d.adminSettings !== undefined) {
          await confCol.updateOne({ _id: 'adminSettings' }, { $set: { data: d.adminSettings } }, { upsert: true });
        }
        if (d.appUpdate !== undefined) {
          await confCol.updateOne({ _id: 'appUpdate' }, { $set: { data: d.appUpdate } }, { upsert: true });
        }
        if (Array.isArray(d.shops)) {
          const currentIds = d.shops.map(s => s.id);
          await shopsCol.deleteMany({ id: { $nin: currentIds } });
          for (const s of d.shops) {
            await shopsCol.updateOne({ id: s.id }, { $set: s }, { upsert: true });
          }
        }
      } catch (e) {
        console.error('MongoDB async save error:', e.message);
      }
    })();
  }
}

async function initMongo() {
  if (!MONGODB_URI) {
    console.log('ℹ️ MONGODB_URI nahi mila. Local data.json & keys.json use ho raha hai.');
    return;
  }
  try {
    console.log('Connecting to MongoDB Atlas...');
    mongoClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    await mongoClient.connect();
    mongoDb = mongoClient.db('sone_sathi_db');
    console.log('✅ MongoDB Atlas connected successfully! Zero data loss enabled.');

    const confCol = mongoDb.collection('config');
    const shopsCol = mongoDb.collection('shops');

    // 1. Keys sync
    const savedKeys = await confCol.findOne({ _id: 'keys' });
    if (savedKeys && savedKeys.pub && savedKeys.priv) {
      keys = { pub: savedKeys.pub, priv: savedKeys.priv };
      try { fs.writeFileSync(KF, JSON.stringify(keys)); } catch(_) {}
      console.log('🔑 Loaded persistent signing keys from MongoDB Atlas.');
    } else {
      await confCol.updateOne({ _id: 'keys' }, { $set: { pub: keys.pub, priv: keys.priv } }, { upsert: true });
      console.log('🔑 Saved initial signing keys to MongoDB Atlas.');
    }

    // 2. Announcement sync
    const savedAnn = await confCol.findOne({ _id: 'announcement' });
    if (savedAnn && savedAnn.data) {
      dataCache.announcement = savedAnn.data;
    }

    // 3. Admin settings sync
    const savedSet = await confCol.findOne({ _id: 'adminSettings' });
    if (savedSet && savedSet.data) {
      dataCache.adminSettings = savedSet.data;
    }

    // 4. Remote App Update info sync
    const savedUp = await confCol.findOne({ _id: 'appUpdate' });
    if (savedUp && savedUp.data) {
      dataCache.appUpdate = savedUp.data;
    } else if (!dataCache.appUpdate) {
      dataCache.appUpdate = { version: '1.0.0', downloadUrl: '', notes: 'Official Stable Release', mandatory: false, releaseDate: Date.now() };
    }

    // 5. Shops sync
    const count = await shopsCol.countDocuments();
    if (count > 0) {
      const remoteShops = await shopsCol.find({}).toArray();
      dataCache.shops = remoteShops.map(s => {
        const { _id, ...rest } = s;
        return rest;
      });
      try { fs.writeFileSync(DB, JSON.stringify(dataCache, null, 1)); } catch(_) {}
      console.log(`🏢 Loaded ${dataCache.shops.length} shops permanently from MongoDB Atlas.`);
    } else if (dataCache.shops && dataCache.shops.length > 0) {
      console.log(`Migrating ${dataCache.shops.length} local shops to MongoDB Atlas...`);
      for (const s of dataCache.shops) {
        await shopsCol.updateOne({ id: s.id }, { $set: s }, { upsert: true });
      }
    }
  } catch (err) {
    console.error('⚠️ MongoDB Atlas connection failed:', err.message, '\nFallback to local disk storage.');
    mongoDb = null;
  }
}
initMongo();

const sign=p=>{const b=Buffer.from(JSON.stringify(p));return b.toString('base64')+'.'+crypto.sign(null,b,crypto.createPrivateKey(keys.priv)).toString('base64')};
const mkKey=()=>'SONE-'+[1,2,3].map(()=>crypto.randomBytes(2).toString('hex').toUpperCase()).join('-');
const app=express();app.use(express.json({limit:'50mb'}));

// ---- shop app calls this ----
app.post('/api/license/check',(req,res)=>{
  const {key,deviceId,recoveryKey,metrics}=req.body||{},d=load(),s=d.shops.find(x=>x.key===key);
  if(!s)return res.status(404).json({error:'Key galat hai'});
  if(s.status==='suspended')return res.status(403).json({error:'Account band hai. Provider se baat karein'});

  let migrated = false;
  const reqRecKey = (recoveryKey && typeof recoveryKey === 'string') ? recoveryKey.trim().toUpperCase() : null;
  const matchRecKey = (reqRecKey && s.recoveryKey && reqRecKey === s.recoveryKey);

  if(!s.deviceId){
    s.deviceId = deviceId;
  } else if(s.deviceId !== deviceId){
    if(s.migrationAllowed || matchRecKey){
      // Authorized PC Migration
      s.deviceId = deviceId;
      s.migrationAllowed = false;
      s.migratedAt = Date.now();
      migrated = true;
    } else {
      return res.status(409).json({
        error:'Ye key doosre computer par lagi hai. Naye computer par chalane ke liye Admin se "PC Migration" authorize karwayen ya Recovery Passkey dalein.',
        locked: true
      });
    }
  }

  s.lastSeen=Date.now();
  if(recoveryKey && typeof recoveryKey === 'string' && recoveryKey.trim()){
    s.recoveryKey = recoveryKey.trim().toUpperCase();
  }
  if(metrics && typeof metrics === 'object'){
    s.telemetry = {
      invoicesCount: Number(metrics.invoicesCount) || 0,
      customersCount: Number(metrics.customersCount) || 0,
      stockCount: Number(metrics.stockCount) || 0,
      appVersion: String(metrics.appVersion || '1.0.0').slice(0, 20),
      os: String(metrics.os || 'Windows').slice(0, 20),
      updatedAt: Date.now()
    };
  }
  save(d);

  const isTrial = !!s.isTrial;
  const trialDaysRemaining = isTrial ? Math.max(0, Math.ceil((s.paidUntil - Date.now()) / DAY)) : null;

  if(s.paidUntil < Date.now()){
    if(isTrial){
      return res.status(402).json({
        error: 'Aapka 7-din ka Free Trial poora ho chuka hai. Software bina kisi rukawat chalate rehne ke liye kripya provider se license renew karein.',
        isTrial: true,
        trialExpired: true
      });
    }
    return res.status(402).json({ error: 'Monthly payment baaki hai' });
  }

  const shopPlan = s.plan || 'standard';
  const shopModules = s.modules || {
    girvi: shopPlan !== 'basic',
    barcode: true,
    karigar: shopPlan === 'gold',
    gst: true
  };

  const bks = bkList(s);
  const hasCloudBackup = bks && bks.length > 0;
  const latestBackup = hasCloudBackup ? bks[0] : null;

  res.json({
    token:sign({
      key,
      name:s.name,
      paidUntil:s.paidUntil,
      deviceId,
      checkBy:Date.now()+7*DAY,
      plan:shopPlan,
      modules:shopModules,
      isTrial:isTrial,
      trialDaysRemaining:trialDaysRemaining
    }),
    logo:s.logo||null,
    address:s.address||'',
    phone:s.phone||'',
    gstin:s.gstin||'',
    name:s.name,
    announcement: d.announcement || null,
    appUpdate: d.appUpdate || null,
    plan: shopPlan,
    modules: shopModules,
    isTrial: isTrial,
    trialDaysRemaining: trialDaysRemaining,
    migrated: migrated,
    hasCloudBackup: hasCloudBackup,
    latestBackup: latestBackup
  });
});

app.get('/api/announcement',(req,res)=>{
  const d=load();
  res.json(d.announcement||{active:false,text:'',type:'info'});
});

app.get('/api/app-update',(req,res)=>{
  const d=load();
  res.json(d.appUpdate||{version:'1.0.0',downloadUrl:'',notes:'Official stable release',mandatory:false});
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
  if(q.body.metrics && typeof q.body.metrics === 'object'){
    const m = q.body.metrics;
    x.telemetry = {
      invoicesCount: Number(m.invoicesCount) || 0,
      customersCount: Number(m.customersCount) || 0,
      stockCount: Number(m.stockCount) || 0,
      appVersion: String(m.appVersion || '1.0.0').slice(0, 20),
      os: String(m.os || 'Windows').slice(0, 20),
      updatedAt: Date.now()
    };
  }
  save(d);
  if (mongoDb) {
    (async () => {
      try {
        await mongoDb.collection('backups').updateOne(
          { _id: `${s.id}_latest` },
          { $set: { shopId: s.id, name: 'latest.json.gz', gz: gz, size: buf.length, time: Date.now() } },
          { upsert: true }
        );
      } catch(e) { console.error('Mongo backup upload error:', e.message); }
    })();
  }
  r.json({ok:1})});
app.post('/api/backup/list',(q,r)=>{const s=shopAuth(q,r);if(s)r.json({shop:s.name,list:bkList(s)})});
app.post('/api/backup/download',async(q,r)=>{const s=shopAuth(q,r);if(!s)return;const f=String(q.body.name||'');if(!BN.test(f))return r.sendStatus(400);
  const p=path.join(BK,s.id,f);
  if(fs.existsSync(p)){
    const d=load(),x=d.shops.find(y=>y.id===s.id);x.bkDevice=q.body.deviceId;save(d);
    return r.json({gz:fs.readFileSync(p).toString('base64')});
  }
  if(mongoDb){
    try{
      const doc=await mongoDb.collection('backups').findOne({shopId:s.id,name:f});
      if(doc&&doc.gz){
        const d=load(),x=d.shops.find(y=>y.id===s.id);x.bkDevice=q.body.deviceId;save(d);
        return r.json({gz:doc.gz});
      }
    }catch(_){}
  }
  return r.status(404).json({error:'Backup nahi mila'});
});

// ---- admin (password protected) ----
const auth=(req,res,next)=>{const h=Buffer.from((req.headers.authorization||'').split(' ')[1]||'','base64').toString();
  if(h.slice(h.indexOf(':')+1)===PASS)return next();res.set('WWW-Authenticate','Basic realm="Admin"').status(401).send('Login chahiye')};
app.use('/admin',auth,express.static(path.join(D,'admin')));
app.use('/api/admin',auth);
app.get('/api/admin/shops',(q,r)=>r.json(load().shops.map(s=>({...s,bk:bkList(s)[0]||null}))));
app.get('/api/admin/shops/:id/backup/:name',(q,r)=>{const s=load().shops.find(x=>x.id===q.params.id);if(!s||!BN.test(q.params.name))return r.sendStatus(404);const p=path.join(BK,s.id,q.params.name);if(!fs.existsSync(p))return r.sendStatus(404);
  r.set('Content-Type','application/json').set('Content-Disposition','attachment; filename="'+s.name.replace(/[^\w]/g,'_')+'-'+q.params.name.replace('.gz','')+'"').send(zlib.gunzipSync(fs.readFileSync(p)))});
app.post('/api/admin/shops',(q,r)=>{const d=load();
  const isTrial = !!q.body.isTrial;
  const trialDays = Number(q.body.trialDays) || 7;
  const m = Number(q.body.months) || 0;
  const paidUntil = isTrial ? (Date.now() + trialDays * DAY) : (Date.now() + m * 30 * DAY);
  const plan = q.body.plan || 'standard';
  d.shops.push({
    id: Date.now().toString(36),
    name: q.body.name || 'Shop',
    phone: q.body.phone || '',
    address: q.body.address || '',
    gstin: q.body.gstin || '',
    logo: q.body.logo || null,
    key: mkKey(),
    status: 'active',
    deviceId: null,
    lastSeen: null,
    paidUntil: paidUntil,
    isTrial: isTrial,
    trialDays: isTrial ? trialDays : null,
    plan: plan,
    modules: q.body.modules || {
      girvi: plan !== 'basic',
      barcode: true,
      karigar: plan === 'gold',
      gst: true
    },
    telemetry: null,
    migrationAllowed: false
  });save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/convert-trial',(q,r)=>{
  const d=load(),s=d.shops.find(x=>x.id===q.params.id);
  if(!s)return r.sendStatus(404);
  const m = Number(q.body.months) || 1;
  s.isTrial = false;
  s.trialDays = null;
  s.paidUntil = Math.max(s.paidUntil || Date.now(), Date.now()) + m * 30 * DAY;
  if(q.body.plan) s.plan = q.body.plan;
  save(d);r.json({ok:1,shop:s})});
app.post('/api/admin/shops/:id/authorize-migration',(q,r)=>{
  const d=load(),s=d.shops.find(x=>x.id===q.params.id);
  if(!s)return r.sendStatus(404);
  s.deviceId = null;
  s.migrationAllowed = true;
  save(d);r.json({ok:1,shop:s,latestBackup:bkList(s)[0]||null})});
app.post('/api/admin/shops/:id/plan',(q,r)=>{
  const d=load(),s=d.shops.find(x=>x.id===q.params.id);
  if(!s)return r.sendStatus(404);
  s.plan=q.body.plan||s.plan||'standard';
  if(q.body.modules && typeof q.body.modules === 'object'){
    s.modules = {
      girvi: !!q.body.modules.girvi,
      barcode: !!q.body.modules.barcode,
      karigar: !!q.body.modules.karigar,
      gst: !!q.body.modules.gst
    };
  }
  save(d);r.json({ok:1,plan:s.plan,modules:s.modules})});
app.post('/api/admin/shops/:id/logo',(q,r)=>{
  const d=load(),s=d.shops.find(x=>x.id===q.params.id);
  if(!s)return r.sendStatus(404);
  s.logo=q.body.logo||null;
  save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/extend',(q,r)=>{const d=load(),s=d.shops.find(x=>x.id===q.params.id);if(!s)return r.sendStatus(404);
  s.isTrial=false;s.trialDays=null;
  s.paidUntil=Math.max(s.paidUntil,Date.now())+(Number(q.body.months)||1)*30*DAY;save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/recovery-key',(q,r)=>{const d=load(),s=d.shops.find(x=>x.id===q.params.id);if(!s)return r.sendStatus(404);s.recoveryKey=String(q.body.recoveryKey||'').trim().toUpperCase()||null;save(d);r.json({ok:1})});
app.post('/api/admin/shops/:id/:act',(q,r)=>{const d=load(),s=d.shops.find(x=>x.id===q.params.id);if(!s)return r.sendStatus(404);
  const a=q.params.act;if(a==='suspend')s.status='suspended';else if(a==='resume')s.status='active';else if(a==='reset'){s.deviceId=null;s.migrationAllowed=true;}else return r.sendStatus(400);save(d);r.json({ok:1})});
app.delete('/api/admin/shops/:id',(q,r)=>{const d=load();d.shops=d.shops.filter(x=>x.id!==q.params.id);save(d);r.json({ok:1})});

// Announcement / In-App Broadcast endpoints
app.get('/api/admin/announcement',(q,r)=>{const d=load();r.json(d.announcement||{active:false,text:'',type:'info'})});
app.post('/api/admin/announcement',(q,r)=>{const d=load();d.announcement={active:!!q.body.active,text:String(q.body.text||'').trim(),type:q.body.type||'info',updatedAt:Date.now()};save(d);r.json({ok:1,announcement:d.announcement})});

// Admin Pricing & Payment UPI Settings
app.get('/api/admin/settings',(q,r)=>{const d=load();r.json(d.adminSettings||{upiId:'sone-sathi@upi',upiName:'Sone Sathi Software',monthlyFee:999,quarterlyFee:2499,yearlyFee:7999})});
app.post('/api/admin/settings',(q,r)=>{const d=load();d.adminSettings={upiId:String(q.body.upiId||'').trim(),upiName:String(q.body.upiName||'').trim(),monthlyFee:Number(q.body.monthlyFee)||999,quarterlyFee:Number(q.body.quarterlyFee)||2499,yearlyFee:Number(q.body.yearlyFee)||7999};save(d);r.json({ok:1,settings:d.adminSettings})});

// Remote App Release & Update management
app.get('/api/admin/app-update',(q,r)=>{const d=load();r.json(d.appUpdate||{version:'1.0.0',downloadUrl:'',notes:'Official Stable Release',mandatory:false})});
app.post('/api/admin/app-update',(q,r)=>{const d=load();d.appUpdate={version:String(q.body.version||'1.0.0').trim(),downloadUrl:String(q.body.downloadUrl||'').trim(),notes:String(q.body.notes||'').trim(),mandatory:!!q.body.mandatory,releaseDate:Date.now()};save(d);r.json({ok:1,appUpdate:d.appUpdate})});

// Database Health & Storage status
app.get('/api/admin/db-status',(q,r)=>{
  r.json({
    isMongo: !!mongoDb,
    uriConfigured: !!MONGODB_URI,
    storageType: mongoDb ? 'MongoDB Atlas (Permanent Cloud)' : 'Local JSON Disk'
  });
});

// Hostinger & Offline Data Migration Exports
app.get('/api/admin/keys',(q,r)=>r.json(keys));
app.get('/api/admin/export-data-json',(q,r)=>{
  const d=load();
  const payload={
    shops:(d.shops||[]).map(s=>{const {bk,...rest}=s;return rest;}),
    announcement:d.announcement||{active:false,text:'',type:'info'},
    adminSettings:d.adminSettings||{upiId:'sone-sathi@upi',upiName:'Sone Sathi Software',monthlyFee:999,quarterlyFee:2499,yearlyFee:7999}
  };
  r.set('Content-Type','application/json')
   .set('Content-Disposition','attachment; filename="data.json"')
   .send(JSON.stringify(payload,null,2));
});
app.get('/api/admin/export-keys-json',(q,r)=>{
  r.set('Content-Type','application/json')
   .set('Content-Disposition','attachment; filename="keys.json"')
   .send(JSON.stringify(keys,null,2));
});

app.listen(PORT,()=>console.log('Server chal raha: http://localhost:'+PORT+'/admin  (password: '+(process.env.ADMIN_PASSWORD?'set':'admin123 - badal do!')+')'));
