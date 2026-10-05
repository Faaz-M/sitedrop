'use strict';
// SiteDrop server: zero dependencies, needs Node.js 22.5 or newer.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const E=process.env;
const C={port:+E.PORT||3000,pass:E.ADMIN_PASSWORD||'',secret:E.SECRET||crypto.randomBytes(24).toString('hex'),
 name:E.BIZ_NAME||'SiteDrop',legal:E.BIZ_LEGAL_NAME||'Your Legal Business Name',gstin:E.BIZ_GSTIN||'',addr:E.BIZ_ADDRESS||'Bengaluru, Karnataka',
 phone:E.BIZ_PHONE||'',email:E.BIZ_EMAIL||'',wa:(E.BIZ_WHATSAPP||'').replace(/\D/g,''),site:(E.SITE_URL||'').replace(/\/$/,''),
 fee:+E.DELIVERY_FEE||49,free:+E.FREE_DELIVERY_ABOVE||500,pinA:+E.PIN_FROM||560001,pinB:+E.PIN_TO||560105,gst:+E.GST_RATE||18,
 rzKey:E.RAZORPAY_KEY_ID||'',rzSec:E.RAZORPAY_KEY_SECRET||'',hook:E.NOTIFY_WEBHOOK||'',rzWh:E.RAZORPAY_WEBHOOK_SECRET||'',sms:E.SMS_PROVIDER||'',twSid:E.TWILIO_SID||'',twTok:E.TWILIO_TOKEN||'',twFrom:E.TWILIO_FROM||'',smsHook:E.SMS_WEBHOOK||'',reqLogin:E.REQUIRE_LOGIN==='1',proxy:E.TRUST_PROXY==='1'};
if(C.pass.length<8){console.error('Set ADMIN_PASSWORD (8+ characters) first. See README.md.');process.exit(1)}
fs.mkdirSync('data',{recursive:true});
const db=new DatabaseSync('data/shop.db');
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,brand TEXT,name TEXT,weight INT DEFAULT 0,price INT,t15 INT,t45 INT,stock INT,category TEXT,color TEXT DEFAULT '#1F6FB2',hsn TEXT DEFAULT '3214',active INT DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,name TEXT,phone TEXT,addr TEXT,pin TEXT,gstin TEXT,items TEXT,sub INT,fee INT,tot INT,status TEXT,pay TEXT,paid INT DEFAULT 0,rz TEXT,created INT);`);
db.exec('CREATE TABLE IF NOT EXISTS otps(phone TEXT PRIMARY KEY,hash TEXT,exp INT,tries INT DEFAULT 0)');
try{db.exec('ALTER TABLE products ADD COLUMN img TEXT')}catch{}
fs.mkdirSync('data/uploads',{recursive:true});
if(!db.prepare('SELECT COUNT(*) n FROM products').get().n){
 const S=[['Roff','T01 NCA Tile Adhesive',30,430,'Adhesive','#C0392B',420,410],['MYK Laticrete','303 Tile Adhesive',20,255,'Adhesive','#1F6FB2'],['MYK Laticrete','305 Tile Adhesive',30,420,'Adhesive','#1F6FB2'],['MYK Laticrete','335 Super Flex',20,1360,'Adhesive','#16507F'],['Birla White','TX1 Tile Adhesive',20,299,'Adhesive','#5C6B7A'],['Roff','T02 NSA Tile Adhesive',30,740,'Adhesive','#A93226'],['Roff','T09 NSA White',20,615,'Adhesive','#8E3B33'],['Asian Paints','SmartCare Tile Adhesive',30,370,'Adhesive','#B9531F'],['MYK Laticrete','SP-100 Epoxy Grout',0,610,'Grout','#2E7D6B']];
 const ins=db.prepare('INSERT INTO products(brand,name,weight,price,category,color,t15,t45,stock) VALUES(?,?,?,?,?,?,?,?,100)');
 for(const s of S)ins.run(s[0],s[1],s[2],s[3],s[4],s[5],s[6]||Math.round(s[3]*.98),s[7]||Math.round(s[3]*.96));
}
class Err extends Error{}
const unit=(p,q)=>q>=45?p.t45:q>=15?p.t15:p.price;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const str=(v,n)=>String(v??'').trim().slice(0,n);
const inr=n=>'₹'+Number(n).toLocaleString('en-IN',{maximumFractionDigits:2});
const pub=p=>({id:p.id,b:p.brand,n:p.name,w:p.weight,p:p.price,t:[p.t15,p.t45],c:p.category,k:p.color,s:p.stock,i:p.img||''});
const send=(res,code,body,type='application/json')=>{res.writeHead(code,{'Content-Type':type+'; charset=utf-8','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY'});res.end(type==='application/json'?JSON.stringify(body):body)};
const json=(res,code,o)=>send(res,code,o);
const readBody=req=>new Promise((ok,no)=>{let d='';req.on('data',c=>{d+=c;if(d.length>1e5){no(new Err('Request too large'));req.destroy()}});req.on('end',()=>{try{ok(d?JSON.parse(d):{})}catch{no(new Err('Bad JSON'))}})});
const hmac=s=>crypto.createHmac('sha256',C.secret).update(s).digest('hex');
const same=(a,b)=>{const x=crypto.createHash('sha256').update(String(a)).digest(),y=crypto.createHash('sha256').update(String(b)).digest();return crypto.timingSafeEqual(x,y)};
const cookie=(req,k)=>((req.headers.cookie||'').split(/;\s*/).find(c=>c.startsWith(k+'='))||'').slice(k.length+1);
const isAdmin=req=>{const [exp,sig]=cookie(req,'adm').split('.');return !!sig&&+exp>Date.now()&&same(sig,hmac('adm'+exp))};
const ip=req=>C.proxy?String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress:req.socket.remoteAddress;
const readRaw=(req,max)=>new Promise((ok,no)=>{const c=[];let n=0;req.on('data',d=>{n+=d.length;if(n>max){no(new Err('File too large'));req.destroy();return}c.push(d)});req.on('end',()=>ok(Buffer.concat(c)))});
const custSet=(res,ph)=>{const exp=Date.now()+2592e6;res.setHeader('Set-Cookie',`cu=${ph}.${exp}.${hmac('cu'+ph+exp)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${C.site.startsWith('https')?'; Secure':''}`)};
const cust=req=>{const [ph,exp,sig]=cookie(req,'cu').split('.');return sig&&+exp>Date.now()&&same(sig,hmac('cu'+ph+exp))?ph:null};
async function sms(ph,text){
 if(C.sms==='twilio'){const r=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${C.twSid}/Messages.json`,{method:'POST',headers:{Authorization:'Basic '+Buffer.from(C.twSid+':'+C.twTok).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({To:'+91'+ph,From:C.twFrom,Body:text})});if(!r.ok)throw new Error('sms')}
 else if(C.smsHook){const r=await fetch(C.smsHook,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:'91'+ph,message:text})});if(!r.ok)throw new Error('sms')}
 else console.log(`[DEV MODE, no SMS provider set] code for ${ph}: ${text}`)}
const hits=new Map();
const limited=(key,max,ms)=>{const now=Date.now(),h=(hits.get(key)||[]).filter(t=>now-t<ms);h.push(now);hits.set(key,h);return h.length>max};
setInterval(()=>{const now=Date.now();for(const[k,v]of hits)if(!v.some(t=>now-t<36e5))hits.delete(k)},6e5).unref();

function markPaid(rz){let o;db.exec('BEGIN IMMEDIATE');try{
 o=db.prepare('SELECT * FROM orders WHERE rz=?').get(rz);
 if(o&&!o.paid){
  if(o.status==='Cancelled'){const L=JSON.parse(o.items);
   if(L.every(l=>{const p=db.prepare('SELECT stock FROM products WHERE id=?').get(l.id);return p&&(p.stock===null||p.stock>=l.q)})){
    for(const l of L)db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock IS NOT NULL').run(l.q,l.id);db.prepare("UPDATE orders SET status='New' WHERE id=?").run(o.id)}}
  db.prepare('UPDATE orders SET paid=1 WHERE id=?').run(o.id)}
 db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}
 if(o&&!o.paid)notify(db.prepare('SELECT * FROM orders WHERE id=?').get(o.id))}
function cancel(id){db.exec('BEGIN IMMEDIATE');try{
 const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);
 if(o&&o.status!=='Cancelled'){for(const l of JSON.parse(o.items))db.prepare('UPDATE products SET stock=stock+? WHERE id=? AND stock IS NOT NULL').run(l.q,l.id);
  db.prepare("UPDATE orders SET status='Cancelled' WHERE id=?").run(id)}
 db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}}
const notify=o=>{const text=`${o.status==='Cancelled'?'PAID BUT CANCELLED, REFUND NEEDED: ':''}New order ${o.id}: ${inr(o.tot)} (${o.pay==='online'?'paid online':'cash on delivery'}) from ${o.name}, ${o.phone}, ${o.addr} ${o.pin}`;
 console.log(text);if(C.hook)fetch(C.hook,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,order:o})}).catch(()=>{})};
setInterval(()=>{for(const o of db.prepare("SELECT id FROM orders WHERE pay='online' AND paid=0 AND status='New' AND created<?").all(Date.now()-18e5))cancel(o.id)},3e5).unref();
setInterval(()=>{try{fs.mkdirSync('backups',{recursive:true});db.exec('PRAGMA wal_checkpoint(TRUNCATE)');fs.copyFileSync('data/shop.db','backups/shop-'+new Date().toISOString().slice(0,10)+'.db');
 const f=fs.readdirSync('backups').sort();while(f.length>14)fs.unlinkSync('backups/'+f.shift())}catch(e){console.error('backup failed',e.message)}},864e5).unref();

async function placeOrder(req,res){
 if(limited('o'+ip(req),15,36e5))return json(res,429,{error:'Too many orders from this connection. Please call us.'});
 const b=await readBody(req),sess=cust(req);
 if(!sess)return json(res,401,{error:'Please verify your mobile number with OTP before placing the order.'});
 const name=str(b.name,80),phone=str(sess,10),addr=str(b.addr,200),pin=+b.pin,gstin=str(b.gstin,15).toUpperCase(),pay=b.pay==='online'&&C.rzKey?'online':'cod';
 if(!name||!/^[6-9]\d{9}$/.test(phone)||addr.length<8)return json(res,400,{error:'Please check your name, 10-digit mobile number and address.'});
 if(!(pin>=C.pinA&&pin<=C.pinB))return json(res,400,{error:`We deliver only to pincodes ${C.pinA} to ${C.pinB}.`});
 if(gstin&&!/^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(gstin))return json(res,400,{error:'The GSTIN looks invalid.'});
 const items=Array.isArray(b.items)?b.items.slice(0,30):[];
 if(!items.length)return json(res,400,{error:'Your cart is empty.'});
 const id='SD'+Date.now().toString(36).toUpperCase()+crypto.randomInt(10,99);
 let o;db.exec('BEGIN IMMEDIATE');
 try{let sub=0;const lines=[];
  for(const it of items){const q=Math.floor(+it.q),p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(+it.id);
   if(!p||!(q>=1&&q<=500))throw new Err('An item in your cart is no longer available.');
   if(p.stock!==null&&p.stock<q)throw new Err(p.stock?`Only ${p.stock} left of ${p.name}.`:`${p.name} is out of stock.`);
   if(p.stock!==null)db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(q,p.id);
   const u=unit(p,q);sub+=u*q;lines.push({id:p.id,n:p.brand+' '+p.name,q,u,hsn:p.hsn})}
  const fee=sub<C.free?C.fee:0;
  o={id,name,phone,addr,pin:String(pin),gstin,items:JSON.stringify(lines),sub,fee,tot:sub+fee,status:'New',pay,paid:0,rz:'',created:Date.now()};
  db.prepare('INSERT INTO orders VALUES(:id,:name,:phone,:addr,:pin,:gstin,:items,:sub,:fee,:tot,:status,:pay,:paid,:rz,:created)').run(o);
  db.exec('COMMIT');
 }catch(e){db.exec('ROLLBACK');if(e instanceof Err)return json(res,409,{error:e.message});throw e}
 if(pay==='online'){
  try{const r=await fetch('https://api.razorpay.com/v1/orders',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Basic '+Buffer.from(C.rzKey+':'+C.rzSec).toString('base64')},body:JSON.stringify({amount:o.tot*100,currency:'INR',receipt:id})});
   const d=await r.json();if(!d.id)throw new Error('rz');
   db.prepare('UPDATE orders SET rz=? WHERE id=?').run(d.id,id);
   return json(res,200,{id,tot:o.tot,rz:{key:C.rzKey,orderId:d.id,amount:o.tot*100}})
  }catch{cancel(id);return json(res,502,{error:'Online payment is unavailable right now. Please choose pay on delivery.'})}}
 notify(o);json(res,200,{id,tot:o.tot});
}
async function verifyPay(req,res){
 const b=await readBody(req),o=db.prepare('SELECT * FROM orders WHERE id=?').get(str(b.id,30));
 if(!o||!o.rz||o.rz!==b.razorpay_order_id)return json(res,400,{error:'Unknown order'});
 const sig=crypto.createHmac('sha256',C.rzSec).update(o.rz+'|'+b.razorpay_payment_id).digest('hex');
 if(!same(sig,b.razorpay_signature))return json(res,400,{error:'Bad signature'});
 markPaid(o.rz);json(res,200,{ok:true});
}
const STATUS=['New','Packed','Out for delivery','Delivered','Cancelled'];
async function admin(req,res,u){
 if(u.pathname==='/api/admin/login'&&req.method==='POST'){
  if(limited('l'+ip(req),6,9e5))return json(res,429,{error:'Too many attempts. Wait 15 minutes.'});
  const b=await readBody(req);if(!same(b.password||'',C.pass))return json(res,401,{error:'Wrong password'});
  const exp=Date.now()+288e5;res.setHeader('Set-Cookie',`adm=${exp}.${hmac('adm'+exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${C.site.startsWith('https')?'; Secure':''}`);return json(res,200,{ok:true})}
 if(u.pathname==='/api/admin/logout'&&req.method==='POST'){
  res.setHeader('Set-Cookie','adm=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true})
 }
 if(!isAdmin(req))return json(res,401,{error:'Login required'});
 if(u.pathname==='/api/admin/upload'&&req.method==='POST'){const buf=await readRaw(req,2e6);
  const ext=buf.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))?'png':buf.subarray(0,3).equals(Buffer.from([0xff,0xd8,0xff]))?'jpg':(buf.subarray(0,4).toString()==='RIFF'&&buf.subarray(8,12).toString()==='WEBP')?'webp':null;
  if(!ext)return json(res,400,{error:'Use a PNG, JPG or WebP image under 2 MB.'});
  const nm=crypto.randomBytes(8).toString('hex')+'.'+ext;fs.writeFileSync('data/uploads/'+nm,buf);return json(res,200,{url:'/uploads/'+nm})}
 const m=u.pathname.match(/^\/api\/admin\/(orders|products)(?:\/(\w+))?$/);if(!m)return json(res,404,{error:'Not found'});
 const [,what,id]=m;
 if(what==='orders'){
  if(req.method==='GET')return json(res,200,db.prepare('SELECT * FROM orders ORDER BY created DESC LIMIT 300').all().map(o=>({...o,items:JSON.parse(o.items)})));
  if(req.method==='PATCH'){const b=await readBody(req);if(!STATUS.includes(b.status))return json(res,400,{error:'Bad status'});
   if(b.status==='Cancelled')cancel(id);else db.prepare('UPDATE orders SET status=? WHERE id=?').run(b.status,id);
   if(b.status==='Delivered')db.prepare("UPDATE orders SET paid=1 WHERE id=? AND pay='cod'").run(id);return json(res,200,{ok:true})}}
 if(what==='products'){
  if(req.method==='GET')return json(res,200,db.prepare('SELECT * FROM products WHERE active=1 ORDER BY id').all());
  if(req.method==='DELETE'){db.prepare('UPDATE products SET active=0 WHERE id=?').run(+id);return json(res,200,{ok:true})}
  if(req.method==='POST'||req.method==='PUT'){const b=await readBody(req),n=k=>Math.max(0,Math.round(+b[k])||0);
   const v=[str(b.brand,60),str(b.name,100),n('weight'),n('price'),n('t15')||n('price'),n('t45')||n('price'),b.stock===''||b.stock==null?null:n('stock'),str(b.category,30)||'Adhesive',/^#[0-9a-f]{6}$/i.test(b.color)?b.color:'#1F6FB2',str(b.hsn,8)||'3214',/^\/uploads\/[a-f0-9]{16}\.(png|jpg|webp)$/.test(b.img||'')?b.img:null];
   if(!v[1]||!v[3])return json(res,400,{error:'Name and price are required'});
   if(req.method==='POST')db.prepare('INSERT INTO products(brand,name,weight,price,t15,t45,stock,category,color,hsn,img) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(...v);
   else db.prepare('UPDATE products SET brand=?,name=?,weight=?,price=?,t15=?,t45=?,stock=?,category=?,color=?,hsn=?,img=? WHERE id=?').run(...v,+id);
   return json(res,200,{ok:true})}}
 json(res,405,{error:'Method not allowed'});
}
const shell=(title,body,desc='')=>`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><meta name="description" content="${esc(desc||title)}"><style>body{font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:20px;color:#102A43}a{color:#1F6FB2}table{width:100%;border-collapse:collapse}td,th{padding:6px;border-bottom:1px solid #ccd;text-align:left}th:last-child,td:last-child{text-align:right}@media(prefers-color-scheme:dark){body{background:#0C1824;color:#EAF0F6}a{color:#8cc4ff}td,th{border-color:#24394F}}@media print{.np{display:none}}</style></head><body>${body}</body></html>`;
const contact=`${esc(C.legal)}, ${esc(C.addr)}${C.gstin?`. GSTIN ${esc(C.gstin)}`:''}${C.phone?`. Phone ${esc(C.phone)}`:''}${C.email?`. Email ${esc(C.email)}`:''}`;
const POL={terms:['Terms of Service',`<p>These terms apply to orders placed on ${esc(C.name)}, operated by ${contact}.</p><h2>Orders and prices</h2><p>Prices are in Indian rupees and include GST unless stated. We may cancel an order if an item is unavailable or the delivery address is outside our service area, and refund any payment received.</p><h2>Delivery</h2><p>See the Shipping Policy. Please inspect goods at delivery.</p><h2>Liability</h2><p>Products are sold as supplied by the manufacturer. Use them as directed on the packaging.</p>`],
 privacy:['Privacy Policy',`<p>${esc(C.name)} collects your name, phone number, address and order details only to process and deliver your order and to issue invoices. Payments are handled by our payment provider; we do not store card details. We do not sell your data. Data is retained as needed for tax and accounting law. To request correction or deletion, contact us: ${contact}.</p>`],
 refund:['Refund and Return Policy',`<p>Check the bags at delivery. If an item is damaged, expired or not what you ordered, tell us within 24 hours with photos and we will replace it or refund you. Sealed, undamaged, unused bags may be returned within 48 hours; return pickup may be charged. Refunds for online payments go to the original payment method. Contact: ${contact}.</p>`],
 shipping:['Shipping Policy',`<p>We deliver to Bengaluru pincodes ${C.pinA} to ${C.pinB}. Delivery is free for orders of ${inr(C.free)} or more; otherwise the fee is ${inr(C.fee)}. We aim to deliver within about 60 minutes of confirmation, subject to traffic and stock. Contact: ${contact}.</p>`]};
function invoice(o){
 const L=JSON.parse(o.items),g=C.gst,rows=L.map(l=>({...l,amt:l.u*l.q}));if(o.fee)rows.push({n:'Delivery charge',q:1,u:o.fee,amt:o.fee,hsn:'9965'});
 const tax=o.tot-o.tot/(1+g/100),inter=o.gstin&&!o.gstin.startsWith('29');
 return shell('Invoice '+o.id,`<p class="np"><button onclick="print()">Print or save as PDF</button></p><h1>Tax Invoice</h1><p><b>${esc(C.legal)}</b><br>${esc(C.addr)}${C.gstin?'<br>GSTIN: '+esc(C.gstin):''}</p><p>Invoice no: <b>${o.id}</b><br>Date: ${new Date(o.created).toLocaleDateString('en-IN')}<br>Bill to: ${esc(o.name)}, ${esc(o.phone)}<br>${esc(o.addr)} ${esc(o.pin)}${o.gstin?'<br>GSTIN: '+esc(o.gstin):''}</p><table><tr><th>Item</th><th>HSN</th><th>Qty</th><th>Rate</th><th>Amount</th></tr>${rows.map(r=>`<tr><td>${esc(r.n)}</td><td>${esc(r.hsn)}</td><td>${r.q}</td><td>${inr(r.u)}</td><td>${inr(r.amt)}</td></tr>`).join('')}</table><p>Taxable value: ${inr(o.tot-tax)}<br>${inter?`IGST ${g}%: ${inr(tax)}`:`CGST ${g/2}%: ${inr(tax/2)}<br>SGST ${g/2}%: ${inr(tax/2)}`}<br><b>Total (incl. GST): ${inr(o.tot)}</b><br>Payment: ${o.pay==='online'?'Paid online':'Cash/UPI on delivery'}</p>`)}
const MIME={'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.ico':'image/x-icon'};
http.createServer(async(req,res)=>{try{
 const u=new URL(req.url,'http://x'),p=u.pathname;
 if(p.startsWith('/api/admin/'))return await admin(req,res,u);
 if(p==='/api/config')return json(res,200,{name:C.name,fee:C.fee,free:C.free,a:C.pinA,b:C.pinB,online:!!C.rzKey,phone:C.phone,wa:C.wa,legal:C.legal,addr:C.addr,gstin:C.gstin});
 if(p==='/api/products')return json(res,200,db.prepare('SELECT * FROM products WHERE active=1 ORDER BY id').all().map(pub));
 if(p==='/api/order'&&req.method==='POST')return await placeOrder(req,res);
 if(p==='/api/pay/verify'&&req.method==='POST')return await verifyPay(req,res);
 if(p==='/api/track'){const o=db.prepare('SELECT status,pay,paid,tot FROM orders WHERE id=? AND phone=?').get(str(u.searchParams.get('id'),30),str(u.searchParams.get('phone'),10));return o?json(res,200,o):json(res,404,{error:'No order found for that order ID and phone number.'})}
 let m;
 if(p==='/api/otp/send'&&req.method==='POST'){const b=await readBody(req),ph=str(b.phone,10);
  if(!/^[6-9]\d{9}$/.test(ph))return json(res,400,{error:'Enter a valid 10-digit mobile number.'});
  if(limited('os'+ip(req),10,36e5)||limited('op'+ph,3,6e5))return json(res,429,{error:'Too many codes requested. Try again in a few minutes.'});
  const code=String(crypto.randomInt(100000,1e6));
  db.prepare('INSERT INTO otps VALUES(?,?,?,0) ON CONFLICT(phone) DO UPDATE SET hash=excluded.hash,exp=excluded.exp,tries=0').run(ph,hmac('otp'+ph+code),Date.now()+3e5);
  try{await sms(ph,`${code} is your ${C.name} login code. It is valid for 5 minutes.`)}catch{return json(res,502,{error:'Could not send the code. Please try again.'})}
  return json(res,200,{ok:true})}
 if(p==='/api/otp/verify'&&req.method==='POST'){const b=await readBody(req),ph=str(b.phone,10),o=db.prepare('SELECT * FROM otps WHERE phone=?').get(ph);
  if(!o||o.exp<Date.now()||o.tries>=5)return json(res,400,{error:'Code expired. Please request a new one.'});
  db.prepare('UPDATE otps SET tries=tries+1 WHERE phone=?').run(ph);
  if(!same(o.hash,hmac('otp'+ph+str(b.code,6))))return json(res,400,{error:'Wrong code.'});
  db.prepare('DELETE FROM otps WHERE phone=?').run(ph);custSet(res,ph);return json(res,200,{ok:true,phone:ph})}
 if(p==='/api/logout'){res.setHeader('Set-Cookie','cu=; Path=/; Max-Age=0');return json(res,200,{ok:true})}
 if(p==='/api/me'){const ph=cust(req);return json(res,200,ph?{phone:ph,orders:db.prepare('SELECT id,tot,status,pay,paid,created,items FROM orders WHERE phone=? ORDER BY created DESC LIMIT 30').all(ph).map(o=>({...o,items:JSON.parse(o.items)}))}:{})}
 if(p==='/api/pay/webhook'&&req.method==='POST'){const raw=(await readRaw(req,2e5)).toString();
  if(!C.rzWh||!same(crypto.createHmac('sha256',C.rzWh).update(raw).digest('hex'),req.headers['x-razorpay-signature']||''))return json(res,400,{error:'bad signature'});
  const ev=JSON.parse(raw),oid=ev.payload?.payment?.entity?.order_id||ev.payload?.order?.entity?.order_id;
  if(['payment.captured','order.paid'].includes(ev.event)&&oid)markPaid(oid);return json(res,200,{ok:true})}
 if(m=p.match(/^\/uploads\/([a-f0-9]{16}\.(png|jpg|webp))$/)){const f='data/uploads/'+m[1];
  if(fs.existsSync(f)){res.writeHead(200,{'Content-Type':'image/'+(m[2]==='jpg'?'jpeg':m[2]),'Cache-Control':'public, max-age=31536000, immutable','X-Content-Type-Options':'nosniff'});return fs.createReadStream(f).pipe(res)}}
 if(m=p.match(/^\/invoice\/(\w+)$/)){const o=db.prepare('SELECT * FROM orders WHERE id=?').get(m[1]);
  if(!o||!(isAdmin(req)||o.phone===u.searchParams.get('phone')))return send(res,404,shell('Not found','<p>Invoice not found.</p>'),'text/html');return send(res,200,invoice(o),'text/html')}
 if(m=p.match(/^\/p\/(\w+)$/)){const x=POL[m[1]];if(x)return send(res,200,shell(x[0]+' | '+C.name,`<p><a href="/">← ${esc(C.name)}</a></p><h1>${x[0]}</h1>${x[1]}`),'text/html')}
 if(m=p.match(/^\/product\/(\d+)$/)){const x=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(+m[1]);
  if(x){const t=`${x.brand} ${x.name}${x.weight?' '+x.weight+' kg':''}`,ld={'@context':'https://schema.org','@type':'Product',name:t,...(x.img?{image:C.site+x.img}:{}),brand:{'@type':'Brand',name:x.brand},offers:{'@type':'Offer',priceCurrency:'INR',price:x.price,availability:x.stock===0?'https://schema.org/OutOfStock':'https://schema.org/InStock'}};
   return send(res,200,shell(`${t} price in Bengaluru | ${C.name}`,`<p><a href="/">← ${esc(C.name)}</a></p><h1>${esc(t)}</h1><p>${inr(x.price)} per ${x.weight?'bag':'unit'}. Bulk: ${inr(x.t15)} for 15 or more, ${inr(x.t45)} for 45 or more. ${x.stock===0?'Currently out of stock.':'In stock.'} Delivery in about 60 minutes across Bengaluru. Pay on delivery available.</p><p><a href="/#shop"><b>Order now</b></a></p><script type="application/ld+json">${JSON.stringify(ld).replace(/</g,'\\u003c')}</script>`,`Buy ${t} online in Bengaluru. ${inr(x.price)}, bulk prices, 60-minute delivery, GST invoice.`),'text/html')}}
 if(p==='/robots.txt')return send(res,200,`User-agent: *\nDisallow: /api/\nDisallow: /admin.html\nSitemap: ${C.site}/sitemap.xml\n`,'text/plain');
 if(p==='/sitemap.xml'){const urls=['/',...Object.keys(POL).map(k=>'/p/'+k),...db.prepare('SELECT id FROM products WHERE active=1').all().map(x=>'/product/'+x.id)];
  return send(res,200,`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(x=>`<url><loc>${C.site}${x}</loc></url>`).join('')}</urlset>`,'application/xml')}
 const f=path.join(__dirname,'public',p==='/'?'index.html':p);
 if(!f.startsWith(path.join(__dirname,'public'))||!fs.existsSync(f)||fs.statSync(f).isDirectory())return send(res,404,shell('Not found','<p>Page not found. <a href="/">Home</a></p>'),'text/html');
 const ext=path.extname(f);res.writeHead(200,{'Content-Type':(MIME[ext]||'application/octet-stream')+(ext==='.html'?'; charset=utf-8':''),'Cache-Control':ext==='.html'?'no-cache':'public, max-age=86400','X-Content-Type-Options':'nosniff'});fs.createReadStream(f).pipe(res);
}catch(e){if(e instanceof Err)return json(res,400,{error:e.message});console.error(e);if(!res.headersSent)json(res,500,{error:'Something went wrong. Please try again.'})}}).listen(C.port,()=>console.log(`${C.name} running on http://localhost:${C.port}`));
