"""Compose admitted GUI build payloads; execute no package code."""
import hashlib,io,json,pathlib,tarfile
import sys
if len(sys.argv)!=3:raise SystemExit('Usage: compose-gui-overlay.py REVIEW_DIRECTORY OUTPUT_DIRECTORY')
root=pathlib.Path(sys.argv[1]).resolve();review=root/'gui-input-review';output=pathlib.Path(sys.argv[2]);output.mkdir(mode=0o700,exist_ok=False)
pins=json.loads(pathlib.Path(__file__).with_name('gui-overlay-inputs.json').read_text())
for name,pin in pins.items():
    p=root/name
    if p.is_symlink() or not p.is_file() or p.stat().st_size!=pin['bytes']:raise SystemExit('Refused GUI input type/size: '+name)
    with p.open('rb') as source:observed=hashlib.file_digest(source,'sha256').hexdigest()
    if observed!=pin['sha256']:raise SystemExit('Refused GUI input digest: '+name)

admission=json.loads((review/'admission.json').read_text());assert admission['decision']=='admitted_for_data_overlay_construction_fixed_native_link_probe_and_offline_reviewed_repository_gate_only'
rows=json.loads((review/'archive-review.json').read_text());entries={};blobs={};controls={};package_files={}

def add(name,data=b'',kind='file',mode=0o644,link=''):
 path=pathlib.PurePosixPath(name);name=str(path)
 if name=='.':return
 assert not path.is_absolute() and '..' not in path.parts and len(name)<=4096
 assert path.parts[0] in ['usr','etc','var'],name
 assert kind in ['file','directory','symlink','hardlink'] and not mode&0o6000
 item={'kind':kind,'mode':mode,'bytes':len(data) if kind=='file' else 0,'link':link}
 if kind=='file':item['sha256']=hashlib.sha256(data).hexdigest()
 if name in entries:assert entries[name]==item and blobs[name]==data,(name,'conflicting payload');return
 entries[name]=item;blobs[name]=data

def ar(data):
 assert data.startswith(b'!<arch>\n');offset=8;parts={}
 while offset<len(data):
  h=data[offset:offset+60];size=int(h[48:58]);name=h[:16].decode().strip().removesuffix('/');offset+=60;parts[name]=data[offset:offset+size];offset+=size+size%2
 return parts

def fields(text):
 result={};key=None
 for line in text.splitlines():
  if line.startswith(' ') and key:result[key]+='\n'+line
  elif ': ' in line:key,value=line.split(': ',1);result[key]=value
 return result

for package,row in sorted(rows.items()):
 data=(review/row['filename']).read_bytes();assert hashlib.sha256(data).hexdigest()==admission['packages'][package]['SHA256'];package_files[package]=[]
 for part,body in ar(data).items():
  if not part.startswith(('data.tar.','control.tar.')):continue
  with tarfile.open(fileobj=io.BytesIO(body),mode='r:*') as archive:
   for member in archive:
    name=str(pathlib.PurePosixPath(member.name))
    if name=='.':continue
    payload=archive.extractfile(member).read(member.size+1) if member.isfile() else b''
    if member.isfile():assert len(payload)==member.size
    if part.startswith('control.'):
     if member.isfile():controls[(package,name)]=payload
     continue
    item=row['inventory'][part+'/'+name]
    if member.isfile():assert hashlib.sha256(payload).hexdigest()==item['sha256']
    add(name,payload,item['kind'],item['mode'],item['link']);package_files[package].append('/'+name)

with tarfile.open(root/'patched-input-review/construction-v1/overlay.tar') as archive:
 status=archive.extractfile('var/lib/dpkg/status').read().decode()
configured={row['Package']:row for row in map(fields,status.strip().split('\n\n'))}
for package,row in sorted(rows.items()):
 metadata=fields(controls[(package,'control')].decode());metadata['Status']='install ok unpacked';configured[package]=metadata
 prefix='var/lib/dpkg/info/'+package+(':'+metadata['Architecture'] if metadata.get('Multi-Arch')=='same' else '')
 add(prefix+'.list',('/.\n'+'\n'.join(sorted(package_files[package]))+'\n').encode())
 for field in ['md5sums','shlibs','symbols','triggers','conffiles']:
  if (package,field) in controls:add(prefix+'.'+field,controls[(package,field)])
encoded='\n\n'.join('\n'.join(key+': '+value for key,value in row.items()) for _,row in sorted(configured.items()))+'\n\n';add('var/lib/dpkg/status',encoded.encode())
embedded={**admission};embedded['remaining_advisories']=[{k:v for k,v in row.items() if k!='description'} for row in admission['remaining_advisories']]
add('usr/local/share/gbplus-linux-image/gui-inputs.json',(json.dumps(embedded,indent=2)+'\n').encode())
with tarfile.open(output/'overlay.tar','w',format=tarfile.PAX_FORMAT) as archive:
 for name,item in sorted(entries.items()):
  h=tarfile.TarInfo(name);h.uid=h.gid=0;h.uname=h.gname='root';h.mtime=0;h.mode=item['mode'];h.linkname=item['link'];h.size=item['bytes'];h.type={'file':tarfile.REGTYPE,'directory':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE}[item['kind']]
  archive.addfile(h,io.BytesIO(blobs[name]) if item['kind']=='file' else None)
with tarfile.open(output/'overlay.tar') as archive:
 observed={}
 for member in archive:
  item=entries[member.name];assert member.uid==member.gid==0 and member.mode==item['mode'] and member.size==item['bytes']
  if member.isfile():assert hashlib.sha256(archive.extractfile(member).read()).hexdigest()==item['sha256']
  else:assert member.linkname==item['link']
  observed[member.name]=True
assert set(observed)==set(entries)
digest=hashlib.sha256((output/'overlay.tar').read_bytes()).hexdigest();assert digest=='022d5d2bb002557005a9a98d248dc1dbda9d08569b5567c9a0f110a913d344c6';(output/'manifest.json').write_text(json.dumps({'sha256':digest,'bytes':(output/'overlay.tar').stat().st_size,'entries':entries,'admission_sha256':hashlib.sha256((review/'admission.json').read_bytes()).hexdigest()},indent=2)+'\n')
(output/'Dockerfile').write_text('FROM '+admission['base_image']+'\nADD overlay.tar /\nLABEL org.gbplus.gui-overlay-sha256="'+digest+'"\n')
(output/'.dockerignore').write_text('*\n!Dockerfile\n!overlay.tar\n')
print(json.dumps({'entries':len(entries),'overlay_bytes':(output/'overlay.tar').stat().st_size,'overlay_sha256':digest,'package_scripts_executed':False,'image_built':False}),flush=True)
