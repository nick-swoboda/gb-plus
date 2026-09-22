"""Compose the admitted data overlay; no package or installer is executed.

Usage: python3 scripts/linux-image/compose-overlay.py REVIEW_DIRECTORY OUTPUT_DIRECTORY
All metadata and archive inputs are fixed by overlay-inputs.json. Output is
accepted only when it matches the reviewed overlay digest and length.
"""
import hashlib,io,json,pathlib,sys,tarfile
if len(sys.argv)!=3:raise SystemExit(__doc__)
root=pathlib.Path(sys.argv[1]).resolve();review=root/'patched-input-review'
output=pathlib.Path(sys.argv[2]);output.mkdir(mode=0o700,exist_ok=False)
pins=json.loads(pathlib.Path(__file__).with_name('overlay-inputs.json').read_text())
for name,pin in pins.items():
    path=root/name
    if path.is_symlink() or not path.is_file() or path.stat().st_size!=pin['bytes']:
        raise SystemExit('Refused input type or length: '+name)
    with path.open('rb') as source:observed=hashlib.file_digest(source,'sha256').hexdigest()
    if observed!=pin['sha256']:raise SystemExit('Refused input digest: '+name)
base=json.loads((root/'filesystem-inventory.json').read_text())
meta=json.loads((review/'base-package-metadata.json').read_text())
acquired=json.loads((review/'acquired-inputs.json').read_text())
changes=json.loads((review/'package-path-changes.json').read_text())
assert all(not entry['removed_non_directories'] for entry in changes.values())
blobs={};headers={};controls={};package_entries={}

def add(name,data,kind='file',mode=0o644,target=''):
    name=name.removeprefix('./');path=pathlib.PurePosixPath(name)
    if name in ('','.'):
        return
    assert not path.is_absolute() and '..' not in path.parts and len(name)<=4096
    assert name.startswith(('usr/','etc/','var/','bin/','sbin/','lib/')) or name in ('usr','etc','var')
    header={'kind':kind,'mode':mode&~0o6000,'target':target,'bytes':len(data)}
    if kind in ('symlink','hardlink'):
        assert target and len(target)<=4096
    if name in headers and kind!='dir':assert headers[name]==header and blobs[name]==data,(name,'conflicting overlays')
    headers[name]=header;blobs[name]=data

def ar(data):
    assert data[:8]==b'!<arch>\n';offset=8;members={}
    while offset<len(data):
        header=data[offset:offset+60];size=int(header[48:58]);name=header[:16].decode().strip().removesuffix('/');offset+=60
        members[name]=data[offset:offset+size];offset+=size+(size%2)
    return members

def fields(text):
    row={};key=None
    for line in text.splitlines():
        if line.startswith(' ') and key:row[key]+='\n'+line
        elif ': ' in line:key,value=line.split(': ',1);row[key]=value
    return row

toolchain='usr/local/rustup/toolchains/1.97.1-aarch64-unknown-linux-gnu/'
for item in acquired:
    data=(review/item['filename']).read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256']
    if item['kind']=='deb':
        parts=ar(data);package_entries[item['name']]=[]
        for part,body in parts.items():
            if not part.endswith(('.xz','.gz')):continue
            with tarfile.open(fileobj=io.BytesIO(body),mode='r:*') as archive:
                for member in archive:
                    name=member.name.removeprefix('./')
                    if name in ('','.'):continue
                    if part.startswith('control.'):
                        if member.isfile():
                            content=archive.extractfile(member).read();controls[(item['name'],name)]=content
                        continue
                    package_entries[item['name']].append('/'+name)
                    kind='file' if member.isfile() else 'dir' if member.isdir() else 'symlink' if member.issym() else 'hardlink'
                    content=archive.extractfile(member).read() if member.isfile() else b''
                    add(name,content,kind,member.mode,member.linkname)
    else:
        package=item['name'];prefix=item['filename'].removesuffix('.tar.xz')+'/'+package+'/'
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
            selected=[]
            for member in archive:
                name=member.name.removeprefix('./')
                if name.startswith(prefix) and member.isfile() and not name.endswith('/manifest.in'):
                    relative=name[len(prefix):]
                    assert relative.startswith(('bin/','share/doc/'))
                    content=archive.extractfile(member).read();add(toolchain+relative,content,mode=0o755 if relative.startswith('bin/') else 0o644)
                    selected.append(relative)
            assert len(selected)==5,(package,selected)

# Normalize inherited set-ID programs using original, hash-verified file bytes.
required={name for name,value in base.items() if value['kind']=='file' and value['mode']&0o6000 and name not in headers}
inherited={}
for layer_name in sorted(name for name in pins if name.endswith('.tar.gz')):
    layer = root / layer_name
    with tarfile.open(layer,'r:gz') as archive:
        for member in archive:
            name=member.name.removeprefix('./')
            if name in required:
                assert member.isfile();inherited[name]=archive.extractfile(member).read()
assert set(inherited)==required
for name,data in inherited.items():
    assert hashlib.sha256(data).hexdigest()==base[name]['sha256'];add(name,data,mode=base[name]['mode'])

# Package payload state is explicitly unpacked: maintainer scripts did not run.
# The original configured database is preserved for provenance in this image.
status=meta['texts']['var/lib/dpkg/status'];rows=[fields(block) for block in status.strip().split('\n\n')]
for row in rows:
    name=row['Package']
    if (name,'control') not in controls:continue
    replacement=fields(controls[(name,'control')].decode())
    replacement['Status']='install ok unpacked'
    row.clear();row.update(replacement)
    prefix=meta['prefixes'][name]
    add(prefix+'.list',('/.\n'+'\n'.join(sorted(set(package_entries[name])))+'\n').encode())
    for field in ('md5sums','shlibs','symbols','triggers','conffiles'):
        if (name,field) in controls:add(prefix+'.'+field,controls[(name,field)])
add('usr/local/share/gbplus-linux-image/base-dpkg-status',status.encode())
encoded='\n\n'.join('\n'.join(key+': '+value for key,value in row.items()) for row in rows)+'\n\n'
add('var/lib/dpkg/status',encoded.encode())
manifest={'base_arm64_manifest':'3928ba262c79a46d18a4d1c125b24c089963ba1e1d6b203bd3bc169924e71f04','input_archives':acquired,'installation_scripts_executed':False,'package_state':'payload-only, unpacked; original configured metadata retained','toolchain_commands':'direct native 1.97.1 bin PATH; no rustup installation or registration','development_only':True,'admission_status':'remaining advisories and construction validation pending'}
add('usr/local/share/gbplus-linux-image/inputs.json',(json.dumps(manifest,indent=2)+'\n').encode())
for name,header in headers.items():
    if header['kind']=='file':header['sha256']=hashlib.sha256(blobs[name]).hexdigest()
with tarfile.open(output/'overlay.tar.incomplete','w',format=tarfile.PAX_FORMAT) as archive:
    for name in sorted(headers):
        h=headers[name];member=tarfile.TarInfo(name);member.uid=member.gid=0;member.uname=member.gname='root';member.mode=h['mode'];member.mtime=0
        member.type={'file':tarfile.REGTYPE,'dir':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE}[h['kind']]
        member.linkname=h['target'];member.size=h['bytes'] if h['kind']=='file' else 0
        archive.addfile(member,io.BytesIO(blobs[name]) if member.isfile() else None)
with (output/'overlay.tar.incomplete').open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
if digest!='b805c63b0ed41d194b531697b1ef969888b76f04837f830e4f7e4c121eef014b' or (output/'overlay.tar.incomplete').stat().st_size!=52572160:
    raise SystemExit('Refused: composed overlay differs from its admission.')
(output/'overlay.tar.incomplete').rename(output/'overlay.tar')
(output/'manifest.json').write_text(json.dumps({'overlay_sha256':digest,'overlay_bytes':(output/'overlay.tar').stat().st_size,'entries':headers,'image_built_or_loaded':False,'admitted':False},indent=2)+'\n')
print(json.dumps({'entries':len(headers),'overlay_bytes':(output/'overlay.tar').stat().st_size,'sha256':digest,'image_built_or_loaded':False,'admitted':False}))
