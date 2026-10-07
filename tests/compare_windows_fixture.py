#!/usr/bin/env python3
"""Compare an offline Rust capture with an independently recorded Windows fixture."""
import argparse
import json
import re
import struct
from pathlib import Path

ALIASES = {'BA':'S-1-5-32-544','SY':'S-1-5-18','BU':'S-1-5-32-545','AU':'S-1-5-11','WD':'S-1-1-0','LW':'S-1-16-4096'}
RIGHTS = {'FA':0x1f01ff,'FR':0x120089,'FW':0x120116,'FX':0x1200a0,'SD':0x10000,'RC':0x20000,'WD':0x40000,'WO':0x80000,'GA':0x10000000,'GX':0x20000000,'GW':0x40000000,'GR':0x80000000,'NW':1,'NR':2,'NX':4}
ACE_FLAGS = {'OI':1,'CI':2,'NP':4,'IO':8,'ID':16,'SA':64,'FA':128}

def tokens(text, table):
    if text.startswith('0x'):
        return int(text, 16)
    value=0
    for i in range(0,len(text),2):
        value |= table[text[i:i+2]]
    return value

def sddl(value):
    sections={}
    matches=list(re.finditer(r'([OGDS]):',value))
    for index,match in enumerate(matches):
        body=value[match.end():matches[index+1].start() if index+1<len(matches) else len(value)]
        name=match.group(1)
        if name in 'OG':
            sections[name]=ALIASES.get(body,body)
            continue
        flags=body.split('(',1)[0]
        aces=[]
        for ace in re.findall(r'\(([^)]*)\)',body):
            kind,flags_text,rights,object_id,inherited_id,sid=ace.split(';')
            if object_id or inherited_id:
                raise ValueError('fixture comparator does not support object ACEs')
            aces.append([kind,tokens(flags_text,ACE_FLAGS),tokens(rights,RIGHTS),ALIASES.get(sid,sid)])
        sections[name]={'flags':sorted(re.findall('AI|AR|P',flags)),'aces':aces}
    return sections

def security(hex_text):
    data=bytes.fromhex(hex_text)
    control=struct.unpack_from('<H',data,2)[0]
    def sid(offset):
        count=data[offset+1]
        authority=int.from_bytes(data[offset+2:offset+8],'big')
        sub=struct.unpack_from('<'+'I'*count,data,offset+8)
        return 'S-'+str(data[offset])+'-'+str(authority)+''.join('-'+str(n) for n in sub)
    result={}
    for name,field in [('O',4),('G',8)]:
        offset=struct.unpack_from('<I',data,field)[0]
        if offset:result[name]=sid(offset)
    for name,field,present,protected,inherited,required in [('D',16,4,0x1000,0x400,0x100),('S',12,16,0x2000,0x800,0x200)]:
        offset=struct.unpack_from('<I',data,field)[0]
        if not control&present or not offset:continue
        flags=[]
        for mask,label in [(protected,'P'),(inherited,'AI'),(required,'AR')]:
            if control&mask:flags.append(label)
        count=struct.unpack_from('<H',data,offset+4)[0]
        cursor=offset+8
        aces=[]
        for _ in range(count):
            kind,ace_flags,size=struct.unpack_from('<BBH',data,cursor)
            if ace_flags&~0xdf:raise ValueError('unknown fixture ACE flag')
            rights=struct.unpack_from('<I',data,cursor+4)[0]
            aces.append([{0:'A',1:'D',2:'AU',17:'ML'}[kind],ace_flags,rights,sid(cursor+8)])
            cursor+=size
        result[name]={'flags':sorted(flags),'aces':aces}
    return result

def normalize_path(path):
    return re.sub(r'\\+','/',path).strip('/')

def reparse(hex_text):
    if not hex_text:return {}
    data=bytes.fromhex(hex_text)
    tag=struct.unpack_from('<I',data)[0]
    if tag not in [0xa0000003,0xa000000c]:raise ValueError('unknown fixture reparse')
    start=20 if tag==0xa000000c else 16
    sub_offset,sub_size,print_offset,print_size=struct.unpack_from('<HHHH',data,8)
    result={'Tag':tag,'Sub':data[start+sub_offset:start+sub_offset+sub_size].decode('utf-16le'),'Print':data[start+print_offset:start+print_offset+print_size].decode('utf-16le'),'Flags':struct.unpack_from('<I',data,16)[0] if tag==0xa000000c else 0}
    for field in ['Sub','Print']:
        value=re.sub(r'\\+',lambda _: '\\',result[field])
        result[field]=re.sub(re.escape('C:\\NativeDiskCapture'),'<ROOT>',value,flags=re.IGNORECASE)
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--windows-metadata',type=Path,required=True)
    parser.add_argument('--windows-extra',type=Path,required=True)
    parser.add_argument('--offline-metadata',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    before=json.loads(json.loads(args.windows_metadata.read_text())['stdout'])
    extra=json.loads(json.loads(args.windows_extra.read_text())['stdout'])
    actual=json.loads(args.offline_metadata.read_text())
    expected={normalize_path(n['Path']):n for n in before}
    observed={normalize_path(n['Path']):n for n in actual['entries']}
    differences=[]
    for path in sorted(set(expected)|set(observed)):
        if path not in expected or path not in observed:
            differences.append({'path':path,'reason':'missing/extra entry'})
            continue
        a=expected[path];b=observed[path]
        for field in ['Attributes','Creation','Access','Write']:
            if a['Info'][field]!=b['Info'][field]:differences.append({'path':path,'field':field,'windows':a['Info'][field],'offline':b['Info'][field]})
        if a['Info']['Identity'].split(':')[1]!=b['Info']['Identity']:differences.append({'path':path,'field':'Identity'})
        if a['Short']!=b['Short']:differences.append({'path':path,'field':'Short','windows':a['Short'],'offline':b['Short']})
        if sddl(a['Security'])!=security(b['SecurityRaw']):differences.append({'path':path,'field':'Security','windows':sddl(a['Security']),'offline':security(b['SecurityRaw'])})
        left={s['Name']:(s['Length'],s['Hash'].replace('-','').lower()) for s in a['Streams']}
        right={s['Name']:(s['Length'],s['Hash'].lower()) for s in b['Streams']}
        if left!=right:differences.append({'path':path,'field':'Streams','windows':left,'offline':right})
        r=dict(a['Reparse'])
        for field in ['Sub','Print']:
            if field in r:r[field]=re.sub(r'\\+',lambda _: '\\',r[field])
        if r!=reparse(b['ReparseRaw']):differences.append({'path':path,'field':'Reparse','windows':r,'offline':reparse(b['ReparseRaw'])})
    for node in extra:
        if node['Name'] not in observed:continue
        target=observed[node['Name']]
        for old,new in [('EA','EaRaw'),('ObjectID','ObjectIdRaw')]:
            if isinstance(node[old],str) and node[old].replace('-','').lower()!=target[new]:differences.append({'path':node['Name'],'field':old,'windows':node[old],'offline':target[new]})
    result={'passes':not differences,'windows_entries':len(expected),'offline_entries':len(observed),'streams_compared':sum(len(n['Streams']) for n in observed.values()),'metadata_policy':'Exact attrs, three times, NTFS references, short names, stream sizes/SHA256, EA/object IDs; security SID/mask/ACE/control semantics and normalized reparse target strings. Raw security and reparse bytes retained separately.','differences':differences}
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['passes'] else 1
if __name__=='__main__':raise SystemExit(main())
