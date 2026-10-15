# SPDX-License-Identifier: GPL-3.0-only
from copy import deepcopy
import uuid
from unittest.mock import patch
import pytest
from armhpc_ota import boot_maintenance, deployment
from armhpc_ota.device import discover
from armhpc_ota.errors import OTAError
from armhpc_ota.io import atomic_json,read_json
from armhpc_ota.platform import bind_mbr_labels,storage_view
from test_oesp_boot_maintenance import OespBootMaintenance
from test_oesp_storage import disk


@pytest.fixture
def interrupted():
    fixture=OespBootMaintenance();fixture.setUp()
    try:
        board,parts,table=disk()
        original=read_json(fixture.r/'device.json')
        roles=('boot','rescue_a','rescue_b','shared')
        for number,(role,node) in enumerate(zip(roles,parts),1):
            node.update(type='part',fstype='vfat' if role=='boot' else 'ext4' if role=='shared' else 'squashfs',
                uuid='shared-uuid' if role=='shared' else None,label=board['labels'][role],
                mountpoints=[],fixture_role=role,**{'maj:min':f'179:{number}'})
        device={**original,'root':parts[1]['path'],'blocks':[
            {'path':'/dev/mmcblk1','type':'disk','size':8*1024**3,'log-sec':512,'tran':'mmc','serial':'fixture-emmc'},
            *parts,*[node for node in original['blocks'] if node.get('path','').startswith('/dev/sda')]]}
        atomic_json(fixture.r/'device.json',device)
        task_id=str(uuid.uuid4());task=boot_maintenance.apply(fixture.e,fixture.bundle,task_id)['task']
        task['stage']='deploying-rescue';boot_maintenance.save(fixture.c,task)
        deployment.begin(fixture.c,device,'rescue_b',parts[2],
            {'job_id':'boot-'+task_id,'release':task['release']})
        raw=deepcopy(device);raw['blocks'][3]['label']=None
        yield fixture,raw,table,task
    finally:fixture.tearDown()


def valid_active_slot(config):
    def read(path,capacity,trust):
        if path.endswith('p3'):raise OTAError('slot_uncommitted','Interrupted inactive trailer')
        return {'board':config.profile,'layout':config.board()['layout']},b'signed-active'
    return read


def test_admitted_partial_slot_remains_discoverable_without_reading_its_trailer(interrupted):
    fixture,raw,table,task=interrupted
    with patch('armhpc_ota.squashfs.read_trailer',side_effect=valid_active_slot(fixture.c)) as reader:
        blocks=storage_view(fixture.c,raw,lambda parent:table)['blocks']
    target=next(node for node in blocks if node['path']=='/dev/mmcblk1p3')
    assert target['label']==fixture.c.board()['labels']['rescue_b']
    assert target['_deployment_role']=='rescue_b'
    assert all(call.args[0]!='/dev/mmcblk1p3' for call in reader.call_args_list)


def test_unsigned_slot_without_admitted_intent_is_still_refused(interrupted):
    fixture,raw,table,task=interrupted
    deployment.complete(fixture.c,'rescue_b')
    with patch('armhpc_ota.squashfs.read_trailer',side_effect=valid_active_slot(fixture.c)):
        with pytest.raises(OTAError,match='Interrupted inactive'):bind_mbr_labels(fixture.c,raw['blocks'],lambda parent:table)


def test_completed_boot_rollback_retains_partial_target_identity(interrupted):
    fixture,raw,table,task=interrupted
    atomic_json(fixture.r/'device.json',raw)
    boot_maintenance.rollback(fixture.e,task['task_id'])
    assert boot_maintenance.record(fixture.c)['stage']=='rolled-back'
    entry=deployment.ledger(fixture.c)['targets'].get('rescue_b')
    assert entry,'Rollback must retain the physical identity of an interrupted inactive slot'
    logical=deployment.view(fixture.c,raw)
    target=next(node for node in logical['blocks'] if node['path']=='/dev/mmcblk1p3')
    assert target['_deployment_role']=='rescue_b'
    assert fixture.e.store.control()['confirmed']['rescue']['slot']=='a'


@pytest.mark.parametrize('change',['identity','guid','geometry','disk','active_root'])
def test_admission_refuses_changed_identity_or_target(interrupted,change):
    fixture,raw,table,task=interrupted
    if change=='identity':raw['device_id']='other-device'
    elif change=='guid':raw['blocks'][3]['partuuid']='eeeeffff-03'
    elif change=='geometry':raw['blocks'][3]['start']+=2048
    elif change=='disk':raw['blocks'][0]['serial']='replacement-emmc'
    else:raw['root']='/dev/mmcblk1p3'
    with patch('armhpc_ota.squashfs.read_trailer') as reader:
        with pytest.raises(OTAError):storage_view(fixture.c,raw,lambda parent:table)
        reader.assert_not_called()


def test_a_raw_private_marker_cannot_bypass_a_signature(interrupted):
    fixture,raw,table,task=interrupted
    deployment.complete(fixture.c,'rescue_b');raw['blocks'][3]['_deployment_role']='rescue_b'
    with patch('armhpc_ota.squashfs.read_trailer',side_effect=valid_active_slot(fixture.c)):
        with pytest.raises(OTAError):storage_view(fixture.c,raw,lambda parent:table)


def test_rollback_history_survives_a_new_task_and_detects_tampering(interrupted):
    fixture,raw,table,task=interrupted
    atomic_json(fixture.r/'device.json',raw)
    boot_maintenance.rollback(fixture.e,task['task_id'])
    boot_maintenance.save(fixture.c,{**task,'task_id':str(uuid.uuid4()),'stage':'preparing'})
    with patch('armhpc_ota.squashfs.read_trailer',side_effect=valid_active_slot(fixture.c)):
        assert storage_view(fixture.c,raw,lambda parent:table)['blocks'][3]['_deployment_role']=='rescue_b'
    history=fixture.c.state/'boot-maintenance/abandoned'/(task['task_id']+'.json')
    data=read_json(history);data['device_id']='other-device';atomic_json(history,data)
    with pytest.raises(OTAError):deployment.view(fixture.c,raw)


def test_replacing_manifest_and_ledger_hash_does_not_bypass_signature(interrupted):
    fixture,raw,table,task=interrupted
    from armhpc_ota.io import sha256
    manifest=fixture.c.state/'manifests'/(task['release']+'.json')
    changed=read_json(manifest);changed['payload']['release']='forged-release';atomic_json(manifest,changed)
    value=deployment.ledger(fixture.c);value['targets']['rescue_b']['manifest_sha256']=sha256(manifest)
    atomic_json(fixture.c.state/'deployment-intents.json',value)
    with pytest.raises(OTAError):deployment.view(fixture.c,raw)


def test_public_discovery_verifies_overlay_and_identity_before_mbr_admission(interrupted):
    fixture,raw,table,task=interrupted
    from pathlib import Path
    import json
    from armhpc_ota import device as module
    source_read=Path.read_bytes;source_exists=Path.exists
    atomic_json(fixture.c.state/'identity.json',{'device_id':raw['device_id']})
    tree=[]
    for node in raw['blocks']:
        if node.get('type')=='disk':
            disk=deepcopy(node);disk['children']=[deepcopy(p) for p in raw['blocks'] if p.get('parent')==node['path']];tree.append(disk)
    context={'target':'rescue','slot':'a','root':raw['root'],'partuuid':'abcd1234-02','lower_mount':'/run/armhpc-ota/lower'}
    def run(*args,**kwargs):
        if args[0]=='lsblk':return json.dumps({'blockdevices':tree})
        if args[0]=='sfdisk':return json.dumps({'partitiontable':table})
        if args[0]=='dpkg':return 'arm64'
        if args==('findmnt','-n','-o','SOURCE','/'):return 'overlay'
        if args[0]=='findmnt' and 'SOURCE,FSTYPE' in args:return raw['root']+' squashfs'
        raise AssertionError(args)
    def read(path):
        if str(path)=='/proc/device-tree/compatible':return ('\0'.join(fixture.c.board()['compatible'])+'\0').encode()
        return source_read(path)
    def exists(path):
        if str(path)=='/etc/armhpc/rescue-environment':return True
        if str(path)=='/run/armhpc-install-medium':return False
        return source_exists(path)
    simulation=fixture.c.simulate;fixture.c.simulate=None
    try:
        with patch.object(module,'run',side_effect=run),patch.object(Path,'read_bytes',read),patch.object(Path,'exists',exists),\
                patch('armhpc_ota.squashfs.boot_context',return_value=context),\
                patch('armhpc_ota.squashfs.read_trailer',side_effect=valid_active_slot(fixture.c)):
            result=discover(fixture.c)
        assert result['root']==raw['root'] and result['mode']=='rescue' and result['device_id']==raw['device_id']
        assert next(p for p in result['blocks'] if p['path']=='/dev/mmcblk1p3')['_deployment_role']=='rescue_b'
    finally:fixture.c.simulate=simulation


def test_real_signed_squashfs_with_cleared_inactive_trailer_keeps_admitted_identity(interrupted):
    import os,shutil,subprocess
    from pathlib import Path
    from armhpc_ota.squashfs import write_trailer,read_trailer
    from armhpc_ota.metadata import sign
    from armhpc_ota.io import sha256
    if os.name!='posix' or not shutil.which('mksquashfs'):pytest.skip('Native SquashFS tools are required')
    fixture,raw,table,task=interrupted
    source=fixture.r/'native-root';source.mkdir();(source/'random-data').write_bytes(os.urandom(16*1024**2))
    payload=fixture.r/'native.squashfs'
    subprocess.run(['mksquashfs',str(source),str(payload),'-noappend','-no-progress','-processors','1','-comp','xz'],
                   check=True,stdout=subprocess.DEVNULL)
    assert payload.stat().st_size>=16*1024**2
    manifest_path=fixture.c.state/'manifests'/(task['release']+'.json')
    manifest=read_json(manifest_path)['payload'];artifact=next(a for a in manifest['artifacts'] if a['role']=='rescue-rootfs')
    artifact.update(size=payload.stat().st_size,expanded_size=payload.stat().st_size,
                    sha256=sha256(payload),expanded_sha256=sha256(payload))
    signed=sign(manifest,fixture.key,'test');manifest_path.write_bytes(signed)
    for index,name in ((2,'native-a.img'),(3,'native-b.img')):
        target=fixture.r/name
        shutil.copyfile(payload,target)
        with target.open('r+b') as stream:stream.truncate(536870912)
        write_trailer(target,536870912,signed)
        raw['blocks'][index]['path']=str(target);table['partitions'][index-1]['node']=str(target)
    raw['root']=raw['blocks'][2]['path'];raw['blocks'][3]['label']=fixture.c.board()['labels']['rescue_b']
    deployment.begin(fixture.c,raw,'rescue_b',raw['blocks'][3],{'job_id':'boot-'+task['task_id'],'release':task['release']})
    write_trailer(raw['blocks'][3]['path'],536870912)
    with Path(raw['blocks'][3]['path']).open('r+b') as stream:
        stream.seek(4096);stream.write(b'partial replacement');stream.flush();os.fsync(stream.fileno())
    raw['blocks'][3]['label']=None
    with pytest.raises(OTAError):read_trailer(raw['blocks'][3]['path'],536870912,fixture.c.trust)
    result=storage_view(fixture.c,raw,lambda parent:table)
    assert result['blocks'][2]['_mbr_role']=='rescue_a'
    assert result['blocks'][3]['_deployment_role']=='rescue_b'
    assert read_trailer(raw['root'],536870912,fixture.c.trust)[0]['release']==task['release']
