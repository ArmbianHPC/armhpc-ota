# SPDX-License-Identifier: GPL-3.0-only
from copy import deepcopy
import json
import pytest
from armhpc_ota.config import Config
from armhpc_ota.errors import OTAError
from armhpc_ota.platform import slot_nodes, require_fixed_boot

def disk():
    b=Config(profile='wxy-oesp-v22',storage_layout='oesp-mbr-squashfs-ab-v1').board()
    sizes=[b['boot_sectors'],b['rescue_a_sectors'],b['rescue_a_sectors'],5000000]
    starts=[b['boot_start'],b['rescue_a_start'],b['rescue_b_start'],b['shared_start']]
    blocks=[];entries=[]
    for n,(start,size) in enumerate(zip(starts,sizes),1):
        path=f'/dev/mmcblk1p{n}'
        blocks.append({'path':path,'parent':'/dev/mmcblk1','start':start,'size':size*512,
                       'partuuid':f'abcd1234-{n:02x}','label':'OESP_BOOT' if n==1 else None})
        entries.append({'node':path,'start':start,'size':size,'type':'c' if n==1 else '83'})
    return b,blocks,{'device':'/dev/mmcblk1','label':'dos','id':'0xabcd1234','sectorsize':512,'partitions':entries}

def test_profile_and_mbr_geometry():
    board,blocks,table=disk()
    assert board['boot_fstype']=='vfat' and board['protected_prefix_bytes']==100*1024**2
    assert slot_nodes(board,blocks,table)['rescue_b']['partuuid']=='abcd1234-03'

@pytest.mark.parametrize('case',['signature','offset','boot_duplicate','gpt','type','extra'])
def test_foreign_mbr_refused(case):
    board,blocks,table=disk()
    if case=='signature':blocks[2]['partuuid']='aaaaaaaa-03'
    elif case=='offset':table['partitions'][1]['start']+=1
    elif case=='boot_duplicate':blocks.append(deepcopy(blocks[0]))
    elif case=='gpt':table['label']='gpt'
    elif case=='type':table['partitions'][2]['type']='82'
    else:table['partitions'].append(deepcopy(table['partitions'][3]))
    with pytest.raises(OTAError):slot_nodes(board,blocks,table)

def test_fixed_boot_only_rejects_changed_boot(tmp_path):
    c=Config(profile='wxy-oesp-v22',state=tmp_path)
    (tmp_path/'manifests').mkdir()
    artifacts=[{'role':'rescue-'+kind,'sha256':'a'*64} for kind in ('kernel','dtb','initramfs')]
    (tmp_path/'manifests/initial.json').write_text(json.dumps({'payload':{'artifacts':artifacts}}))
    control={'confirmed':{'rescue':{'boot':{'release':'initial'}}}}
    require_fixed_boot(c,{'artifacts':[{'role':'system-kernel','sha256':'a'*64}]},control)
    with pytest.raises(OTAError,match='confirmed fixed'):
        require_fixed_boot(c,{'artifacts':[{'role':'system-dtb','sha256':'b'*64}]},control)

def test_oect_layout_policy_is_unchanged():
    b=Config(storage_layout='oect-squashfs-ab-v2').board()
    assert b['boot_start']==368640 and b['labels']['boot']=='OECT_BOOT'

def test_layout_cannot_be_selected_for_another_board():
    with pytest.raises(OTAError):Config(profile='wxy-oesp-v22',storage_layout='oect-squashfs-ab-v2').board()
