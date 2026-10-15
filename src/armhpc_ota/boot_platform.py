# SPDX-License-Identifier: GPL-3.0-only
"""Board-specific BOOT entries, filesystem handling and load-window checks."""
import os
from pathlib import Path
import shutil
import struct
import tempfile
import zlib
from .errors import require
from .io import atomic_bytes, atomic_copy, fsync_dir

LAYOUTS = {'oect-squashfs-ab-v2': ('wxy-oect-original','ext4'),
           'oesp-mbr-squashfs-ab-v1': ('wxy-oesp-v22','vfat')}
HEADER = struct.Struct('>7I4B32s')


def supported(board):
    return LAYOUTS.get(board['layout']) == (board['id'], board.get('boot_fstype','ext4'))


def entry_names(board):
    require(supported(board),'boot_compatibility','Unsupported BOOT adapter')
    names = ('boot.scr','boot.cmd','extlinux/extlinux.conf','armbianEnv.txt')
    return names + (('aml_autoscript','aml_autoscript.cmd') if board['id']=='wxy-oesp-v22' else ())


def write(config, path, data):
    path = Path(path)
    if config.board().get('boot_fstype','ext4') != 'vfat' or config.simulate:
        atomic_bytes(path,data,0o644)
        return
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path);fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def copy(config, source, destination):
    if config.board().get('boot_fstype','ext4') != 'vfat' or config.simulate:
        atomic_copy(source,destination,0o644)
        return
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+destination.name+'-',dir=destination.parent)
    temporary=Path(name)
    try:
        with Path(source).open('rb') as src,os.fdopen(fd,'wb') as dst:
            shutil.copyfileobj(src,dst,1024**2);dst.flush();os.fsync(dst.fileno())
        os.replace(temporary,destination);fsync_dir(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def ramdisk(raw, epoch=0):
    require(raw and len(raw)<=0xffffffff and raw[:4]!=bytes.fromhex('27051956'),
            'raw_initramfs','Expected a raw initramfs')
    header=HEADER.pack(0x27051956,0,int(epoch),len(raw),0,0,zlib.crc32(raw),
                       5,2,3,0,b'ARMHPC OESP initramfs')
    return header[:4]+struct.pack('>I',zlib.crc32(header))+header[8:]+raw


def script_image(script, epoch=0):
    require(script and len(script)<=1024**2,'boot_script','Invalid boot script size')
    payload=struct.pack('>II',len(script),0)+script
    header=HEADER.pack(0x27051956,0,int(epoch),len(payload),0,0,zlib.crc32(payload),
                       5,2,6,0,b'ARMHPC BOOT entry')
    return header[:4]+struct.pack('>I',zlib.crc32(header))+header[8:]+payload


def validate_load_window(board, kernel, dtb, initramfs):
    if board['id']!='wxy-oesp-v22':
        return
    with Path(kernel).open('rb') as stream:
        image=stream.read(64)
    with Path(dtb).open('rb') as stream:
        tree=stream.read(40)
    require(len(image)==64 and image[56:60]==b'ARMd','boot_kernel','Expected ARM64 Image')
    offset,size=struct.unpack_from('<QQ',image,8)
    require(offset==0x01080000 and size>=Path(kernel).stat().st_size,
            'boot_kernel_abi','Kernel differs from the vendor text-offset ABI')
    require(len(tree)==40 and tree[:4]==b'\xd0\x0d\xfe\xed' and
            struct.unpack_from('>I',tree,4)[0]==Path(dtb).stat().st_size,
            'boot_dtb','DTB size/header differs')
    regions=[(0x08080000,Path(kernel).stat().st_size),(offset,size),
             (0x08008000,Path(dtb).stat().st_size+65536),
             (0x13000000,Path(initramfs).stat().st_size+64),(0x01020000,65536)]
    for index,(start,count) in enumerate(regions):
        require(start+count<0x20000000,'boot_memory','BOOT payload exceeds the load window')
        require(all(not (start<left+length and left<start+count) for left,length in regions[:index]),
                'boot_memory','BOOT load regions overlap')


def arguments(board, slot=None, task=None, recovery=False, watchdog=False):
    value='rootfstype=squashfs ro rootwait boot=armhpc net.ifnames=0 console='+board.get('console','ttyS2,1500000')
    value+=' console=tty1 systemd.unified_cgroup_hierarchy=1'
    if recovery:
        require(slot in ('a','b'),'recovery_slot','Invalid recovery slot')
        return value+' armhpc.recovery-slot='+slot
    if task:
        value+=' armhpc.boot-maintenance='+task
    if task or watchdog:
        value+=' armhpc.watchdog=1 watchdog.open_timeout=180 watchdog.stop_on_reboot=0'
        value+=' meson_gxbb_wdt.nowayout=1' if board['id']=='wxy-oesp-v22' else ' dw_wdt.nowayout=1'
    return value


def entry_files(directory, append, board=None):
    require(directory.startswith('/') and '..' not in directory and all(c.isalnum() or c in '/-._' for c in directory),
            'boot_path','Unsafe boot directory')
    require('\n' not in append and '\r' not in append and '"' not in append,
            'boot_arguments','Unsafe boot arguments')
    ext=('DEFAULT ARMHPC\nTIMEOUT 10\nLABEL ARMHPC\n  LINUX '+directory+'/kernel\n  INITRD '+directory+
         '/initramfs\n  FDT '+directory+'/dtb\n  APPEND '+append+'\n')
    if board and board['id']=='wxy-oesp-v22':
        script=('# SPDX-License-Identifier: GPL-3.0-only\n'
                'if test -z "${devtype}"; then setenv devtype mmc; fi\n'
                'if test -z "${devnum}"; then setenv devnum 1; fi\n'
                'setenv kernel_addr_r 0x08080000\nsetenv fdt_addr_r 0x08008000\n'
                'setenv ramdisk_addr_r 0x13000000\nsetenv fdt_high 0x20000000\n'
                'setenv bootargs "'+append+'"\n'
                'if fatload ${devtype} ${devnum}:1 ${kernel_addr_r} '+directory+'/kernel; then\n'
                ' if fatload ${devtype} ${devnum}:1 ${fdt_addr_r} '+directory+'/dtb; then\n'
                '  if fatload ${devtype} ${devnum}:1 ${ramdisk_addr_r} '+directory+'/initramfs.uboot; then\n'
                '   fdt addr ${fdt_addr_r}\n'
                '   booti ${kernel_addr_r} ${ramdisk_addr_r} ${fdt_addr_r}\n  fi\n fi\nfi\n')
    else:
        script=('# SPDX-License-Identifier: GPL-3.0-only\n'
                'if test -z "${devtype}"; then setenv devtype mmc; fi\n'
                'if test -z "${devnum}"; then setenv devnum 0; fi\n'
                'if test -z "${distro_bootpart}"; then setenv distro_bootpart 1; fi\n'
                'setenv kernel_addr_r 0x02000000\nsetenv fdt_addr_r 0x12000000\nsetenv ramdisk_addr_r 0x12180000\n'
                'setenv bootargs "'+append+'"\n'
                'if load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_r} '+directory+'/kernel; then\n'
                ' if load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} '+directory+'/dtb; then\n'
                '  if load ${devtype} ${devnum}:${distro_bootpart} ${ramdisk_addr_r} '+directory+'/initramfs; then\n'
                '   setenv armhpc_initrd_size ${filesize}\n'
                '   booti ${kernel_addr_r} ${ramdisk_addr_r}:${armhpc_initrd_size} ${fdt_addr_r}\n  fi\n fi\nfi\n')
    return ext.encode(),script.encode()
