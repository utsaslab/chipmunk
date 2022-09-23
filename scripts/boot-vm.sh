#!/bin/bash

cores=$1
image=$2 # optional

if [ ! -f $image ]; then 
    echo "$image does not exist. Please run flytrap/tools/create-image.sh and move stretch.img to the flytrap root directory."
fi


if [ -z $cores ]; then
    echo "Usage: boot-vm.sh cores [image number]"
    exit 1
fi

image_name="stretch${image}.img"

# sudo qemu-system-x86_64 -boot c -m 8192 -hda $image -enable-kvm \
# -nographic -kernel vmshare/linux-5.1/arch/x86/boot/bzImage -append \
# "root=/dev/sda console=ttyS0 earlyprintk=serial memmap=128M!4G memmap=128M!4224M" \
# -fsdev local,security_model=passthrough,id=fsdev0,path=vmshare -device virtio-9p-pci,\
# id=fs0,fsdev=fsdev0,mount_tag=hostshare -smp $cores -net nic -net user,\
# hostfwd=tcp::2222-:22 -cpu host
sudo qemu-system-x86_64 -boot c -m 8G -hda $image_name -enable-kvm \
-nographic -kernel vmshare/linux-5.1/arch/x86/boot/bzImage -append \
"root=/dev/sda console=ttyS0 earlyprintk=serial memmap=128M!4G memmap=128M!4224M" \
-fsdev local,security_model=passthrough,id=fsdev0,path=vmshare$image -device virtio-9p-pci,\
id=fs0,fsdev=fsdev0,mount_tag=hostshare -smp $cores -cpu host -net nic -net user,\
hostfwd=tcp::2222-:22 -cpu host