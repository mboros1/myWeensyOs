# server side gdb server running qemu
qemu-system-x86_64 -net none -parallel file:log.txt -smp 1 -M q35 -device piix4-ide,bus=pcie.0,id=piix4-ide -drive file=weensyos.img,if=none,format=raw,id=bootdisk -device ide-hd,drive=bootdisk,bus=piix4-ide.0 -s -S -d int,cpu_reset,guest_errors
