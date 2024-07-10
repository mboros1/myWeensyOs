# client side of connecting to a gdb-server running qemu
/opt/homebrew/bin/x86_64-elf-gdb -ex 'target remote localhost:1234' -ex 'file obj/bootsector.full'
