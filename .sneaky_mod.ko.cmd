cmd_/home/yl483/compsci590-final-project/sneaky_mod.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -T ./scripts/module-common.lds --build-id  -o /home/yl483/compsci590-final-project/sneaky_mod.ko /home/yl483/compsci590-final-project/sneaky_mod.o /home/yl483/compsci590-final-project/sneaky_mod.mod.o