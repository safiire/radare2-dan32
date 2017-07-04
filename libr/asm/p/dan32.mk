OBJ_DAN32=asm_dan32.o

# myarch backend
#OBJ_DAN32+=../arch/myarch/udis86/file1.o
#OBJ_DAN32+=../arch/myarch/udis86/file2.o
#[...]

STATIC_OBJ+=${OBJ_DAN32}
TARGET_DAN32=asm_dan32.${EXT_SO}

ALL_TARGETS+=${TARGET_DAN32}

${TARGET_DAN32}: ${OBJ_DAN32}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_DAN32} ${OBJ_DAN32}
