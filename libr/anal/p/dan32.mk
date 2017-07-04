OBJ_DAN32=anal_dan32.o

STATIC_OBJ+=$(OBJ_DAN32)
TARGET_DAN32=anal_dan32.$(EXT_SO)

ALL_TARTGETS+=$(TARGET_DAN32)

$(TARGET_DAN32): $(OBJ_DAN32)
	$(CC) $(call libname,anal_dan32) ${LDFLAGS} ${CFLAGS} -o anal_dan32.$(EXT_SO) $(OBJ_DAN32)
