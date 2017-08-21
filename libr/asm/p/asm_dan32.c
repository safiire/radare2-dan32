#include <r_asm.h>
#include <r_lib.h>

#define EIP 63
#define NUM_OPS 32
#define SIX_BIT 077

//  I don't even use this...
static const struct {
  char *name;
} ops[NUM_OPS] = {
  { "load.b"  },
  { "load.h"  },
  { "load.w"  },
  { NULL      },
  { "store.b" },
  { "store.h" },
  { "store.w" },
  { NULL      },
  { "add"     },
  { "mul"     },
  { "div"     },
  { "nor"     },
  { NULL      },
  { NULL      },
  { NULL      },
  { NULL      },
  { "movi"    },
  { NULL      },
  { "cmov"    },
  { NULL      },
  { NULL      },
  { NULL      },
  { NULL      },
  { NULL      },
  { "in"      },
  { "out"     },
  { "read"    },
  { "write"   },
  { NULL      },
  { NULL      },
  { NULL      },
  { "halt"    }
};


static const struct {
  char *name;
} regs[] = {
  { "r00" }, { "r01"  }, { "r02" }, { "r03" }, { "r04" }, { "r05" }, { "r06" }, { "r07" },
  { "r08" }, { "r09"  }, { "r10" }, { "r11" }, { "r12" }, { "r13" }, { "r14" }, { "r15" },
  { "r16" }, { "r17"  }, { "r18" }, { "r19" }, { "r20" }, { "r21" }, { "r22" }, { "r23" },
  { "r24" }, { "r25"  }, { "r26" }, { "r27" }, { "r28" }, { "r29" }, { "r30" }, { "r31" },
  { "r32" }, { "r33"  }, { "r34" }, { "r35" }, { "r36" }, { "r37" }, { "r38" }, { "r39" },
  { "r40" }, { "r41"  }, { "r42" }, { "r43" }, { "r44" }, { "r45" }, { "r46" }, { "r47" },
  { "r48" }, { "r49"  }, { "r50" }, { "r51" }, { "r52" }, { "r53" }, { "r54" }, { "r55" },
  { "r56" }, { "r57"  }, { "r58" }, { "r59" }, { "r60" }, { "r61" }, { "esp" }, { "eip" }
};


static const char *size_suffixes[] = {"b", "h", "w"};

static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {

  //  Initialize to invalid
  snprintf(op->buf_asm, R_ASM_BUFSIZE, "invalid");
  op->size = -1;

  //  Decode the op
  ut8 big_end[4];
  big_end[0] = buf[3];
  big_end[1] = buf[2];
  big_end[2] = buf[1];
  big_end[3] = buf[0];
  ut32 dword = *(ut32*)big_end;

  ut8 op_index = (dword >> 27);       // 5-bit opcode

  //  Decode registers / arguments
  ut8 edi = (dword >> 9 ) & SIX_BIT;  // 6-bit arg
  ut8 esi = (dword >> 15) & SIX_BIT;  // 6-bit arg
  ut8 ebp = (dword >> 21) & SIX_BIT;  // 6-bit arg

  char *edi_reg = regs[edi].name;
  char *esi_reg = regs[esi].name;
  char *ebp_reg = regs[ebp].name;

  //  Let's see if we are altering EIP to cause jumps
  bool eip_jump = ebp == EIP;

  //  Some scratch "registers"
  ut32 eax = 0x0;
  ut32 ecx = 0x0;

  switch(op_index) {
    case 0:
    case 1:
    case 2:
      if(esi == 0 || edi == 0){
        eax = esi | edi;
        snprintf(op->buf_asm, R_ASM_BUFSIZE, "load.%s %s, [%s]", size_suffixes[op_index], ebp_reg, regs[eax].name);
      }else{
        snprintf(op->buf_asm, R_ASM_BUFSIZE, "load.%s %s, [%s + %s]", size_suffixes[op_index], ebp_reg, esi_reg, edi_reg);
      }
      op->size = 4;
      break;

    case 4:
    case 5:
    case 6:
      if(esi == 0 || edi == 0){
        eax = esi | edi;
        snprintf(op->buf_asm, R_ASM_BUFSIZE, "store.%s [%s], %s", size_suffixes[op_index - 4], regs[eax].name, ebp_reg);
      }else{
        snprintf(op->buf_asm, R_ASM_BUFSIZE, "store.%s [%s + %s], %s", size_suffixes[op_index - 4], esi_reg, edi_reg, ebp_reg);
      }
      op->size = 4;
      break;

    case 8:
      if(eip_jump){
        if(esi == 0){
          snprintf(op->buf_asm, R_ASM_BUFSIZE, "goto %s", edi_reg);
        }else if(edi == 0){
          snprintf(op->buf_asm, R_ASM_BUFSIZE, "goto %s", esi_reg);
        }
      }else{
        snprintf(op->buf_asm, R_ASM_BUFSIZE, "add %s, %s, %s", ebp_reg, esi_reg, edi_reg);
      }
      op->size = 4;
      break;

    case 9:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "mul %s, %s, %s", ebp_reg, esi_reg, edi_reg);
      op->size = 4;
      break;

    case 10:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "div %s, %s, %s", ebp_reg, esi_reg, edi_reg);
      op->size = 4;
      break;

    case 11:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "nor %s, %s, %s", ebp_reg, esi_reg, edi_reg);
      op->size = 4;
      break;

    case 16:
      eax = dword;
      ecx = dword;
      eax >>= 5;
      eax &= 0xffff;
      ecx &= 037;
      eax <<= (ecx & 0xff);

      snprintf(op->buf_asm, R_ASM_BUFSIZE, "movi %s, 0x%0x", ebp_reg, eax);
      op->size = 4;
      break;

    case 18:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "cmov %s, %s if %s", ebp_reg, esi_reg, edi_reg);
      op->size = 4;
      break;

    case 24:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "in %s", ebp_reg);
      op->size = 4;
      break;

    case 25:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "out %s", ebp_reg);
      op->size = 4;
      break;

    case 26:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "read [%s], sector(%s)", ebp_reg, esi_reg);
      op->size = 4;
      break;

    case 27:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "write [%s], sector(%s)", ebp_reg, esi_reg);
      op->size = 4;
      break;

    case 31:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "halt");
      op->size = 4;
      break;

    case 3: case 7: case 12: case 13: case 14: case 15: case 17: case 19:
    case 20: case 21: case 22: case 23: case 28: case 29: case 30:
      snprintf(op->buf_asm, R_ASM_BUFSIZE, "!imp (%s, %s, %s)", ebp_reg, esi_reg, edi_reg);
      op->size = -1;
      break;
  };

  return op->size;
}


RAsmPlugin r_asm_plugin_dan32 = {
  .name = "dan32",
  .author = "safiire@irkenkitties.com",
  .license = "None",
  .desc = "Dan32 disassembler",
  .arch = "dan32",
  .endian = R_SYS_ENDIAN_BIG,
  .bits = 32,
  .init = NULL,
  .fini = NULL,
  .disassemble = &disassemble,
  .modify = NULL,
  .assemble = NULL,
};


#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
  .type = R_LIB_TYPE_ASM,
  .data = &r_asm_plugin_dan32
};
#endif
