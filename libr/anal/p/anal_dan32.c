#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define EIP (63)
#define ESP (62)
#define SIX_BIT (077)
#define DAN32_DISK (0x200000)
#define DAN32_SECTOR_SIZE (0x200)


static int set_reg_profile(RAnal *anal) {
  const char *p =
  "=A0  r03\n"
  "=A1  r04\n"
  "=A2  r05\n"
  "=LR  r59\n"
  "=PC  r63\n"
  "=SP  r62\n"
  "gpr r00 .32   0 0\n gpr r01 .32   4 0\n gpr r02 .32   8 0\n gpr r03 .32  12 0\n gpr r04 .32  16 0\n gpr r05 .32  20 0\n gpr r06 .32  24 0\n gpr r07 .32  28 0\n"
  "gpr r08 .32  32 0\n gpr r09 .32  36 0\n gpr r10 .32  40 0\n gpr r11 .32  44 0\n gpr r12 .32  48 0\n gpr r13 .32  52 0\n gpr r14 .32  56 0\n gpr r15 .32  60 0\n"
  "gpr r16 .32  64 0\n gpr r17 .32  68 0\n gpr r18 .32  72 0\n gpr r19 .32  76 0\n gpr r20 .32  80 0\n gpr r21 .32  84 0\n gpr r22 .32  88 0\n gpr r23 .32  92 0\n"
  "gpr r24 .32  96 0\n gpr r25 .32 100 0\n gpr r26 .32 104 0\n gpr r27 .32 108 0\n gpr r28 .32 112 0\n gpr r29 .32 116 0\n gpr r30 .32 120 0\n gpr r31 .32 124 0\n"
  "gpr r32 .32 128 0\n gpr r33 .32 132 0\n gpr r34 .32 136 0\n gpr r35 .32 140 0\n gpr r36 .32 144 0\n gpr r37 .32 148 0\n gpr r38 .32 152 0\n gpr r39 .32 156 0\n"
  "gpr r40 .32 160 0\n gpr r41 .32 164 0\n gpr r42 .32 168 0\n gpr r43 .32 172 0\n gpr r44 .32 176 0\n gpr r45 .32 180 0\n gpr r46 .32 184 0\n gpr r47 .32 188 0\n"
  "gpr r48 .32 192 0\n gpr r49 .32 196 0\n gpr r50 .32 200 0\n gpr r51 .32 204 0\n gpr r52 .32 208 0\n gpr r53 .32 212 0\n gpr r54 .32 216 0\n gpr r55 .32 220 0\n"
  "gpr r56 .32 224 0\n gpr r57 .32 228 0\n gpr r58 .32 232 0\n gpr r59 .32 236 0\n gpr r60 .32 240 0\n gpr r61 .32 244 0\n gpr r62 .32 248 0\n gpr r63 .32 252 0\n";
  return r_reg_set_profile_string(anal->reg, p);
}


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
  { "r56" }, { "r57"  }, { "r58" }, { "r59" }, { "r60" }, { "r61" }, { "r62" }, { "r63" }
};

/*  Here is the Dan32 Instruction Set */
enum {
  Dan32_OP_Load_B,
  Dan32_OP_Load_H,
  Dan32_OP_Load_W,
  Dan32_OP_Reserved_3,
  Dan32_OP_Store_B,
  Dan32_OP_Store_H,
  Dan32_OP_Store_W,
  Dan32_OP_Reserved_7,
  Dan32_OP_Add,
  Dan32_OP_Mul,
  Dan32_OP_Div,
  Dan32_OP_Nor,
  Dan32_OP_Reserved_12,
  Dan32_OP_Reserved_13,
  Dan32_OP_Reserved_14,
  Dan32_OP_Reserved_15,
  Dan32_OP_MovI,
  Dan32_OP_Reserved_17,
  Dan32_OP_CMov,
  Dan32_OP_Reserved_19,
  Dan32_OP_Reserved_20,
  Dan32_OP_Reserved_21,
  Dan32_OP_Reserved_22,
  Dan32_OP_Reserved_23,
  Dan32_OP_In,
  Dan32_OP_Out,
  Dan32_OP_Read,
  Dan32_OP_Write,
  Dan32_OP_Reserved_28,
  Dan32_OP_Reserved_29,
  Dan32_OP_Reserved_30,
  Dan32_OP_Halt
};


//  return the current value of a 32-bit register
static ut32 register_value(const char* reg_name, RAnal *anal){
  return r_reg_get_value(anal->reg, r_reg_get(anal->reg, reg_name, -1));
}


static int dan32_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {

  //  Decode the big-endian opcode
  ut8 big_end[4];
  big_end[0] = data[3];
  big_end[1] = data[2];
  big_end[2] = data[1];
  big_end[3] = data[0];
  const ut32 dword = *(ut32*)big_end;

  ut8 op_index = (dword >> 27);       // 5-bit opcode

  //  Decode registers / arguments
  ut8 edi = (dword >> 9 ) & SIX_BIT;  // 6-bit arg
  ut8 esi = (dword >> 15) & SIX_BIT;  // 6-bit arg
  ut8 ebp = (dword >> 21) & SIX_BIT;  // 6-bit arg

  //  Initialize the op to some default values
  memset(op, '\0', sizeof(RAnalOp));
  op->id = op_index;
  op->addr = addr;
  op->size = 4;
  op->nopcode = 1;
  op->addr = addr;
  op->jump = -1;
  op->fail = -1;
  op->ptr = -1;
  op->val = -1;
  op->type = R_ANAL_OP_TYPE_UNK;
  op->family = R_ANAL_OP_FAMILY_CPU;

  r_strbuf_init(&op->esil);
  ut8 next_op = addr + op->size;
  RReg *reg = anal->reg;

  char *edi_reg = regs[edi].name;
  char *esi_reg = regs[esi].name;
  char *ebp_reg = regs[ebp].name;

  //  Some scratch "registers"
  ut32 eax = 0x0;
  ut32 ecx = 0x0;

  //  Let's see if we are altering EIP to cause jumps
  bool eip_jump = ebp == EIP;

  switch(op_index){
    // load.x r17, [r01 + r03]
    case Dan32_OP_Load_B:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_LOAD | R_ANAL_OP_TYPE_REG;
      op->ptr = (ecx + eax) & 0xff;
      r_strbuf_setf(&op->esil, "%s,%s,+,[1],%s,=", edi_reg, esi_reg, ebp_reg);

      if(eip_jump){
        op->type = R_ANAL_OP_TYPE_RJMP;
        op->jump = op->ptr;
        op->fail = next_op;
      }
      break;

    case Dan32_OP_Load_H:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_LOAD | R_ANAL_OP_TYPE_REG;
      op->ptr = (ecx + eax) & 0xffff;
      r_strbuf_setf(&op->esil, "%s,%s,+,[2],%s,=", edi_reg, esi_reg, ebp_reg);

      if(eip_jump){
        op->type = R_ANAL_OP_TYPE_RJMP;
        op->jump = op->ptr;
        op->fail = next_op;
      }
      break;

    case Dan32_OP_Load_W:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_LOAD | R_ANAL_OP_TYPE_REG;
      op->ptr = (ecx + eax);
      r_strbuf_setf(&op->esil, "%s,%s,+,[4],%s,=", edi_reg, esi_reg, ebp_reg);

      if(eip_jump){
        op->type = R_ANAL_OP_TYPE_RJMP;
        op->jump = op->ptr;
        op->fail = next_op;
      }
      break;

    // store.x [r15 + r31], r02
    case Dan32_OP_Store_B:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_STORE | R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_REG;
      op->ptr = (ecx + eax) & 0xff;

      r_strbuf_setf(&op->esil, "%s,%s,%s,+,=[1]", ebp_reg, esi_reg, edi_reg);
      break;

    case Dan32_OP_Store_H:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_STORE | R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_REG;
      op->ptr = (ecx + eax) & 0xffff;
      r_strbuf_setf(&op->esil, "%s,%s,%s,+,=[2]", ebp_reg, esi_reg, edi_reg);
      break;

    case Dan32_OP_Store_W:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_STORE | R_ANAL_OP_TYPE_MEM | R_ANAL_OP_TYPE_REG;
      op->ptr = ecx + eax;
      r_strbuf_setf(&op->esil, "%s,%s,%s,+,=[4]", ebp_reg, esi_reg, edi_reg);
      break;

    // add r23, r22, r57
    case Dan32_OP_Add:
      op->type = R_ANAL_OP_TYPE_ADD;
      r_strbuf_setf(&op->esil, "%s,%s,+,%s,=", esi_reg, edi_reg, ebp_reg);

      if(eip_jump){
        ecx = register_value(edi_reg, anal);
        eax = register_value(esi_reg, anal);
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = eax + ecx;
        op->fail = next_op;
      }
      break;

    // mul r20, r00, r20
    case Dan32_OP_Mul:
      op->type = R_ANAL_OP_TYPE_MUL;
      r_strbuf_setf(&op->esil, "%s,%s,*,%s,=", esi_reg, edi_reg, ebp_reg);

      if(eip_jump){
        ecx = register_value(edi_reg, anal);
        eax = register_value(esi_reg, anal);
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = eax * ecx;
        op->fail = next_op;
      }
      break;

    // div r20, r00, r20
    case Dan32_OP_Div:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_DIV;
      r_strbuf_setf(&op->esil, "%s,%s,/,%s,=", edi_reg, esi_reg, ebp_reg);

      if(eip_jump && ecx != 0){
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = eax / ecx;
        op->fail = next_op;
      }
      break;

    // nor r20, r00, r00
    case Dan32_OP_Nor:
      op->type = R_ANAL_OP_TYPE_NOR;

      r_strbuf_setf(&op->esil, "%s,0xffffffff,^,%s,0xffffffff,^,&,%s,=", esi_reg, edi_reg, ebp_reg);

      if(eip_jump){
        ecx = register_value(edi_reg, anal);
        eax = register_value(esi_reg, anal);
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = (eax ^ 0xffffffff) & (ecx ^ 0xffffffff);
        op->fail = next_op;
      }
      break;

    // movi r57, 0xc
    case Dan32_OP_MovI:
      eax = dword;
      ecx = dword;
      eax >>= 5;
      eax &= 0xffff;
      ecx &= 037;
      eax <<= (ecx & 0xff);
      op->type = R_ANAL_OP_TYPE_MOV;
      op->ptr = eax;
      r_strbuf_setf(&op->esil, "0x%x,%s,=", eax, ebp_reg);

      if(eip_jump){
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = eax;
        op->fail = next_op;
      }
      break;

    // cmov eip, r57 if r23
    case Dan32_OP_CMov:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_CMOV;
      op->ptr = eax;
      r_strbuf_setf(&op->esil, "%s,?{,%s,%s,=,}", edi_reg, esi_reg, ebp_reg);

      if(eip_jump && ecx != 0){
        op->type = R_ANAL_OP_TYPE_CJMP;  //  Maybe just JMP?
        op->jump = register_value(ebp_reg, anal);
        op->fail = next_op;
      }
      break;

    // halt
    case Dan32_OP_Halt:
      op->eob = true;
      op->type = R_ANAL_OP_TYPE_TRAP;
      r_strbuf_setf(&op->esil, "BREAK");
      break;

    // in [r21]
    case Dan32_OP_In:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IO;
      op->family = R_ANAL_OP_FAMILY_IO;
      op->ptr = eax;

      //  Just always read 0x69 for now
      r_strbuf_setf(&op->esil, "0x69,%s,=[1]", esi_reg);
      break;

    // out r57
    case Dan32_OP_Out:
      op->type = R_ANAL_OP_TYPE_IO;
      op->family = R_ANAL_OP_FAMILY_IO;
      eax = register_value(ebp_reg, anal) & 0xff;
      break;

    // read [rbp], sector(rsi)
    case Dan32_OP_Read:
      eax = register_value(esi_reg, anal);
      ecx = register_value(edi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IO;
      op->family = R_ANAL_OP_FAMILY_IO;
      op->ptr = eax;

      r_strbuf_setf(&op->esil, "0x0,r40,=,0x%x,%s,*,0x%x,+,r40,+,[8],%s,r40,+,=[8],0x8,r40,+=,0x%x,r40,==,!,?{,3,GOTO,}",
          DAN32_SECTOR_SIZE, esi_reg, DAN32_DISK, ebp_reg, DAN32_SECTOR_SIZE);
      break;

    //  write sector(rsi), [rbp]
    case Dan32_OP_Write:
      ecx = register_value(edi_reg, anal);
      eax = register_value(esi_reg, anal);
      op->type = R_ANAL_OP_TYPE_IO;
      op->family = R_ANAL_OP_FAMILY_IO;
      op->ptr = eax;

      r_strbuf_setf(&op->esil, "0x0,r40,=,%s,r40,+,[8],0x%x,esi,*,0x%x,+,r40,+,=[8],0x8,r40,+=,0x%x,r40,==,!,?{,3,GOTO,}",
          ebp_reg, DAN32_SECTOR_SIZE, DAN32_DISK, DAN32_SECTOR_SIZE);
      break;

    case Dan32_OP_Reserved_3:  case Dan32_OP_Reserved_7:  case Dan32_OP_Reserved_12: case Dan32_OP_Reserved_13:
    case Dan32_OP_Reserved_14: case Dan32_OP_Reserved_15: case Dan32_OP_Reserved_17: case Dan32_OP_Reserved_19:
    case Dan32_OP_Reserved_20: case Dan32_OP_Reserved_21: case Dan32_OP_Reserved_22: case Dan32_OP_Reserved_23:
    case Dan32_OP_Reserved_28: case Dan32_OP_Reserved_29: case Dan32_OP_Reserved_30:
      op->type = R_ANAL_OP_TYPE_ILL;
      break;
  };

  return op->size;
}


static int esil_dan32_init (RAnalEsil *esil) {
  return true;
}


static int esil_dan32_fini (RAnalEsil *esil) {
  return true;
}


RAnalPlugin r_anal_plugin_dan32 = {
  .name = "dan32",
  .desc = "Dan32 analysis plugin",
  .license = "None",
  .arch = "dan32",
  .author = "safiire@irkenkitties.com",
  .bits = 32,
  .esil = true,
  .op = &dan32_anal_op,
  .set_reg_profile = &set_reg_profile,
  .esil_init = esil_dan32_init,
  .esil_fini = esil_dan32_fini
};


#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
  .type = R_LIB_TYPE_ANAL,
  .data = &r_anal_plugin_dan32,
  .version = R2_VERSION
};
#endif
