#include <r_bin.h>
#include <r_lib.h>

#define DAN32_BASE_ADDRESS (0x00000000LL)
#define DAN32_STACK_END    (0x00100000LL)
#define DAN32_DISK_ADDRESS (0x00200000LL)
#define DAN32_MAGIC        "\x87\xe0\x01\x80\xa2\x00\xe0\x87\xc2\x8d\x89\x21\x87\xe0\x02\xa3"
#define DAN32_MAGIC2       "\x47\xbf\x80\x00\x87\x20\x00\x22\x5f\x3c\xf2\x00\x47\xbe\xf2\x00"


//  Trace some info from RBinFile
static void trace(RBinFile *arch){
  eprintf("RBinFile struct:\n");
  eprintf("\tfile: %s\n", arch->file);
  eprintf("\tfd: %d\n", arch->fd);
  eprintf("\tsize %d\n", arch->size);
  eprintf("\trawstr %d\n", arch->rawstr);
  eprintf("\tid: %d\n", arch->id);
  eprintf("\toffset: %d\n", arch->offset);
  eprintf("\tloadaddr: 0x%x\n", arch->loadaddr);
  eprintf("\tsdb? 0x%x\n", arch->sdb);
  eprintf("\tsdb_info? 0x%x\n", arch->sdb_info);
  eprintf("\tsdb_addrinfo? 0x%x\n", arch->sdb_addrinfo);
}


static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 size, ut64 loadaddr, Sdb *sdb){
  return R_NOTNULL;
}


//  I will just check the first 16 bytes are from this one exact file
static bool check_bytes(const ut8 *buf, ut64 length){
  if(!buf) return false;
  return memcmp(buf, DAN32_MAGIC, 0x10) == 0 ||
         memcmp(buf, DAN32_MAGIC2, 0x10) == 0;
}


//  See if it even calls load
static bool load(RBinFile *arch){
  const ut8 *bytes = arch ? r_buf_buffer(arch->buf) : NULL;
  ut64 size = arch ? r_buf_size(arch->buf) : 0;

  if (!arch || !arch->o) return false;
  arch->o->bin_obj = load_bytes(arch, bytes, size, arch->o->loadaddr, arch->sdb);
  return check_bytes (bytes, size);
}


//  Clean up
static int destroy(RBinFile *arch) {
  r_buf_free(arch->buf);
  arch->buf = NULL;
  return true;
}


//  Return the base address
static ut64 baddr(RBinFile *arch) {
  return DAN32_BASE_ADDRESS;
}


static RList *memory(RBinFile *arch){
  RList *mem_list;
  if(!(mem_list = r_list_new())) return NULL;
  mem_list->free = free;

  RBinMem *sram = R_NEW0(RBinMem);
  if(!sram) return mem_list;
  sram->name = strdup("sram");
  sram->addr = DAN32_BASE_ADDRESS;
  sram->size = 0x7503;
  sram->perms = r_str_rwx("rwx");
  r_list_append(mem_list, sram);

  RBinMem *diskrom = R_NEW0(RBinMem);
  if(!diskrom) return mem_list;
  diskrom->name = strdup("diskrom");
  diskrom->addr = DAN32_DISK_ADDRESS;
  diskrom->size = 0x7503;
  diskrom->perms = r_str_rwx("r--");
  r_list_append(mem_list, diskrom);

  return mem_list;
}


static RList* entries(RBinFile *arch){
  RList *entry_list;
  if(!(entry_list = r_list_new())) return NULL;
  entry_list->free = free;

  RBinAddr *entry = R_NEW0(RBinAddr);
  if(!entry) return entry_list;
  entry->paddr = DAN32_BASE_ADDRESS;
  entry->vaddr = DAN32_BASE_ADDRESS;
  r_list_append(entry_list, entry);

  return entry_list;
}


//  Label some important symbols in this program
static RList* symbols(RBinFile *arch) {
  RList *symbol_list;
  if(!(symbol_list = r_list_new())) return NULL;
  symbol_list->free = free;

  //  Entrypoint
  RBinSymbol *symbol = R_NEW0(RBinSymbol);
  if(!symbol) return symbol_list;
  symbol->name = r_str_newf("entry");
  symbol->paddr = DAN32_BASE_ADDRESS;
  symbol->vaddr = DAN32_BASE_ADDRESS;
  symbol->size = 1;
  symbol->ordinal = 0;
  r_list_append(symbol_list, symbol);

  return symbol_list;
}


//  Create the section outlined in my analysis
static RList* sections(RBinFile *arch) {
  RList *section_list;
  RBinSection *section;
  if(!(section_list = r_list_new())) return NULL;
  section_list->free = free;

  //  .text (rwx)
  section = R_NEW0(RBinSection);
  if(!section) return section_list;

  strcpy(section->name, ".text");
  section->paddr = DAN32_BASE_ADDRESS;
  section->vaddr = DAN32_BASE_ADDRESS;
  section->size  = 0x92b;
  section->vsize = 0x92b;
  section->srwx =  r_str_rwx("mrwx");
  section->add = true;
  r_list_append(section_list, section);

  //  .bss (rw-)
  section = R_NEW0(RBinSection);
  if(!section) return section_list;

  strcpy(section->name, ".bss");
  section->paddr = 0x92c;
  section->vaddr = 0x92c;
  section->size  = 0x24d;
  section->vsize = 0x24d;
  section->srwx =  r_str_rwx("mrw-");
  section->add = true;
  r_list_append(section_list, section);

  //  .encrypted (rw-)
  section = R_NEW0(RBinSection);
  if(!section) return section_list;

  strcpy(section->name, ".encrypted");
  section->paddr = 0xc00;
  section->vaddr = 0xc00;
  section->size  = 0x6903;
  section->vsize = 0x6903;
  section->srwx =  r_str_rwx("mrw-");
  section->add = true;
  r_list_append(section_list, section);

  // .stack section (rw-)
  section = R_NEW0(RBinSection);
  if(!section) return section_list;

  strcpy(section->name, ".stack");
  section->vaddr = DAN32_STACK_END - 0x400;
  section->size  = 0x400;
  section->vsize = 0x400;
  section->srwx =  r_str_rwx("mrw-");
  section->add = true;
  r_list_append(section_list, section);

  //  I will label the disk sectors as symbols
  // .rodata section (r--)
  section = R_NEW0(RBinSection);
  if(!section) return section_list;

  strcpy(section->name, ".diskrom");
  section->paddr = DAN32_BASE_ADDRESS;
  section->vaddr = DAN32_DISK_ADDRESS;
  section->size  = arch->size;
  section->vsize = arch->size;
  section->srwx =  r_str_rwx("mr--");
  section->add = true;
  r_list_append(section_list, section);

  return section_list;
}


static RBinInfo *info(RBinFile *arch){
  RBinInfo *ret = R_NEW0(RBinInfo);
  if(!ret) return NULL;

  ret->file = arch->file ? strdup(arch->file) : NULL;
  ret->type = strdup("Image");
  ret->bclass = strdup("Disk Image (Encrypted)");
  ret->cpu = strdup("Dan32");
  ret->arch = strdup ("dan32");
  ret->os = strdup("any");
  ret->lang = "Hexidecimal++";
  ret->bits = 32;
  ret->has_va = true;
  ret->big_endian = true;
  ret->has_pi = false;
  ret->has_canary = false;
  ret->has_nx = false;
  ret->has_crypto = true;
  //ret->baddr = DAN32_DISK_ADDRESS;   //  ???
  return ret;
}


RBinPlugin r_bin_plugin_dan32 = {
  .name = "dan32",
  .author = "safiire@irkenkitties.com",
  .desc = "Danish 32-bit CTF Virtual Machine",
  .license = "None",
  .load = &load,
  .load_bytes = &load_bytes,
  .destroy = &destroy,
  .check_bytes = &check_bytes,
  .baddr = &baddr,
  .symbols = &symbols,
  .sections = &sections,
  .entries = &entries,
  .info = &info,
  .mem = &memory,
  //.binsym = &binsym,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
  .type = R_LIB_TYPE_BIN,
  .data = &r_bin_plugin_dan32,
  .version = R2_VERSION
};
#endif
