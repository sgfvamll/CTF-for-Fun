from ast import Tuple
from xmlrpc.client import Boolean
from barf.barf import BARF
import angr
import struct
import sys
from pwnlib import elf
from queue import SimpleQueue
# from pwn import *

class PatchHelper:
  opcode = {'a' :0x87, 'ae':0x83, 'b' :0x82, 'be':0x86, 'c' :0x82, 'e' :0x84, 'z' :0x84, 'g' :0x8F, 
            'ge':0x8D, 'l' :0x8C, 'le':0x8E, 'na':0x86, 'nae':0x82,'nb':0x83, 'nbe':0x87,'nc':0x83,
            'ne':0x85, 'ng':0x8E, 'nge':0x8C,'nl':0x8D, 'nle':0x8F,'no':0x81, 'np':0x8B, 'ns':0x89,
            'nz':0x85, 'o' :0x80, 'p' :0x8A, 'pe':0x8A, 'po':0x8B, 's' :0x88, 'nop':0x90,'jmp':0xE9, 'j':0x0F}
  JMP_SIZE = 5
  
  def is_unreachable(self, bb):
    if isinstance(bb, int):
      bb = self.block(bb)
    for i in range(len(bb.instrs)):
      if bb.instrs[i].mnemonic != "call":
        continue
      target = bb.instrs[i].operands[0].immediate
      if target == self.func_terminate:
        return True

  def block(self, addr):
    bb = self.cfg.find_basic_block(addr)
    if bb is None:
      bb = barf.bb_builder.strategy._disassemble_bb(addr, barf.binary.ea_end, {})
    return bb

  @staticmethod
  def is_imm(operand):
    return (hasattr(operand, "_X86ImmediateOperand__key"))

  @staticmethod
  def is_reg(operand):
    return (hasattr(operand, "_X86RegisterOperand__key"))

  def is_call_throw(self, instr):
    return instr.mnemonic == "call" and \
        self.is_imm(instr.operands[0]) and\
        instr.operands[0].immediate == self.func_throw

  def is_call_allocate_exception(self, instr):
    return instr.mnemonic == "call" and \
        self.is_imm(instr.operands[0]) and\
        instr.operands[0].immediate == self.func_allocate_exception

  def is_call_obf_exception(self, instr):
    return instr.mnemonic == "call" and \
        self.is_imm(instr.operands[0]) and\
        instr.operands[0].immediate == self.func_obf_exception


  def skip_call_args(self, bb, i):
    while ((bb.instrs[i].mnemonic in ["xor","mov","lea"]) and\
      (len(bb.instrs[i].operands) > 0) and (self.is_reg(bb.instrs[i].operands[0])) and\
      (bb.instrs[i].operands[0].name in ["edx", "rdx", "esi", "rsi", "edi", "rdi"])) or \
      bb.instrs[i].mnemonic == "nop":
      i -= 1
    return i

  def get_patchable_from_relblk(self, bb):
    i = 0 
    end = bb.start_address + bb.size
    while i < len(bb.instrs) and not self.is_call_throw(bb.instrs[i]):
      i += 1
    i = self.skip_call_args(bb, i-1)
    if i == len(bb.instrs) - 1:
      start = end 
    else:
      start = bb.instrs[i+1].address
    self.fill_nops(start, end)
    return (start, end-start)
  
  def __init__(self, proj, elf, barf, cfg) -> None:
    self.p = proj
    obj = proj.loader.main_object
    self.func_terminate = obj.symbols_by_name["__clang_call_terminate"].rebased_addr
    self.func_throw = obj.plt["__cxa_throw"]
    self.func_allocate_exception = obj.plt["__cxa_allocate_exception"]
    self.func_obf_exception = obj.symbols_by_name["_ZN18StdSubObfExceptionC2Ec"].rebased_addr
    self.elf = elf
    self.elfData = bytearray(self.elf.data)
    self.barf = barf
    self.cfg = cfg
    self.nops = []

  def append_nop(self, nopblk):
    if nopblk[1] > 0:
      self.nops.append(nopblk)

  def finalize(self):
    self.nops.sort()
    idx = 0
    while idx < len(self.nops) - 1:
      if self.nops[idx][0] + self.nops[idx][1] != self.nops[idx+1][0]:
        idx += 1
        continue
      self.nops[idx]=(self.nops[idx][0], self.nops[idx][1]+self.nops[idx+1][1])
      del self.nops[idx+1]

  def fill_nops(self, va_start, va_end):
    assert not self.elf is None
    start = self.elf.vaddr_to_offset(va_start)
    end   = self.elf.vaddr_to_offset(va_end)
    for i in range(start, end):
      self.elfData[i] = PatchHelper.opcode['nop']

  def get_nop_around(self, addr):
    for start, size in self.nops:
      if start<=addr<=start+size:
        return (start, size)
    return (-1, 0)
  
  def get_nop_by_size(self, min_size):
    for idx, nop in enumerate(self.nops):
      if nop[1] > min_size:
        del self.nops[idx]
        return nop
    return (-1, 0)

  def delete_nop(self, addr, delsize):
    for idx, start, size in enumerate(self.nops):
      if start>=addr and addr<=start+size:
        if start == addr:
          self.nops[idx] = (start+delsize, size-delsize)
          break
        elif start+size == addr+delsize:
          self.nops[idx] = (start, addr-start)
          break
        else: # not handled
          self.nops[idx] = (start, 0)

  def do_patch(self, va_start, codes):
    start = self.elf.vaddr_to_offset(va_start)
    for i in range(len(codes)):
      self.elfData[start+i] = codes[i]

  def patch_jmp(self, va_start, va_target):
    offset = va_target - va_start - PatchHelper.JMP_SIZE
    jmp = bytes([PatchHelper.opcode['jmp']])+struct.pack('<i', offset)
    self.do_patch(va_start, jmp)
    return PatchHelper.JMP_SIZE

  def patch_branches(self, bb, va_targets):
    va_start, size = self.get_patchable_from_relblk(bb)
    if size < PatchHelper.JMP_SIZE:
      print("[Warning] patch_jmp at block %x may fail. size: %d."%(bb.address, size))
    org_start = va_start
    print(f"va_start: {hex(va_start)}, bb addr: {hex(bb.address)}, size: {size}")
    ## `cmp esi, v` instr takes 3 bytes while `je xxx` takes 6 bytes
    ## And the last jmp instr takes 5 bytes. 
    total_size = (3+6) * len(va_targets) - 4
    if size < total_size:
      ## If the nop block at the end of current block is not large enough, 
   	  ## try to find another nop block and then jump to it. 
      nx_va_start, nx_size = self.get_nop_by_size(total_size)
      if nx_size == 0:
        print("\033[31m[Error]\033[0m `patch_branches` needs a nop block with size larger than %d."%(total_size))
      self.patch_jmp(va_start, nx_va_start)
      va_start, size = nx_va_start, nx_size
    for i, t in enumerate(va_targets[:-1]):
      cmp_instr = bytes([0x83,0xfe,i])
      self.do_patch(va_start, cmp_instr)
      va_start += len(cmp_instr)
      cj_instr = bytes([PatchHelper.opcode['j'],PatchHelper.opcode['e']])
      if t == -1:
        ## -1 represent that we do not know the flow for this selector value for now. 
        cj_instr += struct.pack('<i', self.func_terminate-va_start-6)
        # cj_instr = asm(f"je {hex(self.func_terminate)}", vma=va_start)
      else:
        cj_instr += struct.pack('<i', t-va_start-6)
        # cj_instr = asm(f"je {hex(t)}", vma=va_start)
      self.do_patch(va_start, cj_instr)
      va_start += len(cj_instr)
    va_start += self.patch_jmp(va_start, va_targets[-1])
    if va_start > org_start+size:
      print("[Warning] patches at (%x, %x) overlaps next blk. "%(org_start, va_start))

def get_relevant_blocks(cfg, patch_helper, main_dispatcher):
  isCmpRI = lambda instr: instr.mnemonic == "cmp" and\
    hasattr(instr.operands[0], "_X86RegisterOperand__key") and\
    hasattr(instr.operands[1], "_X86ImmediateOperand__key") 
  isCJmp = lambda instr: instr.mnemonic.startswith("j") and \
    instr.mnemonic != "jmp"
  isSubDispatcher = lambda bb: (len(bb.instrs) == 2) and\
     isCmpRI(bb.instrs[0]) and isCJmp(bb.instrs[1])
  relevant_blocks = []
  visited = set()
  q = SimpleQueue()
  q.put(patch_helper.block(main_dispatcher))
  while not q.empty():
    bb = q.get()
    if isSubDispatcher(bb):
      patch_helper.append_nop((bb.start_address, bb.size))
      for succ, cond in bb.branches:
        if succ in visited:
          continue
        q.put(patch_helper.block(succ))
        visited.add(succ)
    else:
      relevant_blocks.append(bb)
  return relevant_blocks


def parse_logs(logfn, prologue, patch_helper):
  with open(logfn, "r") as f:
    t = f.readlines()
  i = 0
  selector_s = "selector: "
  landingpad_s = "landingPad: "
  relations = set()
  laddr = prologue
  lselector = 0
  landingpad = 0
  while i < len(t):
    try:
      addr = int(t[i], 16)
    except:
      i += 1
      continue
    if not laddr is None:
      relations.add((laddr, lselector, addr))
    if t[i+1].startswith(selector_s):
      selector = int(t[i+1][len(selector_s):], 16)
      i += 2
    elif t[i+1].startswith(landingpad_s):
      landingpad = int(t[i+1][len(landingpad_s):], 16)
      relations.add((addr, -1, landingpad))
      addr = landingpad
      while not patch_helper.is_unreachable(patch_helper.block(addr).direct_branch):
        addr = patch_helper.block(addr).direct_branch
      if t[i+2].startswith(selector_s):
        selector = int(t[i+2][len(selector_s):], 16)
      i += 3
    elif t[i+1].startswith("[Inferior "):
      i += 1
    else:
      print("Warning: %x doesn't have selector. "%addr)
      exit(0)
    laddr = addr
    lselector = selector
  return list(relations)


def generate_gdb_script(relevant_blocks):
  cmds = """\
set pagination off

b *0x40A3D4
commands
  silent
  printf "landingPad: %x\\n", $rdx
  continue
end

b _ZN18StdSubObfExceptionC2Ec
commands
  silent
  printf "selector: %x\\n", $rsi
  continue
end 

define mytrace 
  break $arg0
  commands
    silent
    printf "%x\\n", $pc
    python gdb.execute('continue')
  end
end
"""
  for bb in relevant_blocks:
    cmds += (f"mytrace *{hex(bb.address)} \n")
  cmds += "run\n"
  with open("test.gdb", "w") as f:
    f.write(cmds)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python deflat.py filename function_address(hex) [logfile]')
        exit(0)

    # context.arch = "amd64"
    # context.os = "linux"
    # context.endian = "little"

    filename = sys.argv[1]
    start = int(sys.argv[2], 16)

    origin = elf.ELF(filename)
    b = angr.Project(filename, load_options={'auto_load_libs': False, 'main_opts':{'custom_base_addr': 0}})
    barf = BARF(filename)
    cfg = barf.recover_cfg(start=start)
    patch_helper = PatchHelper(b, origin, barf, cfg)
    blocks = cfg.basic_blocks

    prologue = start
    main_dispatcher = patch_helper.block(prologue).direct_branch
    relevant_blocks = get_relevant_blocks(cfg, patch_helper, main_dispatcher)
    nop = patch_helper.get_patchable_from_relblk(patch_helper.block(prologue))
    patch_helper.append_nop(nop)

    print('*******************relevant blocks************************')
    print('main_dispatcher:%#x' % main_dispatcher)
    print('relevant_blocks:', [hex(bb.address) for bb in relevant_blocks])


    if len(sys.argv) < 4:
      generate_gdb_script(relevant_blocks)
      exit(0)

    print('************************flow******************************')
    relations = parse_logs(sys.argv[3], prologue, patch_helper)
    relations.sort(key = lambda x:x)
    flow = {}
    for bb, selector, child in relations:
      if bb in flow:
        while len(flow[bb]) < selector:
          flow[bb].append(-1)
        flow[bb].append(child)
        assert(len(flow[bb]) == selector+1)
      else:
        flow[bb] = [child]
    for (k, v) in list(flow.items()):
        print('%#x:' % k, [hex(child) for child in v])

    print('************************patch*****************************')
    patch_helper.finalize()
    for (parent, childs) in list(flow.items()):
      ## Patch jmps
      blk = patch_helper.block(parent)
      patch_helper.patch_branches(blk, childs)
      ## Nop call allocate_exception and call obf_exception
      for idx, instr in enumerate(blk.instrs):
        if patch_helper.is_call_allocate_exception(instr) or\
          patch_helper.is_call_obf_exception(instr):
          # si = patch_helper.skip_call_args(blk, idx-1)+1
          # start = blk.instrs[si].address
          start = instr.address
          end = instr.address + instr.size
          patch_helper.fill_nops(start, end)

    with open(filename + '.recovered', 'wb') as f:
        f.write(bytes(patch_helper.elfData))
    print('Successful! The recovered file: %s' % (filename + '.recovered'))
