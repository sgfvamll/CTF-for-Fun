## Ambitious Catches

本题利用 GNUC++ 的异常处理机制隐藏了一个 VM 的实现。可以参考 https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html 了解 GNUC++ 异常处理的基本机制。

代码首先通过在 main 函数开头抛出一个 `bJLFw` 异常来启动 vm。在 `__gxx_personality_v0/scan_eh_tab` 函数内，采用非正常手段捕获异常，通过复写 LSDA (LanguageSpecificData) 数据结构以及修改 libc++abi 代码，扩大了原 Try 块捕获范围至整个函数。

```c++
            // Init VM Context
            bool ICatchIt = false;
            static uint8_t baklen[0x10], sz = 0;
            static uint8_t *baklenptr;
			// Check thrown exception type
            if (typeid(*(std::exception *)adjustedPtr) == typeid(U2BYG)) {
              baklenptr = lenptr;
              sz = endlenptr - lenptr;
              memcpy(baklen, baklenptr, sz);
              mprotect((void *)((uintptr_t)lenptr & (~0xfff)), 0x1000,
                       PROT_READ | PROT_WRITE);
              ZeroPointer(&lenptr, callSiteEncoding);
              mprotect((void *)((uintptr_t)lenptr & (~0xfff)), 0x1000,
                       PROT_READ);
              iSoEr->Init(actionRecord, classInfo, ttypeEncoding);
              ttypeIndex = iSoEr->Next(1);
              ICatchIt = true;
            }
```

对于后续（包括当前）的异常分发流程，`scan_eh_tab` 将通过调用 VM 的 `Next` 方法，转交 VM 进行。

VM 根据调用`Next` 方法时的参数，以及当前的 Opcode (以加密形式存储在 code 文件中)，决定下一条指令的地址。`Next` 方法的参数有三种可能，分别为 `0/1/2` ，分别为退出 VM、正常执行下一条指令、执行分支跳转。`scan_eh_tab` 调用 VM  `Next` 方法的参数由抛出的异常类型决定。

```c++
            if (typeid(*(std::exception *)adjustedPtr) == typeid(rCSmR)) {
              // ......
              ttypeIndex = iSoEr->Next(1);
              ICatchIt = true;
            }
            if (typeid(*(std::exception *)adjustedPtr) == typeid(bZroQ)) {
              ttypeIndex = iSoEr->Next(2);
              ICatchIt = true;
            }
```

最终通过执行 0 号 opcode，抛出 `bJLFw` 异常结束 VM。`scan_eh_tab` 同样捕获 `bJLFw` 并恢复 LSDA 数据结构等。

```c++
            if (typeid(*(std::exception *)adjustedPtr) == typeid(bJLFw)) {
              mprotect((void *)((uintptr_t)lenptr & (~0xfff)), 0x1000,
                       PROT_READ | PROT_WRITE);
              memcpy(baklenptr, baklen, sz);
              mprotect((void *)((uintptr_t)lenptr & (~0xfff)), 0x1000,
                       PROT_READ);
              iSoEr->Init(actionRecord, classInfo, ttypeEncoding);
              ttypeIndex = iSoEr->Next(0);
              ICatchIt = true;
            }
```



VM 初始化、解析 OPCode 等代码如下：

```c++
hp3Ll::hp3Ll(const char *fn) : ip_(1), flag_init_(false) {
  FILE *fp = fopen(fn, "rb");
  if (!fp)
    throw "Code NOT FOUND";
  fseek(fp, 0, SEEK_END);
  size_t ROM_SIZE = ftell(fp);
  rom_.reset(new uint8_t[ROM_SIZE]);
  fseek(fp, 0, SEEK_SET);
  fread((void *)rom_.get(), 1, ROM_SIZE, fp);
  ram_.reset(new uint8_t[DEFAULT_RAM_SIZE]);
}

hp3Ll::~hp3Ll() {}

uint8_t hp3Ll::AdvanceRom() {
    uint8_t r = rom_[ip_ - 1] ^ rom_[ip_];
    ip_++;
    return r;
}


void hp3Ll::Init(uint8_t *action_entry, const uint8_t *classInfo,
                 uint8_t ttypeEncoding) {
  uint8_t *action = action_entry;
  int64_t actionOffset;
  do {
    // Parse Action Table and Build an Easy-to-use Map
    int64_t ttypeIndex = readSLEB128(const_cast<const uint8_t **>(&action));
    const std::type_info *ty =
        get_type_info(ttypeIndex, classInfo, ttypeEncoding);
    ty_action_[ty] = ttypeIndex;
    const uint8_t *temp = action;
    actionOffset = readSLEB128(&temp);
    action += actionOffset;
  } while (actionOffset != 0);
}

int64_t hp3Ll::Next(int next) {
  uint8_t nxtty, op;
  const std::type_info *info;
  if (next == 0)
    return ty_action_[OPLST[12]];
  if (next > 1)
    ip_ = nxs_[next - 2];
  nxs_.resize(0);
  op = AdvanceRom();
  info = OPLST[op];
  nxtty = ty_action_[info];
  if (JMP_OPLST.find(info) != JMP_OPLST.end()) {
    src1_ = &regs_[AdvanceRom()];
    src2_ = &regs_[AdvanceRom()];
    uint8_t tmp = AdvanceRom();
    nxs_.push_back(tmp + (AdvanceRom() << 8));
  }
  if (THRAC_OPLST.find(info) != THRAC_OPLST.end()) {
    dst_ = &regs_[AdvanceRom()];
    src1_ = &regs_[AdvanceRom()];
    src2_ = &regs_[AdvanceRom()];
  }
  if (TWOAC_OPLST.find(info) != TWOAC_OPLST.end()) {
    dst_ = &regs_[AdvanceRom()];
    src1_ = &regs_[AdvanceRom()];
  }
  if (OneAC_OPLST.find(info) != OneAC_OPLST.end()) {
    dst_ = &regs_[AdvanceRom()];
  }
  if (info == LoadImm8_OP(TYPEID)) {
    dst_ = &regs_[AdvanceRom()];
    *dst_ = AdvanceRom();
  }
  if (info == Puts_OP(TYPEID)) {
    src1_ = &regs_[AdvanceRom()];
  }
  // printf("nxtty: %ld\n", nxtty);
  return nxtty;
}

std::unique_ptr<hp3Ll> iSoEr(std::make_unique<hp3Ll>("code"));

```



VM `Next` 方法内的实现可以视为 VM 的控制器(Controller)，而在 main 函数中各个 Catch 块内的实现可以看作 数据通路 (DataPath) 。每个 Opcode 的 DataPath 部分需要访问 src1、src2、dst 以及 ram 的基地址 四个参数，它们由指令本身指定，控制器分发，并通过 `r12`、`r13`、`r14`、`r15` 这四个被调用者保护寄存器传递。寄存器指派详见 `__gxx_personality_v0/set_registers` 函数内实现。

```c++
static void set_registers(_Unwind_Exception *unwind_exception,
                          _Unwind_Context *context,
                          const scan_results &results) {
#if defined(__USING_SJLJ_EXCEPTIONS__)
#define __builtin_eh_return_data_regno(regno) regno
#endif
  _Unwind_SetGR(context, __builtin_eh_return_data_regno(0),
                reinterpret_cast<uintptr_t>(unwind_exception));
  _Unwind_SetGR(context, __builtin_eh_return_data_regno(1),
                static_cast<uintptr_t>(results.ttypeIndex));
  _Unwind_SetGR(context, 12, *(uintptr_t *)iSoEr->dst_);
  _Unwind_SetGR(context, 13, *(uintptr_t *)iSoEr->src1_);
  _Unwind_SetGR(context, 14, *(uintptr_t *)iSoEr->src2_);
  _Unwind_SetGR(context, 15,
                static_cast<uintptr_t>((uintptr_t)iSoEr->ram_.get()));
  _Unwind_SetIP(context, results.landingPad);
}
```

Opcode 的返回值（若有）将通过异常参数传递，并在 `__gxx_personality_v0/scan_eh_tab`  内实现虚拟寄存器赋值：

```c++
            if (typeid(*(std::exception *)adjustedPtr) == typeid(rCSmR)) {
              rCSmR *exc = static_cast<rCSmR *>(adjustedPtr);
              if (exc->hasval())
                *(uintptr_t *)iSoEr->dst_ = exc->what();
			  // .....
            }
```



`code` 文件中 Opcode 的主要功能为校验程序的第一个命令行参数是否为合法的 FLAG。核心部分伪代码为：

```c++
const size_t GFMOD = 0x19f;
const size_t FLAG_SZ = 48;
typedef GF2N<uint8_t, 8, GFMOD> MyGF2;
typedef Eigen::Matrix<MyGF2, FLAG_SZ, FLAG_SZ> GMatrix;
typedef Eigen::Matrix<MyGF2, FLAG_SZ, 1> GColVec;
typedef Eigen::Matrix<MyGF2, 1, FLAG_SZ> GRowVec; 
GMatrix V = GMatrix::Random(), K = GMatrix::Random(), Q = GMatrix::Random();
GColVec I;
for (int i = 0; i < FLAG_SZ; i++)
    I(i, 0) = FLAG[i];
GColVec C = V * I * I.transpose() * K.transpose() * Q * I;
assert(C == [
    0x60, 0xa9, 0x7a, 0x21, 0xb1, 0xe2, 0xb7, 0x66, 0x1e, 0xec, 0x5f, 0x26,
    0x6e, 0xd1, 0xd0, 0x6e, 0xb7, 0xe9, 0x35, 0xe0, 0x57, 0x27, 0xae, 0x27,
    0x9d, 0xa0, 0x12, 0x13, 0x8c, 0x43, 0x4a, 0x99, 0x37, 0xcf, 0x0b, 0x28,
    0xe1, 0xdd, 0x2c, 0x03, 0x7c, 0xa7, 0x4b, 0x55, 0x6d, 0xdd, 0x4b, 0xe9,
]);

```

注意到 `I.transpose() * K.transpose() * Q * I` 的结果是一个 $GF(2^8)$ 上的标量，设为 $a$ 。只需计算 $V^{-1} * C$，然后爆破 $a$ 即可。

两个需要注意的点：

1. `GMatrix` 元素为 模 0x19f 的 $GF(2^8)$ 域上元素，与通常整数上的加减乘除有所不同；

2. `V`、`K`、`Q` 参数矩阵是伪随机生成的（见如下反汇编代码）。

   ```c++
   char Eigen::internal::random_default_impl<GF2N<unsigned char,8ul,415ul>,false,true>::run()
   {
     int v0; // eax
     char v2[8]; // [rsp+8h] [rbp-8h] BYREF
   
     v0 = rand();
     GF2N<unsigned char,8ul,415ul>::GF2N(v2, (unsigned __int8)(v0 >> 23));
     return v2[0];
   }
   ```

   伪随机数种子在 `init_array` 中的 `init` 函数中设置：

   ```c++
   void __attribute__((constructor)) init() {
     int seed = time(0) >> 4;
     srand(seed);
   }
   ```

   显然需要在某个特定的16s的时间内，这个 check 程序才能有正确的输出。联系到密文藏在`code` 文件中，这个特定的值就是 `code` 文件生成的时间戳。或者通过爆破比赛时间前后的时间戳也不难得到正确答案。
   

FLAG: `HFCTF{Enjo7_Pla7in6_w1th_Exc3pt1on_4nd_Alge82a!}`



