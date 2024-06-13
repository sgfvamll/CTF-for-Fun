### yara-?

通过阅读/调试源码，可发现yara-x规则的匹配主要有两部分逻辑: re_code正则匹配逻辑、wasm编译成的native code代码（下称wasm aot code）。

re_code逻辑可以通过在源码里打patch，打印出来。Patch核心部分是在`lib/src/tests`路径下加了一个test文件`mytest.rs`，此外还需要加一些`#[derive(Debug)]`，以及修改一些模块、成员的可见性(改成pub)。 `mytest.rs`内容如下:
```rust
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::compiler::{
    SubPattern, SubPatternFlagSet, SubPatternFlags, SubPatternId,
};
use crate::re::CodeLoc;
use crate::{Rule, Rules, ScanError, Scanner};
use anyhow::{bail, Context, Error};
use digest::consts::False;

use crate::re::fast::instr::Instr as FastInstr;
use crate::re::fast::instr::InstrParser as FastInstrParser;
use crate::re::thompson::instr::{Instr, InstrParser};
use crate::re::thompson::pikevm::PikeVM;

fn print_re_code(
    file: &mut File,
    recode: &[u8],
    start: usize,
    end: usize,
    fast: bool,
    skip: bool,
) -> usize {
    let mut ip = start;
    while ip <= end && ip < recode.len() {
        if fast {
            let (instr, size) = FastInstrParser::decode_instr(unsafe {
                recode.get_unchecked(ip..)
            });
            if size == 0 {
                return ip;
            }
            if !skip {
                file.write(format!("{:}: {:?}\n", ip + 1, instr).as_bytes())
                    .unwrap();
            }
            ip += size;
            match instr {
                FastInstr::Alternation(alternatives) => {
                    for alt in alternatives {
                        file.write(format!("\t{:?}\n", alt).as_bytes())
                            .unwrap();
                    }
                }
                FastInstr::Match => {
                    return ip;
                }
                _ => {}
            };
        } else {
            let (instr, size) = InstrParser::decode_instr(unsafe {
                recode.get_unchecked(ip..)
            });
            if !skip {
                file.write(format!("{:}: {:?}\n", ip + 1, instr).as_bytes())
                    .unwrap();
            }
            ip += size;
            match instr {
                Instr::Match => {
                    return ip;
                }
                _ => {}
            };
        };
    }
    ip
}

#[test]
fn play() {
    let rules_path =
        PathBuf::from_str("/home/link/ctf/r3ctf2024/yara/yara-x/rules_x86")
            .unwrap();
    // let rules_path =
    //     PathBuf::from_str("/home/link/ctf/r3ctf2024/yara/yara-x/output.yarc")
    //         .unwrap();

    let file = File::open(rules_path.clone())
        .with_context(|| format!("can not open {:?}", &rules_path))
        .unwrap();

    let rules = Rules::deserialize_from(file).unwrap();
    let code = rules.re_code();

    let mut file = File::create("re_code.txt").unwrap();
    file.write(format!("{:?}\n\n", rules).as_bytes()).unwrap();
    // print_re_code(&mut file, code, 0, code.len() - 1, false, false);
    file.write("\nSubpatterns: \n".as_bytes()).unwrap();
    for i in 0..=30u32 {
        let (pattern_id, sub_pattern) =
            rules.get_sub_pattern(SubPatternId { 0: i });
        file.write(
            format!("{:?}: {:?}\n", pattern_id, sub_pattern).as_bytes(),
        )
        .unwrap();
    }
    file.write("\nAtoms: \n".as_bytes()).unwrap();
    let mut printed = HashMap::new();
    for atom in rules.atoms() {
        let (_, sub_pattern) = rules.get_sub_pattern(atom.sub_pattern_id());
        let flags = match &sub_pattern {
            SubPattern::Regexp { flags } => flags,
            _ => unreachable!(),
        };
        if !printed.contains_key(&atom.sub_pattern_id().0) {
            file.write(format!("{:?}\n", atom).as_bytes()).unwrap();
            let sss = atom.fwd_code().unwrap().location();
            let eee = if atom.bck_code().is_some() {
                atom.bck_code().unwrap().location()
            } else {
                sss + 100
            };
            // let eee = if sss < eee { eee } else { sss + 100 };
            let fast = flags.contains(SubPatternFlags::FastRegexp);
            // print_re_code(&mut file, code, sss, eee, fast);
            printed.insert(atom.sub_pattern_id().0, fast);
        }
        // else {
        //     assert!(
        //         atom.fwd_code() == printed[&atom.sub_pattern_id().0].fwd_code()
        //     );
        //     assert!(
        //         atom.bck_code() == printed[&atom.sub_pattern_id().0].bck_code()
        //     );
        // }
    }
    file.write("\nfull re code: \n".as_bytes()).unwrap();
    let mut ip = 0;
    let mut i = 0u32;
    while ip < code.len() {
        file.write(format!("\n== {:?}:\n", i).as_bytes()).unwrap();
        ip =
            print_re_code(&mut file, code, ip, code.len(), printed[&i], false);
        ip = print_re_code(&mut file, code, ip, code.len(), printed[&i], false);
        i += 1;
    }
    file.write("\nanchored_sub_patterns: \n".as_bytes()).unwrap();
    for asp in rules.anchored_sub_patterns() {
        file.write(format!("{:?}\n", asp).as_bytes()).unwrap();
    }
}
```

打印出来的正则表达式示例如下:

```
== 0:
1: ClassRanges(ClassRanges([48, 57, 65, 90, 95, 95, 97, 123, 125, 125]))
14: ClassRanges(ClassRanges([48, 57, 65, 90, 95, 95, 97, 123, 125, 125]))
// ... 重复共31次
404: Match
== 1:
811: Literal([114, 51, 99, 116, 102, 123])
820: JumpNoNewlineUnbounded(0..)
825: Literal([125])
829: Match
```

通过yara-x源码中fastvm/pikevm匹配逻辑理解这些指令的函数，逆向正则表达式。整理出来大概这么31条正则:

```
define exist_n_no1(n, no) (no.*.*){n-1}no.*
define exist_n_no2(n, no) (no.*){n-1}no

SubPatternId(0):  [0-9A-Z_a-z\{\}]{31}
SubPatternId(1):  r3ctf\{.*\}

SubPatternId(2):  exist_n_no1(4, _)
SubPatternId(3):  exist_n_no1(5, _)

SubPatternId(6):  exist_n_no1(4, 3)
SubPatternId(7):  exist_n_no1(5, 3)

SubPatternId(8):  exist_n_no1(2, 0)
SubPatternId(9):  exist_n_no1(3, 0)

SubPatternId(5):  ^.{6}[r\{\}]
SubPatternId(4):  ^.{26}[a-z]{2}[0-9]{2}
SubPatternId(10): ^.{25}.*exist_n_no2(4, [56_gh])
SubPatternId(14): ^.{12}[1|3]s.s[0|1]
SubPatternId(16): ^.{6}[2-9A-Za-z]{5}
SubPatternId(17): ^.{6}[^4]{5}
SubPatternId(18): ^.{8}[^3]{5}
SubPatternId(19): ^.{16}[^1]{7}
SubPatternId(25): ^.{18}.*3.*.*3.*
SubPatternId(27): ^.{21}.*m.*
SubPatternId(29): ^.{8}[^_].*
SubPatternId(30): ^.{18}[0-9a-zA-Z]{7}

SubPatternId(13): 1.*
SubPatternId(15): gEx.*
SubPatternId(20): 3_.*
SubPatternId(21): [^_]3.*
SubPatternId(24): x_.*
SubPatternId(26): 3[^3].*
SubPatternId(28): 4w.*

SubPatternId(11): _.{2}_.{2}_
SubPatternId(12): 1.*0

SubPatternId(22): 0.*3.*.*0.*3.*
SubPatternId(23): 0.*3.*.*0.*3.*.*0.*3.*
```

另一边，wasm aot code主要是Rules的condition块逻辑编译而成，逻辑相对简单。笔者的逆向方法是通过自己编写一些测试规则，然后猜测各种调用的含义。比如：

```
rule RegExpExample1
{
    strings:
        $re1 = /md5: [0-9a-fA-F]{32}/
        $re2 = /state: (on|off)/
        $re3 = /_[^\n]*[^\n]*_[^\n]*[^\n]*_[^\n]*[^\n]*_[^\n]*/
        $re4 = /r3ctf\{.*\}/
        $re5 = /^[0-9]{2}[a-z]/

    condition:
        $re1 and (#re2 == 2) and int8(3) == 80 and (not $re3) and $re4 and $re5
}
```

反编译wasm aot code:

```c
__int64 __fastcall wasm_0_::function_168_(__int64 a1)
{
  // .....
  if ( (*(_BYTE *)(v3 + *v2) & 1) != 0 )
  {
    // ......
    if ( (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(a1 + 2344))(*(_QWORD *)(a1 + 2368), a1, 1LL) == 2 )
    {
      v5 = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(a1 + 520))(*(_QWORD *)(a1 + 544), a1, 3LL);
      if ( v6 )
        v7 = 0;
      else
        v7 = v5 == 80;
      if ( v7 )
      {
        if ( !*v1 )
        {
          if ( (*(unsigned int (__fastcall **)(_QWORD, __int64))(a1 + 2504))(*(_QWORD *)(a1 + 2528), a1) )
            *v1 = 1;
          else
            **(_DWORD **)(a1 + 5496) = 1;
        }
        if ( (unsigned __int8)(*(_BYTE *)(v3 + *v2) & 4) >> 2 )
        {
          v4 = 0;
        }
  // ......
}
```

大概可以猜出`(unsigned __int8)(*(_BYTE *)(v3 + *v2) & 4) >> 2`这样的语句是在判断下标为2的strings规则是否匹配上了。而`(*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(a1 + 520))(*(_QWORD *)(a1 + 544), a1, 3LL)`是取文件中字符串第3个字节的值。

这样，得到第3、7、9、23条规则应该不满足，而其它正则规则应满足。此外，还有如下约束:

```python
s.add(flag[26] - flag[28] == 50)
s.add(flag[27] - flag[29] == 50)
s.add(flag[15] - flag[21] == 0)
s.add(flag[16] - flag[22] == 0)
s.add(flag[26] <= flag[27])
```

把以上两部分拼起来，用z3求解满足的表达式:

```python
from z3 import *

flag_sym = [BitVec(f"flag_{i}", 8) for i in range(7, 30)]
flag = list(b"r3ctf{r") + flag_sym + [ord("}")]

def in_range(sym, rg):
    if len(rg) == 0:
        return False
    return Or(And(sym >= rg[0], sym <= rg[1]), in_range(sym, rg[2:]))

s = Solver()
for sym in flag_sym:
    s.add(in_range(sym, [48, 57, 65, 90, 95, 95, 97, 122]))
    # in_range(sym, [48, 57, 65, 90, 95, 95, 97, 123, 125, 125])

s.add(Sum([sym == ord('_') for sym in flag_sym]) == 4)
s.add(Sum([sym == ord('3') for sym in flag_sym]) == 3)
s.add(Sum([sym == ord('0') for sym in flag_sym]) == 2)

# Rule 4
for i in range(26-7, 26-7+2):
    s.add(in_range(flag_sym[i], [97, 122]))
for i in range(26+2-7, 26+2-7+2):
    # e = in_range(flag_sym[i], [48, 57])
    e = in_range(flag_sym[i], [49, 57])
    print(e)
    s.add(e)

# Rule 10
s.add(Sum([
    Or(sym == ord('5'), sym == ord('6'), sym == ord('_'), sym == ord('g'), sym == ord('h'))
    for sym in flag_sym[25-7:]]) >= 4
)

# Rule 13
s.add(Sum([sym == ord('1') for sym in flag_sym]) >= 1)

# Rule 14
s.add(Or(flag_sym[12-7] == ord('1'), flag_sym[12-7] == ord('3')))
s.add(flag_sym[13-7] == ord('s'))
s.add(flag_sym[15-7] == ord('s'))
s.add(Or(flag_sym[16-7] == ord('1'), flag_sym[16-7] == ord('0')))

# Rule 16, 17
for i in range(4):
    s.add(in_range(flag_sym[i], [50, 51, 53, 57, 65, 90, 97, 122]))

# Rule 18
for i in range(8-7, 8-7+5):
    s.add(flag_sym[i] != ord('3'))

# Rule 19
for i in range(16-7, 16-7+7):
    s.add(flag_sym[i] != ord('1'))

# Rule 25
s.add(Sum([sym == ord('3') for sym in flag_sym[18-7:]]) >= 2)
# Rule 27
s.add(Sum([sym == ord('m') for sym in flag_sym[21-7:]]) >= 1)
# Rule 29
s.add(flag_sym[8-7] != ord('_'))

# Rule 30
for i in range(18-7, 18-7+7):
    s.add(in_range(flag_sym[i], [48, 57, 65, 90, 97, 122]))

def exists_lit(s, lit):
    s.add(Or([
        And([flag_sym[i+j] == l for j, l in enumerate(lit)]) 
        for i in range(0, len(flag_sym) - len(lit) + 1)]
    ))

exists_lit(s, b"gEx")
exists_lit(s, b"3_")
exists_lit(s, b"x_")
exists_lit(s, b"4w")
s.add(Or([
    And([flag_sym[i] == ord('3'),  flag_sym[i+1] != ord('3')]) 
    for i in range(0, len(flag_sym) - 1)]
))
s.add(Or([
    And([flag_sym[i] != ord('3'),  flag_sym[i+1] == ord('3')]) 
    for i in range(0, len(flag_sym) - 1)]
))

s.add(flag[26] - flag[28] == 50)
s.add(flag[27] - flag[29] == 50)
s.add(flag[15] - flag[21] == 0)
s.add(flag[16] - flag[22] == 0)
s.add(flag[26] <= flag[27])

import re
p1 = re.compile(".*0.*3.*0.*3.*")
p2 = re.compile(".*1.*0.*")

while s.check() == sat:
    m = s.model()
    ss = "r3ctf{r" + "".join([chr(m[sym].as_long()) for sym in flag_sym]) + "}"
    if p1.match(ss) and p2.match(ss):
        print(ss, True)
    else:
        print(ss, False)
    s.add(Or([sym != m[sym] for sym in flag_sym]))
else:
    print("unsat")

```

求解得到：
```
r3ctf{r3gEx_1s_s0_4w3s0m3_gg55}
r3ctf{r3gEx_1s_s0_34ws0m3_gh56}
r3ctf{r3gEx_1s_s0_4w3s0m3_gh56}
r3ctf{r3gEx_1s_s0_34ws0m3_gg55}
r3ctf{r3gEx_1s_s0_34ws0m3_hh66}
r3ctf{r3gEx_1s_s0_4w3s0m3_hh66}
```
根据MD5，flag为: `r3ctf{r3gEx_1s_s0_4w3s0m3_gh56}`

