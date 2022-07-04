set pagination off

b *0x40A3D4
commands
  silent
  printf "landingPad: %x\n", $rdx
  continue
end

b _ZN18StdSubObfExceptionC2Ec
commands
  silent
  printf "selector: %x\n", $rsi
  continue
end 

define mytrace 
  break $arg0
  commands
    silent
    printf "%x\n", $pc
    python gdb.execute('continue')
  end
end
mytrace *0x409437 
mytrace *0x406443 
mytrace *0x404ab8 
mytrace *0x408031 
mytrace *0x407842 
mytrace *0x407d31 
mytrace *0x407437 
mytrace *0x407f4f 
mytrace *0x4076bd 
mytrace *0x407a6b 
mytrace *0x40723e 
mytrace *0x407fc4 
mytrace *0x409458 
mytrace *0x407bc7 
mytrace *0x40732f 
mytrace *0x407ebc 
mytrace *0x407566 
mytrace *0x407960 
mytrace *0x4070fa 
mytrace *0x405e7a 
mytrace *0x4078e3 
mytrace *0x407e5a 
mytrace *0x4074ca 
mytrace *0x405c87 
mytrace *0x407741 
mytrace *0x407af5 
mytrace *0x4072b4 
mytrace *0x405ded 
mytrace *0x4077b6 
mytrace *0x407c6b 
mytrace *0x4073a4 
mytrace *0x405b29 
mytrace *0x4075f9 
mytrace *0x407a06 
mytrace *0x4071aa 
mytrace *0x406cfe 
mytrace *0x406c94 
mytrace *0x406ef0 
mytrace *0x406859 
mytrace *0x40707d 
mytrace *0x406b62 
mytrace *0x406f5f 
mytrace *0x4065c9 
mytrace *0x406e5d 
mytrace *0x406a72 
mytrace *0x406d7b 
mytrace *0x406704 
mytrace *0x406def 
mytrace *0x406964 
mytrace *0x40944b 
mytrace *0x4064a5 
mytrace *0x405469 
mytrace *0x405a5f 
mytrace *0x404fae 
mytrace *0x40532c 
mytrace *0x40589c 
mytrace *0x404d58 
mytrace *0x4053d3 
mytrace *0x405923 
mytrace *0x404ec5 
mytrace *0x40529a 
mytrace *0x4057b8 
mytrace *0x404bc4 
mytrace *0x405f2a 
mytrace *0x4056f0 
mytrace *0x406299 
mytrace *0x4068f0 
mytrace *0x4063b0 
mytrace *0x406bf9 
mytrace *0x406323 
mytrace *0x406646 
mytrace *0x40620f 
mytrace *0x406b00 
mytrace *0x4060e7 
mytrace *0x4067bb 
mytrace *0x40617c 
mytrace *0x4069e3 
mytrace *0x40606d 
mytrace *0x406521 
mytrace *0x4051fe 
mytrace *0x405647 
mytrace *0x404e14 
mytrace *0x4055b5 
mytrace *0x4050cc 
mytrace *0x40550b 
mytrace *0x404ca4 
run
