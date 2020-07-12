    
    
__export __single_float x = 10.0

__uint32[4] arr = { 1, 2, 3, 4 } 

__uint8[] str = "hello, \nthis is a \"string\"\0"
    
__export 
__proc 
    test:
        # supports the call statement below
        sub rsp,32

        lea rax, [arr]
        cvtsi2ss xmm0, [rax+4]

        lea rcx, [str]
        mov rax, printf
        call rax

        add rsp,32
        ret







    