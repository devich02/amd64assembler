    
    
__export __single_float x = 10.0

__uint8[16] arr = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

__uint8[] str = "hello, \nthis is a \"string\" %d %d %d %d %d\0"
    
__export 
__proc 
    test:
        # supports the call statement below
        sub rsp,32
jmp return
        lea rax, [arr]
        cvtsi2ss xmm0, [rax+4]

        lea rcx, [str]
        mov rdx, 1
        mov r8, 2
        mov r9, 3
        

        mov rax, printf
        call rax

return:
        add rsp,32
        ret







    