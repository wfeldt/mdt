;
; libio.asm
;
; A very minimalistic libc.
;
; Copyright (c) 2008 Steffen Winterfeldt.
;
; For details see file COPYING.
;

		bits 16

; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; interface functions
;
; Make sure not to modify registers!
;

		global printf
		global getchar
		global clrscr
		global memcpy
		global memset
		global x86int

		global _start
		extern _main

		section .init

_start:
		cld
%ifdef BIN
		jmp 0x7c0:_start_10
_start_10:
		mov ax,cs
		mov ss,ax
		xor esp,esp
		mov ds,ax
		mov es,ax
		mov fs,ax
		mov gs,ax
		sti
		call dword _main
		push word 40h
		pop es
		mov word [es:72h],1234h
		jmp 0ffffh:0

%else
		call dword _main
		mov ah,4ch
		int 21h
%endif

		section .text

; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Write text to console.
;
; args on stack
;
; Note: 32 bit call/ret!
;
printf:
		mov [pf_args],sp

		pushad

		call pf_next_arg
		call pf_next_arg
		mov si,ax
printf_10:
		lodsb
		or al,al
		jz printf_90
		cmp al,'%'
		jnz printf_70
		mov byte [pf_pad],' '
		lodsb
		dec si
		cmp al,'0'
		jnz printf_20
		mov [pf_pad],al
printf_20:
		call get_number
		mov [pf_num],ecx
		lodsb
		or al,al
		jz printf_90
		cmp al,'%'
		jz printf_70

		cmp al,'S'
		jnz printf_23
		mov byte [pf_raw_char],1
		jmp printf_24
printf_23:
		cmp al,'s'
		jnz printf_30
printf_24:
		push si

		call pf_next_arg
		mov si,ax
		call puts

		sub ecx,[pf_num]
		neg ecx
		mov al,' '
		call putc_n

		pop si

		mov byte [pf_raw_char],0
		jmp printf_10

printf_30:		
		cmp al,'u'
		jnz printf_35

		mov dx,10
printf_31:
		push si

		call pf_next_arg
		or dh,dh
		jz printf_34
		test eax,eax
		jns printf_34
		neg eax
		push eax
		mov al,'-'
		call putc
		pop eax
printf_34:
		mov cl,[pf_num]
		mov ch,[pf_pad]
		call number
		call puts

		pop si

		jmp printf_10

printf_35:
		cmp al,'x'
		jnz printf_36

printf_35a:
		mov dx,10h
		jmp printf_31

printf_36:
		cmp al,'d'
		jnz printf_37
printf_36a:
		mov dx,10ah
		jmp printf_31

printf_37:
		cmp al,'i'
		jz printf_36a

		cmp al,'p'
		jnz printf_40
		mov al,'0'
		call putc
		mov al,'x'
		call putc
		jmp printf_35a

printf_40:
		cmp al,'c'
		jnz printf_45

		push si
		call pf_next_arg
		call putc
		pop si
		jmp printf_10
printf_45:

		; more ...
		

printf_70:
		call putc
		jmp printf_10
printf_90:		
		popad

		o32 ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Get next printf arg from [pf_args].
;
; return:
;  eax		arg
;
; changes no regs
;
pf_next_arg:
		movzx eax,word [pf_args]
		add word [pf_args],4
		mov eax,[eax]
		ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Convert string to number.
;
;  si		string
;
; return:
;  ecx		number
;  si		points past number
;  CF		not a number
;
get_number:

		xor ecx,ecx
		mov ah,1
get_number_10:
		lodsb
		or al,al
		jz get_number_90
		sub al,'0'
		jb get_number_90
		cmp al,9
		ja get_number_90
		movzx eax,al
		imul ecx,ecx,10
		add ecx,eax
		jmp get_number_10
get_number_90:
		dec si
		shr ah,1
		ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Convert a number to string.
;
;  eax		number
;  cl		field size
;  ch		padding char
;  dl		base
;
; return:
;  si		string
;
number:
		mov di,num_buf
		push ax
		push cx
		mov al,ch
		mov cx,num_buf_end - num_buf
		rep stosb
		pop cx
		pop ax
		movzx cx,cl
		movzx ebx,dl
number_10:
		xor edx,edx
		div ebx
		cmp dl,9
		jbe number_20
		add dl,27h
number_20:
		add dl,'0'
		dec edi
		mov [di],dl
		or eax,eax
		jz number_30
		cmp di,num_buf
		ja number_10
number_30:
		mov si,di
		or cx,cx
		jz number_90
		cmp cx,num_buf_end - num_buf
		jae number_90
		mov si,num_buf_end
		sub si,cx
number_90:
		ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Write string.
;
;  si		text
;
; return:
;  cx		length
;
puts:
		xor cx,cx
puts_10:
		lodsb
		or al,al
		jz puts_90
		call putc
		inc cx
		jmp puts_10
puts_90:
		ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Write char multiple times.
;
;  al		char
;  cx		count (does nothing if count <= 0)
;
putc_n:
		cmp cx,0
		jle putc_n_90
		call putc
		dec cx
		jmp putc_n
putc_n_90:
		ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Print char.
;
;  al		char
;
putc:
		pusha
		cmp al,0ah
		jnz putc_30
		push ax
		mov al,0dh
		call putc_50
		pop ax
putc_30:
		call putc_50
		popa
		ret
putc_50:
		mov bx,7
		mov ah,0eh
		int 10h
		ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Read char from stdin.
;
; return:
;  eax		char
;
; Note: 32 bit call/ret!
;
getchar:
		pushad
		mov ah,10h
		int 16h
		mov [gc_tmp],al
		popad
		movzx eax,byte [gc_tmp]
		o32 ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; Clear screen.
;
; Note: 32 bit call/ret!
;
clrscr:
		pushad
		push es
		push word 40h
		pop es
		mov ax,600h
		mov bh,7
		xor cx,cx
		mov dl,[es:4ah]
		or dl,dl
		jnz clrscr_20
		mov dl,80
clrscr_20:
		dec dl
		mov dh,[es:84h]
		or dh,dh
		jnz clrscr_30
		mov dh,24
clrscr_30:
		int 10h
		mov ah,2
		mov bh,[es:62h]
		xor dx,dx
		int 10h
		pop es
		popad
		o32 ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; dst = memcpy(dst, src, size).
;
; args on stack
;
; return:
;  eax		dst
;
; Note: 32 bit call/ret!
;
memcpy:
		pushad

		mov edi,[esp+0x20+4]
		mov esi,[esp+0x20+8]
		mov ecx,[esp+0x20+12]

		rep movsb

		popad

		mov eax,[esp+4]

		o32 ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; dst = memset(dst, val, size).
;
; args on stack
;
; return:
;  eax		dst
;
; Note: 32 bit call/ret!
;
memset:
		pushad

		mov edi,[esp+0x20+4]
		mov eax,[esp+0x20+8]
		mov ecx,[esp+0x20+12]

		rep stosb

		popad

		mov eax,[esp+4]

		o32 ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
; x86int(int, *regs).
;
; args on stack
;
; Note: 32 bit call/ret!
;
x86int:
		pushad

		mov al,[esp+0x20+4]
		mov [x86int_p],al
		mov ebx,[esp+0x20+8]

		mov ecx,[bx+8]
		mov edx,[bx+0ch]
		mov esi,[bx+10h]
		mov edi,[bx+14h]
		mov ebp,[bx+18h]
		mov ah,[bx+1ch]		; eflags
		sahf
		mov eax,[bx]
		mov ebx,[bx+4]

		int 0h
x86int_p	equ $-1

		push ebx
		mov ebx,[esp+0x24+8]
		pop dword [cs:bx+4]

		mov [cs:bx],eax

		mov ax,cs
		mov ds,ax
		mov es,ax
		mov fs,ax
		mov gs,ax

		mov [bx+8],ecx
		mov [bx+0ch],edx
		mov [bx+10h],esi
		mov [bx+14h],edi
		mov [bx+18h],ebp
		pushfd
		pop dword [bx+1ch]

		popad

		o32 ret


; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
		section .data

; buffer for number conversions
; must be large enough for ps_status_info()
num_buf		times 23h db 0
num_buf_end	db 0

; temp data for printf
pf_args		dw 0
pf_num		dd 0
pf_sig		db 0
pf_pad		db 0
pf_raw_char	db 0
gc_tmp		db 0

