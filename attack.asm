section .rodata
	EXIT_OK		equ 0
	EXIT_ERROR	equ 1
	SYS_EXIT	equ 60
	SYS_OPEN	equ 2
	SYS_READ	equ 0
	SYS_CLOSE	equ 3
	MAGIC_CONST	equ 68020
	BUF_SIZE	equ 8192
	O_RDONLY	equ 0
	SEQ		dd  6, 8, 0, 2, 0
	MAX		equ 2147483647
	INT_SIZE 	equ 4
	ERROR_CODE	equ -1
	ARGC 		equ 2
	SEQ_LEN	equ 5

section .bss
	buf 		resb BUF_SIZE

section .text
	global _start

_start:
	; open file
	cmp	qword [rsp], ARGC			; check if argc == 2
	jne	exit_error_file_closed			; if argc != 2, exit
	mov	rdi, [rsp + 8 * ARGC]     		; mov argv[1] - filename
	pop	rax					; align stack pointer
	mov	rax, SYS_OPEN	    			; the syscall number for open()
	mov	rsi, O_RDONLY				; pass flag for read only mode
	syscall                 			; call the kernel
	cmp	rax, ERROR_CODE 			; check if error occurred
	je	exit_error_file_closed			; if so, exit
	mov	r12, rax				; save file descriptor in r12
	; file opened

	call	read_file
	call	check_size
	xor	r8, r8					; r8 == 0 indicates that integer in range (MAGIC_CONST, MAX] hasn't been found yet
	xor	r9, r9					; set number of matched elements in SEQ
	jmp	process					; process numbers from file

process:
	cmp	r10, BUF_SIZE				; check if BUF_SIZE bytes have been analyzed
	jne	continue
	call	read_file				; if not, read next part of file
continue:
	cmp	r10, r13				; check if all bytes are analyzed
	je	end					; if so, check if file contains attack signal
	mov	ecx, dword [buf + r10] 			; move next integer to register
	bswap	ecx					; reverse byte order of current integer
	cmp	ecx, MAGIC_CONST			; compare integer with banned one
	je	exit_error
	add	r14d, ecx				; add integer to sum
	add	r10, INT_SIZE				; increment number of analyzed bytes

	; match integer with element from SEQ
	cmp	r9, SEQ_LEN				; check if required sequence was found
	je	check_range				; if so, skip that part
	mov	rdx, r9
	xor	r9, r9					; go back to start of SEQ
	cmp	ecx, [SEQ]				; check if current element is equal to the first element in SEQ
	jne	compare
	mov	r9, 1					; if so, set index of element to be matched to 1
compare:
	cmp	dword [SEQ + INT_SIZE * rdx], ecx	; compare current element with next element in SEQ
	jne	check_range
	; move SEQ
	inc	rdx
	mov	r9, rdx					; increment number of elements matched with SEQ

check_range:
	cmp	r8, 1					; check if number in range (MAGIC_CONST, MAX] has been found
	je	process
	cmp	ecx, MAGIC_CONST			; check if current element is bigger than MAGIC_CONST
	jle	process
	cmp	ecx, MAX				; check if current element is less or equal than MAX
	jg	process
	mov	r8, 1					; flag that element in given range has been found
	jmp	process

; check if file contains attack signal
end:
	cmp	r9, SEQ_LEN				; check if the whole SEQ has been matched
	jne	exit_error
	cmp	r8, 1					; check if element in range (MAGIC_CONST, MAX] has been found
	jne	exit_error
	cmp	r14d, MAGIC_CONST			; check if sum == MAGIC_CONST
	jne	exit_error
	jmp	exit_ok 				; every condition is satisfied

read_file:
	mov	rdi, r12				; pass file descriptor
	mov	rsi, buf 				; pass the address of buf
	mov	rdx, BUF_SIZE				; pass the address of bufsize
	mov	rax, SYS_READ				; the syscall number for read()
	syscall 					; call the kernel
	cmp	rax, ERROR_CODE 			; check if error occurred
	je	exit_error_align 			; if so, exit
	mov	r13, rax				; save number of bytes read
	xor	r10, r10				; number of analyzed bytes
	; now file is read to array in buf
	ret

; check if number of bytes read is divisible by 4 i.e. if the file contains valid 32 bit integers
check_size:
	; calculate r13 % INT_SIZE
	xor	rdx, rdx
	mov	rax, r13
	mov	rbx, INT_SIZE
	div	rbx
	cmp	rdx, 0					; rest from division r13 / INT_SIZE is in rdx
	jne	exit_error_align
	ret

close_file:
	mov	rax, SYS_CLOSE				; the syscall number for close()
	mov	rdi, r12				; pass file descriptor
	syscall						; call the kernel
	ret

exit_error_align:
	pop rax						; align the stack pointer
exit_error:
	call	close_file
	mov	rax, SYS_EXIT				; syscall number for exit()
	mov	rdi, EXIT_ERROR 			; pass exit code
	syscall						; call the kernel

exit_error_file_closed:
	mov	rax, SYS_EXIT				; syscall number for exit()
	mov	rdi, EXIT_ERROR 			; pass exit code
	syscall						; call the kernel

exit_ok:
	call	close_file
	mov	rax, SYS_EXIT				; syscall number for exit()
	mov	rdi, EXIT_OK 				; pass exit code
	syscall						; call the kernel
