	; ethernet II prologue: mac:6/mac:6/type:2

	ldh [12]			; ethertype
	jneq #0x800, drop	; ethertype ipv4(0x800)
	ldx #14				; %x -> ip.hdr

	; ip lvl | %x -> ip.hdr (hereinafter #E)
	ldb [%x + 0]		; ip.version == 4, ip.ihl >= 5
	jle #0x45, drop     ; <= 45
	jgt #0x4f, drop     ;  > 4f

	ret  #-1
drop:	ret #0
