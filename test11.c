#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/kernel.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <strings.h>
#include <time.h>

#define CHECK(x) ({int err = (x); \
if (err) { \
fprintf(stderr, "%s: Failed with %d on line %d of file %s\n", strerror(errno), err, __LINE__, __FILE__); \
exit(-1); }\
err;})

#define PEBS_SAMPLE_TYPE PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_CALLCHAIN
#define WATCH_SAMPLE_TYPE PERF_SAMPLE_IP |  PERF_SAMPLE_ADDR | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_CPU
//| PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_CALLCHAIN

//******************************************* Workload to test *******************************************************************
/* Test example starts */
#define MATRIX_SIZE 512
static double a[MATRIX_SIZE][MATRIX_SIZE];
static double b[MATRIX_SIZE][MATRIX_SIZE];
static double c[MATRIX_SIZE][MATRIX_SIZE];

static void naive_matrix_multiply(int quiet) {

  double s;
  int i,j,k;

  for(i=0;i<MATRIX_SIZE;i++) {
    for(j=0;j<MATRIX_SIZE;j++) {
      a[i][j]=(double)i*(double)j;
      b[i][j]=(double)i/(double)(j+5);
    }
  }
  for(j=0;j<MATRIX_SIZE;j++) {
     for(i=0;i<MATRIX_SIZE;i++) {
        s=0;
        for(k=0;k<MATRIX_SIZE;k++) {
           s+=a[i][k]*b[k][j];
        }
        c[i][j] = s;
     }
  }
  s=0.0;
  for(i=0;i<MATRIX_SIZE;i++) {
    for(j=0;j<MATRIX_SIZE;j++) {
      s+=c[i][j];
    }
  }

  if (!quiet) printf("Matrix multiply sum: s=%lf\n",s);

  return;
}

//open and close a file. calls naive MM
static void workload1(int count)
{
	FILE *fp;
        char buffer[] = { 'x' , 'y' , 'z', 'a', 'b' };
	while(count--)
	{
                fp = fopen("dummy.txt", "wb");
                if(fp == NULL)
                {
                         printf("Error opening file\n");
                         exit(1);
                }
         //       naive_matrix_multiply(1);

                fwrite(buffer, sizeof(char), sizeof(buffer), fp);
                fclose(fp);
      }
}
//******************************************************* perf events  *******************************************************************
static int pgsz;

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
  int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
     group_fd, flags);
    return ret;
}
static char * mmapBuffer;
static char * mmapBufferBP;
#define NUM_MMAP_PAGES 8
#define RAW_NONE        0
static long long prev_head;
static long long prev_headBP;
static inline char * mmap_wp_buffer(int fd){
    char * buf = mmap(NULL, (1+NUM_MMAP_PAGES) * pgsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
                perror("mmap");
                exit(-1);
    }
    return buf;
}

static inline void unmap_wp_buffer(void * buf){
    CHECK(munmap(buf, (1+NUM_MMAP_PAGES) * pgsz));
}
void createBP(unsigned long addr);

//*********************************************************** Main ****************************************************************************
int
main(int argc, char **argv)
{
	long long count = 10;
	int fd;
	FILE *fp;

        char buffer[] = { 'x' , 'y' , 'z' };

       struct perf_event_attr pe = {
        .type                   = PERF_TYPE_RAW,
        .size                   = sizeof(struct perf_event_attr),
        .sample_period          = 1003,
        .sample_type            = PEBS_SAMPLE_TYPE,
        .exclude_user           = 1,
        .exclude_kernel         = 0,
        .exclude_hv             = 1,
        .disabled               = 0, /* enabled */
        .config                 = 0x1cd,	//
        .config1                = 0x3,
        .precise_ip             = 3,
        .read_format            = PERF_FORMAT_GROUP | PERF_FORMAT_ID,
        .task                   = 1,
	.watermark              = 1,
        .wakeup_events          = 1,

       };


	pgsz = getpagesize();

	// setting up to do PEBS sampling
        fd = perf_event_open(&pe, 0, -1, -1, 0);
    	if (fd == -1) {
		fprintf(stderr, "Error opening leader %llx\n", pe.config);
		exit(EXIT_FAILURE);
    	}

    	// mmap the file 
    	mmapBuffer = mmap_wp_buffer(fd);

	prev_head = 0;

	//running in a loop
	int outerLoop = 1000;
	while(outerLoop--)
	{

	    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	    ioctl(fd, PERF_EVENT_IOC_REFRESH, 1); //setting to disable after 1 sample
	
	    //whorload
	    workload1(30);

 	    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    	    unsigned long addr = 0;

	    //reading the collected sample
	    int quiet = 0;
    	    prev_head = perf_mmap_read(mmapBuffer, NUM_MMAP_PAGES, prev_head,
	            	    PEBS_SAMPLE_TYPE, 0, 0,
                		NULL, quiet, NULL, RAW_NONE, &addr);
    	    //picking last address
	    printf("sampled address %llx\n", addr);

	    // validate the address by calling PERF_EVENT_IOC_VALIDATE_ATTRIBUTES ioctl
	    // for now we are ignoring any stack address
	    // check 1) whether in stack (thread, interrupt, exception, debug stack)
	    // 2) and virt_addr_valid

	    if(0==ioctl(fd, PERF_EVENT_IOC_VALIDATE_ATTRIBUTES, addr))
			printf("valid address\n");
	    else
	    {
			printf("An Invalid address: check kern.log for details\n");	
			continue;
	    }
	    
	    //upto this point, addr must be a valid address.
	    //XXX	But debug register at "Low Memory" causing freeze 
	    // low memory region 0xffff96cf80000000 - 0xffffabbdc0000000
	    if(addr==0 || (addr <= 0xffffabbdc0000000 && addr >= 0xffff96cf80000000))
	    {
	    		printf("BLACKLISTED Region ------------------------->\n");
                        continue;
	    }

	    //calling to set BP
	    createBP(addr);
	}

        close(fd);
        unmap_wp_buffer(mmapBuffer);
        mmapBuffer = 0;
}

//************************************************ setting a debug register **********************************
void createBP(unsigned long addr)
{

	struct perf_event_attr pe = {
        .type                   = PERF_TYPE_BREAKPOINT,
        .size                   = sizeof(struct perf_event_attr),
        .bp_type                = HW_BREAKPOINT_W | HW_BREAKPOINT_R,
        .bp_len                 = HW_BREAKPOINT_LEN_1,
           .bp_addr = (uintptr_t) addr,
        .sample_period          = 1,
        .sample_type            = WATCH_SAMPLE_TYPE,
        .exclude_user           = 1,
        .disabled               = 0, /* enabled */
	.watermark 		= 1,
	.wakeup_events 		= 1,
    };

	int perf_fd = perf_event_open(&pe, 0, -1, -1 /*group*/, 0);
	if (perf_fd == -1) {
            perror("perf_event_open");
                  exit (-1);
	}

	mmapBufferBP = mmap_wp_buffer(perf_fd);
    
	prev_headBP = 0;
	ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
 	//   ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    	ioctl(perf_fd, PERF_EVENT_IOC_REFRESH, 1);
	
	//workload
	workload1(5);
	
	unsigned long addrBP = 0;
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        
	prev_headBP = perf_mmap_read(mmapBufferBP, NUM_MMAP_PAGES, prev_headBP,
             WATCH_SAMPLE_TYPE, 0, 0,
              NULL, 0, NULL, RAW_NONE, &addrBP);
        printf("sampled address BP ++++++++++++++++%llx \n", addrBP);
        
	close(perf_fd);
        unmap_wp_buffer(mmapBufferBP);
        mmapBufferBP = 0;    
}
