#include<stdio.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<stdlib.h>
#include<elf.h>
#include<string.h>
#include<sys/wait.h>
#include<sys/user.h>
#include<errno.h>

#define FILEPATH_LEN 100
#define SYMBOL_NAME_LEN 50
#define BUF_LEN 200

char filename[FILEPATH_LEN+1];
FILE* fp;
int child_pid;

typedef struct{
    long addr;
    long original_code;
    char name[SYMBOL_NAME_LEN+1];
}Breakpoint;

Breakpoint* breakpoints;
int bp_count;
long proc_base;

void parse_elf_file(){
    Elf64_Ehdr elf_header;
    Elf64_Shdr section_header;
    fp=fopen(filename,"r");
    if(!fp){
        printf("Failed to open ELF file!\n");
        exit(-1);
    }
    fread(&elf_header,1,sizeof(elf_header),fp);
    fseek(fp,elf_header.e_shoff,SEEK_SET);
    for(int i=0;i<elf_header.e_shnum;i++){
        fread(&section_header,1,sizeof(section_header),fp);
        if(section_header.sh_type==SHT_SYMTAB){
            Elf64_Shdr strtab_header;
            long strtab_hdr_offset = elf_header.e_shoff + section_header.sh_link*sizeof(section_header);
            fseek(fp,strtab_hdr_offset,SEEK_SET);
            fread(&strtab_header,1,sizeof(strtab_header),fp);
            fseek(fp,section_header.sh_offset,SEEK_SET);
            int entries=section_header.sh_size/section_header.sh_entsize;
            printf("Found symtab with %d entries\n",entries);
            breakpoints=malloc(entries*2*sizeof(Breakpoint));
                for(i=0;i<entries;++i){
                    Elf64_Sym symbol;
                    fread(&symbol,1,sizeof(symbol),fp);
                    if(ELF64_ST_TYPE(symbol.st_info)==STT_FUNC //is a function
                        && symbol.st_name!=0  //has name
                        && symbol.st_value!=0) {//has address within binary
                        printf("Found function at offset %lx  ",symbol.st_value);
                        long pos =ftell(fp);
                        fseek(fp,strtab_header.sh_offset+symbol.st_name,SEEK_SET);
                        breakpoints[bp_count].addr=symbol.st_value+proc_base;
                        fread(breakpoints[bp_count].name,SYMBOL_NAME_LEN,sizeof(char),fp);
                        printf("BP at %lx(%s)\n",breakpoints[bp_count].addr,breakpoints[bp_count].name);
                        fseek(fp,pos,SEEK_SET);
                        bp_count++;
                    }
                }
        }
    }
}
long get_proc_base(int pid){
	FILE *fp;
    char file_name[64]={0};
    snprintf(file_name,63,"/proc/%d/maps",pid);
	if ((fp=fopen(file_name,"r"))==NULL){
		printf("Open Failed\n");
		return 0;
	}
    long addr;
	fscanf(fp,"%lx",&addr);
	fclose(fp);
    return addr;
}
void insert_breakpoint(int i){
    breakpoints[i].original_code=ptrace(PTRACE_PEEKTEXT,child_pid,(void*)breakpoints[i].addr,0);
    ptrace(PTRACE_POKETEXT,child_pid,(void*)breakpoints[i].addr,(breakpoints[i].original_code&~0xff)|0xcc);
}
void insert_breakpoints(){
    for(int i=0;i<bp_count;++i){
        insert_breakpoint(i);
    }
}
void prepare_breakpoints(){
    parse_elf_file();
    insert_breakpoints();
}
int get_bp_ip(long addr){
    for(int i=0;i<bp_count;++i){
        if(breakpoints[i].addr==addr)return i;
    }
    return -1;
}
void trace(){
    int status;
    ptrace(PTRACE_CONT,child_pid,0,0);
    printf("Tracing started\n===\n");
    
    while(1){
        waitpid(child_pid,&status,0);
        if(WIFEXITED(status)){
            printf("\nChild finished\n");
            return;
        }
        if(WIFSTOPPED(status)){
            if(WSTOPSIG(status)==SIGTRAP){
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS,child_pid,0,&regs);
                int id=get_bp_ip(regs.rip-1);
                if(id==-1){
                    printf("Unexpected SIGTRAP %lld",regs.rip);
                    return;
                }
                else{
                    printf("%s();\n",breakpoints[id].name);
                    regs.rip=breakpoints[id].addr;
                    
                    //long ret_addr;
                    //ret_addr=ptrace(PTRACE_PEEKTEXT,child_pid,(void*)regs.rsp,0);
                    //printf("rip:%012llx rsp: %012llx rbp: %012llx ret: %012lx\n",regs.rip,regs.rsp,regs.rbp,ret_addr);
                    //breakpoints[bp_count].addr=ret_addr;
                    //snprintf(breakpoints[bp_count].name,SYMBOL_NAME_LEN,"~%s",breakpoints[id].name);
                    //printf("BK at %lx(%s)\n",breakpoints[bp_count].addr,breakpoints[bp_count].name);
                    //insert_breakpoint(bp_count++);
                    
                    ptrace(PTRACE_SETREGS,child_pid,0,&regs);//set rip
                    ptrace(PTRACE_POKETEXT,child_pid,(void*)breakpoints[id].addr,breakpoints[id].original_code);
                    ptrace(PTRACE_SINGLESTEP,child_pid,0,0);
                    wait(NULL);
                    ptrace(PTRACE_POKETEXT,child_pid,(void*)breakpoints[id].addr,(breakpoints[id].original_code&~0xff)|0xcc);
                }
            }
            if(((status>>16)&0xffff)==PTRACE_EVENT_EXIT){
                printf("\nChild finished\n");
                return;
            }
        }
        ptrace(PTRACE_CONT,child_pid,0,0);//child continue
    }
}
int main(int argc,char**argv){
    if(argc<2){
        printf("Usage: tracer elf_path\n");
        return -1;
    }
    strncpy(filename,argv[1],FILEPATH_LEN);
    child_pid=fork();
    if(child_pid==0){ //tracee
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execl(argv[1],argv[1],NULL);
        printf("Failed to execl!!\n");
        exit(-1);
    }
    else{ //tracer
        proc_base=get_proc_base(child_pid);
        printf("PID %d: %lx\n",child_pid,proc_base);   
        wait(NULL);
        prepare_breakpoints();
        trace();
        free(breakpoints);
    }
    return 0;
}