#include "command.h"

const char *command_break = "break";
const char *command_b = "b";
const char *command_cont = "cont";
const char *command_c = "c";
const char *command_delete = "delete";
const char *command_disasm = "disasm";
const char *command_d = "d";
const char *command_dump = "dump";
const char *command_x = "x";
const char *command_get = "get";
const char *command_g = "g";
const char *command_getregs = "getregs";
const char *command_help = "help";
const char *command_h = "h";
const char *command_list = "list";
const char *command_l = "l";
const char *command_load = "load";
const char *command_run = "run";
const char *command_r = "r";
const char *command_vmmap = "vmmap";
const char *command_m = "m";
const char *command_set = "set";
const char *command_s = "s";
const char *command_si = "si";
const char *command_start = "start";
const char *command_exit = "exit";
const char *command_q = "q";

const char *help_meg = "- break {instruction-address}: add a break point \n- cont: continue execution \n- delete {break-point-id} : remove a break point \n- disasm addr: disassemble instructions in a file or a memory region \n- dump addr: dump memory content \n- exit: terminate the debugger \n- get reg: get a single value from a register \n- getregs: show registers \n- help: show this message \n- list: list break points \n- load{path/to/ a/program}: load a program \n- run : run the program \n- vmmap: show memory layout \n- set reg val: get a single value to a register \n- si: step into instruction \n- start: start the program and stop at the first instruction\n";

void status_init(current_status *status)
{
    // status->load = false;
    status->run = false;
    // memset(status->file, 0, MAX_LENGTH);
    status->child = 0;
    // status->regs;
    // status->bps;
    // status->bp_num = 0;
    // status->offset = 0;
    // status->entry_point = 0;
}

int check_command_2(char *command[], int num_input, const char *ins, const char *ins_2)
{
    int ret = strncmp(command[0], ins, strlen(ins));
    int ret_2 = strncmp(command[0], ins_2, strlen(ins_2));
    if (ret == 0 && strlen(ins) == strlen(command[0]))
    {
        return 1;
    }
    else if (ret_2 == 0 && strlen(ins_2) == strlen(command[0]))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int check_command(char *command[], int num_input, const char *ins)
{
    int ret = strncmp(command[0], ins, strlen(ins));
    if (ret == 0 && strlen(ins) == strlen(command[0]))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void read_elf_header(current_status *status, const char *elfFile)
{
    ElfW(Ehdr) header;
    FILE *file = fopen(elfFile, "rb");
    if (file)
    {
        fread(&header, sizeof(header), 1, file);
        if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0)
        {
            status->entry_point = header.e_entry;
            status->offset = header.e_phoff;
        }
        fclose(file);
    }
    // perror("fopen");
}

void ptrace_load(char *file, current_status *status)
{
    read_elf_header(status, file);
    strcpy(status->file, file);
    status->load = true;
    printf("** program '%s' loaded. entry point %p\n", file, status->entry_point);
}

void ptrace_vmmap(current_status *status)
{
    char path[MAX_LENGTH];
    sprintf(path, "/proc/%d/maps", status->child);
    FILE *maps = fopen(path, "r");
    unsigned long long addr, endaddr, offset, inode;
    char premission[4], device[MAX_LENGTH], filepath[MAX_LENGTH], buf[MAX_LENGTH];
    while (true)
    {
        int ret = fscanf(maps, "%llx-%llx %s %llx %s %llx", &addr, &endaddr, premission, &offset, device, &inode);
        if (ret == EOF)
        {
            break;
        }
        if (ret >= 0 && ret != EOF && inode != 0)
        {
            fscanf(maps, "%s\n", filepath);
        }
        else
        {
            filepath[0] = '\0';
            fgets(buf, MAX_LENGTH, maps);
            sscanf(buf, "%s\n", filepath);
        }
        premission[3] = '\0';
        printf("%016llx-%016llx %s %-7lld %s\n", addr, endaddr, premission, offset, filepath);
    }
    return;
}

int find_bp_info(current_status *status)
{
    for (int i = 0; i < status->bps.size(); i++)
    {
        if (status->regs.rip - 1 == status->bps[i].b_point)
        {
            return i;
        }
    }
    // printf("Can't find the bp info.\n");
    return -1;
}

int find_bp_info_si(current_status *status)
{
    for (int i = 0; i < status->bps.size(); i++)
    {
        if (status->regs.rip == status->bps[i].b_point)
        {
            return i;
        }
    }
    // printf("Can't find the bp info.\n");
    return -1;
}

void print_instruction(long long addr, instruction1 *in)
{
    int i;
    char bytes[128] = "";
    if (in == NULL)
    {
        fprintf(stderr, "%12llx:\t<cannot disassemble>\n", addr);
    }
    else
    {
        for (i = 0; i < in->size; i++)
        {
            snprintf(&bytes[i * 3], 4, "%2.2x ", in->bytes[i]);
        }
        fprintf(stderr, "%12llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
    }
}

void ptrace_delete(current_status *status, char *point)
{
    int del_b_point = strtol(point, NULL, 10);
    if (del_b_point < status->bp_num)
    {
        unsigned long long a = ptrace(PTRACE_PEEKTEXT, status->child, status->bps[del_b_point].b_point, 0);
        unsigned long long restore_code = ((a & 0xffffffffffffff00) | (status->bps[del_b_point].code & 0xff));
        if (ptrace(PTRACE_POKETEXT, status->child, status->bps[del_b_point].b_point, restore_code) != 0)
            perror("ptrace(cont.POKETEXT)");
        status->bps.erase(status->bps.begin() + del_b_point);
        status->bp_num--;
    }
    else
    {
        printf("Can't find the break_point\n");
    }
}

std::vector<bp_list> bp_restore(current_status *status)
{
    std::vector<bp_list> bps_backup = status->bps;
    for (int i = bps_backup.size() - 1; i >= 0; i--)
    {
        char c = i + '0';
        ptrace_delete(status, &c);
    }
    return bps_backup;
}

void bp_restore_2(current_status *status, std::vector<bp_list> bps_backup)
{
    int len = bps_backup.size();
    for (int i = 0; i < len; i++)
    {
        bp_list temp;
        temp.b_point = bps_backup[i].b_point;
        temp.code = ptrace(PTRACE_PEEKTEXT, status->child, temp.b_point, 0);
        if (ptrace(PTRACE_POKETEXT, status->child, temp.b_point, (temp.code & 0xffffffffffffff00) | 0xcc) != 0)
        {
            perror("ptrace(break.POKETEXT)");
        }
        status->bps.push_back(temp);
        status->bp_num++;
    }
}

void ptrace_disasm(current_status *status, unsigned long long addr, const char *type)
{
    cs_insn *insn;
    csh cshandle;
    int count;
    char buf[64] = {0};
    std::map<long long, instruction1>::iterator mi;
    unsigned long long ptr = addr;
    std::vector<bp_list> bps_backup;
    if (strncmp(type, "disasm", 6) == 0)
    {
        bps_backup = bp_restore(status);
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
        perror("cs_open");

    for (ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE)
    {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, status->child, ptr, NULL);
        if (errno != 0)
            break;
        memcpy(&buf[ptr - addr], &peek, PEEKSIZE);
    }

    if ((count = cs_disasm(cshandle, (uint8_t *)buf, addr - ptr, addr, 0, &insn)) > 0)
    {
        int real_count;
        for (int i = 0; i < count; i++)
        {
            instruction1 in;
            in.size = insn[i].size;
            in.opr = insn[i].mnemonic;
            in.opnd = insn[i].op_str;
            memcpy(in.bytes, insn[i].bytes, insn[i].size);
            instructions[insn[i].address] = in;
            if (strncmp(in.opr.c_str(), "ret", 3) == 0)
            {
                real_count = i + 1;
                break;
            }
        }
        if (strncmp(type, "disasm", 6) == 0)
        {
            for (int i = 0; i < real_count; i++)
            {
                print_instruction(insn[i].address, &(instructions.find(insn[i].address))->second);
                if (i > DISASM_LENGTH - 1)
                {
                    return;
                }
            }
            if (real_count < 10 && real_count != 0)
            {
                printf("** the address is out of the range of the text segment\n");
            }
            bp_restore_2(status, bps_backup);
            return;
        }
        cs_free(insn, count);
    }
    if (strncmp(type, "bp", 2) == 0)
    {
        if ((mi = instructions.find(addr)) != instructions.end())
        {
            print_instruction(addr, &mi->second);
        }
        else
        {
            print_instruction(addr, NULL);
        }
    }
    cs_close(&cshandle);
}

void after_waitpid(current_status *status)
{
    int sta;
    waitpid(status->child, &sta, 0);
    if (WIFEXITED(sta))
    {
        printf("** child process %d terminiated normally (code 0)\n", status->child);
        status_init(status);
    }
    else if (WIFSTOPPED(sta))
    {
        if (ptrace(PTRACE_GETREGS, status->child, 0, &(status->regs)) != 0)
            perror("ptrace(cont.GETREGS)");
        int bp_idx = find_bp_info(status);
        if (bp_idx >= 0)
        {
            unsigned long long a = ptrace(PTRACE_PEEKTEXT, status->child, status->bps[bp_idx].b_point, 0);
            unsigned long long restore_code = ((a & 0xffffffffffffff00) | (status->bps[bp_idx].code & 0xff));
            if (ptrace(PTRACE_POKETEXT, status->child, status->bps[bp_idx].b_point, restore_code) != 0)
                perror("ptrace(cont.POKETEXT)");
            status->regs.rip = status->regs.rip - 1;
            if (ptrace(PTRACE_SETREGS, status->child, 0, &(status->regs)) != 0)
                perror("ptrace(cont.SETREGS)");
            fprintf(stderr, "** breakpoint @");
            ptrace_disasm(status, status->bps[bp_idx].b_point, "bp");
        }
    }
}

void ptrace_start(current_status *status)
{
    pid_t child;
    if ((child = fork()) == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            perror("ptrace");
        char *tmp[2];
        memset(tmp, 0, sizeof(tmp));
        tmp[0] = status->file;
        if (execvp(status->file, tmp) < 0)
        {
            perror("execvp");
            exit(1);
        }
    }
    else
    {
        status->child = child;
        int child_sta;
        if (waitpid(child, &child_sta, 0) < 0)
            perror("waitpid");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        printf("** pid %d\n", status->child);
    }
}

void ptrace_cont(current_status *status)
{
    if (ptrace(PTRACE_CONT, status->child, 0, 0) < 0)
        perror("cont");
    after_waitpid(status);
}

void get_regval(struct user_regs_struct regs, char *name)
{
    if (strncmp(name, "r15", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r15, regs.r15);
    }
    else if (strncmp(name, "r14", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r14, regs.r14);
    }
    else if (strncmp(name, "r13", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r13, regs.r13);
    }
    else if (strncmp(name, "r12", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r12, regs.r12);
    }
    else if (strncmp(name, "rbp", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rbp, regs.rbp);
    }
    else if (strncmp(name, "rbx", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rbx, regs.rbx);
    }
    else if (strncmp(name, "r11", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r11, regs.r11);
    }
    else if (strncmp(name, "r10", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r10, regs.r10);
    }
    else if (strncmp(name, "r9", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r9, regs.r9);
    }
    else if (strncmp(name, "r8", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.r8, regs.r8);
    }
    else if (strncmp(name, "rax", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rax, regs.rax);
    }
    else if (strncmp(name, "rcx", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rcx, regs.rcx);
    }
    else if (strncmp(name, "rdx", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rdx, regs.rdx);
    }
    else if (strncmp(name, "rsi", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rsi, regs.rsi);
    }
    else if (strncmp(name, "rdi", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rdi, regs.rdi);
    }
    else if (strncmp(name, "flags", 5) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.eflags, regs.eflags);
    }
    else if (strncmp(name, "rsp", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rsp, regs.rsp);
    }
    else if (strncmp(name, "rip", 3) == 0)
    {
        printf("%s = %lld (0x%llx)\n", name, regs.rip, regs.rip);
    }
    else
    {
        printf("can't get %s\n", name);
    }
}

void get_allregs(struct user_regs_struct regs)
{
    printf("RAX %-14llx RBX %-14llx RCX %-14llx RDX %-14llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("R8  %-14llx R9  %-14llx R10 %-14llx R11 %-14llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12 %-14llx R13 %-14llx R14 %-14llx R15 %-14llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RDI %-14llx RSI %-14llx RBP %-14llx RSP %-14llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    printf("RIP %-14llx FLAGS %016llx\n", regs.rip, regs.eflags);
}

void ptrace_get(current_status *status, char *name)
{
    if (ptrace(PTRACE_GETREGS, status->child, NULL, &(status->regs)) < 0)
    {
        perror("ptrace");
    }
    if (strncmp(name, "all", 3) != 0)
    {
        get_regval(status->regs, name);
    }
    else
    {
        get_allregs(status->regs);
    }
}

void ptrace_break(current_status *status, char *point)
{
    bp_list temp;
    temp.b_point = strtol(point, NULL, 16);
    temp.code = ptrace(PTRACE_PEEKTEXT, status->child, temp.b_point, 0);
    if (ptrace(PTRACE_POKETEXT, status->child, temp.b_point, (temp.code & 0xffffffffffffff00) | 0xcc) != 0)
    {
        perror("ptrace(break.POKETEXT)");
        return;
    }
    status->bps.push_back(temp);
    status->bp_num++;
}

void ptrace_set(current_status *status, char *param, char *val)
{
    unsigned long long change_val = strtol(val, NULL, 16);
    if (ptrace(PTRACE_GETREGS, status->child, 0, &(status->regs)) != 0)
        perror("ptrace(cont.GETREGS)");

    if (strncmp(param, "r15", 3) == 0)
    {
        status->regs.r15 = change_val;
    }
    else if (strncmp(param, "r14", 3) == 0)
    {
        status->regs.r14 = change_val;
    }
    else if (strncmp(param, "r13", 3) == 0)
    {
        status->regs.r13 = change_val;
    }
    else if (strncmp(param, "r12", 3) == 0)
    {
        status->regs.r12 = change_val;
    }
    else if (strncmp(param, "rbp", 3) == 0)
    {
        status->regs.rbp = change_val;
    }
    else if (strncmp(param, "rbx", 3) == 0)
    {
        status->regs.rbx = change_val;
    }
    else if (strncmp(param, "r11", 3) == 0)
    {
        status->regs.r11 = change_val;
    }
    else if (strncmp(param, "r10", 3) == 0)
    {
        status->regs.r10 = change_val;
    }
    else if (strncmp(param, "r9", 3) == 0)
    {
        status->regs.r9 = change_val;
    }
    else if (strncmp(param, "r8", 3) == 0)
    {
        status->regs.r8 = change_val;
    }
    else if (strncmp(param, "rax", 3) == 0)
    {
        status->regs.rax = change_val;
    }
    else if (strncmp(param, "rcx", 3) == 0)
    {
        status->regs.rcx = change_val;
    }
    else if (strncmp(param, "rdx", 3) == 0)
    {
        status->regs.rdx = change_val;
    }
    else if (strncmp(param, "rsi", 3) == 0)
    {
        status->regs.rsi = change_val;
    }
    else if (strncmp(param, "rdi", 3) == 0)
    {
        status->regs.rdi = change_val;
    }
    else if (strncmp(param, "flags", 5) == 0)
    {
        status->regs.eflags = change_val;
    }
    else if (strncmp(param, "rsp", 3) == 0)
    {
        status->regs.rsp = change_val;
    }
    else if (strncmp(param, "rip", 3) == 0)
    {
        status->regs.rip = change_val;
        std::vector<bp_list> bps_backup;
        bps_backup = bp_restore(status);
        bp_restore_2(status, bps_backup);
    }
    else
    {
        printf("can't get %s\n", param);
    }

    if (ptrace(PTRACE_SETREGS, status->child, NULL, &(status->regs)) != 0)
        perror("ptrace(cont.SETREGS)");
}

void ptrace_dump(current_status *status, unsigned long long addr)
{
    unsigned char buf[DUMPSIZE];
    for (int i = 0; i < DUMPSIZE / 16; i++)
    {
        printf("%12llx: ", addr);
        for (int b = 0; b < 16; b++)
        {
            buf[16 * i + b] = ptrace(PTRACE_PEEKDATA, status->child, addr, NULL);
            addr++;
            printf("%02x ", buf[16 * i + b]);
        }
        printf("|");
        for (int b = 0; b < 16; b++)
        {
            if (isprint(buf[16 * i + b]) != 0)
            {
                printf("%c", buf[16 * i + b]);
            }
            else
            {
                printf(".");
            }
        }
        printf("|\n");
    }
}
int run_command(char *input, current_status *status)
{
    char buf[MAX_LENGTH];

    char *command[MAX_LENGTH];
    const char *delim = " ";
    strcpy(buf, input);
    char *substr = strtok(buf, delim);
    int num_input = 0;
    while (substr)
    {
        command[num_input] = substr;
        num_input++;
        substr = strtok(NULL, delim);
    }
    if (num_input == 1)
    {
        if (check_command_2(command, num_input, command_exit, command_q))
        {
            exit(EXIT_SUCCESS);
        }
        else if (check_command_2(command, num_input, command_help, command_h))
        {
            printf("%s", help_meg);
            return 0;
        }
        else if (check_command_2(command, num_input, command_cont, command_c))
        {
            if (status->run == false)
            {
                printf("** Program is not running, can't cont\n");
                return 0;
            }
            else
            {
                ptrace_cont(status);
                return 0;
            }
        }
        else if (check_command(command, num_input, command_start))
        {
            if (status->load == true && status->run == false)
            {
                ptrace_start(status);
                status->run = true;
                if (status->bps.size() != 0)
                {
                    for (int i = 0; i < status->bps.size(); i++)
                    {
                        if (ptrace(PTRACE_POKETEXT, status->child, status->bps[i].b_point, (status->bps[i].code & 0xffffffffffffff00) | 0xcc) != 0)
                        {
                            perror("ptrace(break.POKETEXT)");
                        }
                    }
                }
                return 0;
            }
            else if (status->load == false)
            {
                printf("** Program is not loaded, can't start\n");
                return 0;
            }
        }
        else if (check_command(command, num_input, command_si))
        {
            if (status->load == true && status->run == true)
            {
                if (ptrace(PTRACE_SINGLESTEP, status->child, NULL, NULL) < 0)
                    perror("si");
                int sta;
                waitpid(status->child, &sta, 0);
                if (WIFEXITED(sta))
                {
                    printf("** child process %d terminiated normally (code 0)\n", status->child);
                    status_init(status);
                }
                else if (WIFSTOPPED(sta))
                {
                    if (ptrace(PTRACE_GETREGS, status->child, 0, &(status->regs)) != 0)
                        perror("ptrace(cont.GETREGS)");
                    int bp_idx = find_bp_info_si(status);
                    if (bp_idx >= 0)
                    {
                        unsigned long long a = ptrace(PTRACE_PEEKTEXT, status->child, status->bps[bp_idx].b_point, 0);
                        unsigned long long restore_code = ((a & 0xffffffffffffff00) | (status->bps[bp_idx].code & 0xff));
                        if (ptrace(PTRACE_POKETEXT, status->child, status->bps[bp_idx].b_point, restore_code) != 0)
                            perror("ptrace(cont.POKETEXT)");
                        /*status->regs.rip = status->regs.rip - 1;
                        if (ptrace(PTRACE_SETREGS, status->child, 0, &(status->regs)) != 0)
                            perror("ptrace(cont.SETREGS)");*/
                        fprintf(stderr, "** breakpoint @");
                        ptrace_disasm(status, status->bps[bp_idx].b_point, "bp");
                    }
                }

                return 0;
            }
            else
            {
                printf("** Program is not running, can't si\n");
                return 0;
            }
        }
        else if (check_command_2(command, num_input, command_vmmap, command_m))
        {
            if (status->run == false)
            {
                printf("** Program is not running, can't vmmap\n");
                return 0;
            }
            else
            {
                ptrace_vmmap(status);
                return 0;
            }
        }
        else if (check_command_2(command, num_input, command_run, command_r))
        {
            if (status->load == false)
            {
                printf("** Program is not loaded, can't run\n");
                return 0;
            }
            else if (status->load == true && status->run == false)
            {
                ptrace_start(status);
                status->run = true;
                if (status->bps.size() != 0)
                {
                    for (int i = 0; i < status->bps.size(); i++)
                    {
                        if (ptrace(PTRACE_POKETEXT, status->child, status->bps[i].b_point, (status->bps[i].code & 0xffffffffffffff00) | 0xcc) != 0)
                        {
                            perror("ptrace(break.POKETEXT)");
                        }
                    }
                }
                ptrace_cont(status);
                return 0;
            }
            else if (status->load == true && status->run == true)
            {
                printf("** program %s is already running\n", status->file);
                ptrace_cont(status);
                return 0;
            }
        }
        else if (check_command(command, num_input, command_getregs))
        {
            if (status->run == true)
            {
                ptrace_get(status, "all");
            }
            else
            {
                printf("** Program is not running, can't getregs\n");
            }
        }
        else if (check_command_2(command, num_input, command_list, command_l))
        {
            for (int i = 0; i < status->bp_num; i++)
            {
                printf("%3d:  %llx\n", i, status->bps[i].b_point);
            }
        }
        else if (check_command(command, num_input, command_disasm) || check_command(command, num_input, command_d))
        {
            printf("** no addr is given.\n");
        }
        else if (check_command_2(command, num_input, command_dump, command_x))
        {
            printf("** no addr is given.\n");
        }
    }

    else if (num_input == 2)
    {
        if (check_command(command, num_input, command_load))
        {
            if (status->load == false)
            {
                ptrace_load(command[num_input - 1], status);
                return 0;
            }
            else
            {
                printf("** Program is loaded already, can't load\n");
                return 0;
            }
        }
        else if (check_command_2(command, num_input, command_get, command_g))
        {
            if (status->run == true)
            {
                ptrace_get(status, command[1]);
                return 0;
            }
            else
            {
                printf("** Program is not running, can't get\n");
            }
        }
        else if (check_command_2(command, num_input, command_break, command_b))
        {
            if (status->load == true && status->run == false)
            {
                printf("** Program is not running, can't break\n");
                return 0;
            }
            else
            {
                ptrace_break(status, command[1]);
                return 0;
            }
        }
        else if (check_command(command, num_input, command_delete))
        {
            if (status->load == true && status->run == false)
            {
                printf("** Program is not running, can't delete\n");
                return 0;
            }
            else
            {
                ptrace_delete(status, command[1]);
                return 0;
            }
        }
        else if (check_command_2(command, num_input, command_dump, command_x))
        {
            if (status->load == true && status->run == false)
            {
                printf("** Program is not running, can't dump\n");
                return 0;
            }
            else
            {
                unsigned long long addr = strtol(command[1], NULL, 16);
                ptrace_dump(status, addr);
                return 0;
            }
        }
        else if (check_command(command, num_input, command_disasm) || strncmp(command[0], command_d, strlen(command_d)) == 0)
        {
            if (status->load == true && status->run == false)
            {
                printf("** Program is not running, can't disasm\n");
                return 0;
            }
            else
            {
                unsigned long long addr = strtol(command[1], NULL, 16);
                ptrace_disasm(status, addr, "disasm");
                return 0;
            }
        }
    }
    else if (num_input == 3)
    {
        if (check_command_2(command, num_input, command_set, command_s))
        {
            if (status->load == true && status->run == false)
            {
                printf("** Program is not running, can't set\n");
                return 0;
            }
            else
            {
                ptrace_set(status, command[1], command[2]);
                return 0;
            }
        }
    }

    return 0;
}
