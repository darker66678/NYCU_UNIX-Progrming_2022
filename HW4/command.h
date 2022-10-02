#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <elf.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/user.h>
#include <vector>
#include <capstone/capstone.h>
#include <string>
#include <map>

#define MAX_LENGTH 100
#define ElfW(type) Elf64_##type
#define DISASM_LENGTH 10
#define PEEKSIZE 8
#define DUMPSIZE 80
typedef struct
{
    unsigned long long b_point;
    unsigned long long code;
} bp_list;

typedef struct
{
    bool load;
    bool run;
    char file[MAX_LENGTH];
    pid_t child;
    struct user_regs_struct regs;
    std::vector<bp_list> bps;
    int bp_num;
    Elf64_Off offset;
    uint64_t entry_point;
} current_status;

class instruction1
{
public:
    unsigned char bytes[16];
    int size;
    std::string opr, opnd;
};

static std::map<long long, instruction1> instructions;

int run_command(char *input, current_status *status);
void ptrace_load(char *file, current_status *status);
void status_init(current_status *status);