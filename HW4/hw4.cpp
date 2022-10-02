#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include "command.h"

current_status status;
char command[MAX_LENGTH];

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    char script[MAX_LENGTH];
    bool is_script = false;
    status_init(&status);
    if (argc != 1)
    {
        int opt = 1;
        while (true)
        {
            opt = getopt(argc, argv, "s:");
            if (opt == -1)
            {
                break;
            }
            switch (opt)
            {
            case 's':
                if (optarg)
                {
                    sprintf(script, optarg);
                    is_script = true;
                }
                break;
            }
        }
        if (optind < argc)
        {
            ptrace_load(argv[optind], &status);
        }
    }
    if (!is_script)
    {
        while (1)
        {
            memset(command, 0, MAX_LENGTH);
            printf("sdb> ");
            fgets(command, MAX_LENGTH, stdin);
            command[strlen(command) - 1] = 0; // remove \n
            run_command(command, &status);
        }
        return 0;
    }
    else
    {
        FILE *file = fopen(script, "rb");
        char command[MAX_LENGTH];
        if (file)
        {
            while (!feof(file))
            {
                memset(command, 0, MAX_LENGTH);
                fgets(command, sizeof(command), file);
                command[strlen(command) - 1] = 0;
                run_command(command, &status);
            }
            fclose(file);
        }
        return 0;
    }
}
