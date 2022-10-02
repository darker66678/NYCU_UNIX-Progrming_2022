#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dlfcn.h>
using namespace std;

struct config
{
    string so_path;
    string output_file;
    char *command[128];
};
config get_config(int argc, char *argv[])
{
    config setting;
    if (argc == 1)
    {
        fprintf(stderr, "no command given.\n");
        exit(EXIT_FAILURE);
    }
    int opt = 0;
    bool default_output = true;
    bool default_path = true;
    while (true)
    {
        opt = getopt(argc, argv, "o:p:");
        if (opt == -1)
        {
            break;
        }
        switch (opt)
        {
        case 'o':
            if (optarg)
            {
                setting.output_file = string(optarg);
                default_output = false;
            }
            break;
        case 'p':
            if (optarg)
            {
                setting.so_path = string(optarg);
                default_path = false;
            }
            break;
        default:
            fprintf(stderr, "%s", "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n       -p: set the path to logger.so, default = ./logger.so\n       -o: print output to file, print to \"stderr\" if no file specified\n       --: separate the arguments for logger and for the command");
            exit(EXIT_FAILURE);
        }
    }
    if (default_output)
        setting.output_file = "default";
    if (default_path)
        setting.so_path = "./logger.so";
    int command_index = 0;
    if (optind == argc)
    {
        fprintf(stderr, "no command given.\n");
        exit(EXIT_FAILURE);
    }
    for (int i = optind; i < argc; i++)
    {
        setting.command[command_index] = argv[i];
        command_index++;
    }
    setting.command[command_index] = NULL;
    return setting;
}
int main(int argc, char *argv[])
{
    auto config = get_config(argc, argv);
    setenv("LD_PRELOAD", config.so_path.c_str(), 1);
    setenv("OUTPUT_FILE", config.output_file.c_str(), 1);

    if (execvp(config.command[0], config.command) < 0)
    {
        perror("error on exec");
        exit(EXIT_FAILURE);
    }

    return 0;
}