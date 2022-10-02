#include <stdio.h>
#include <regex>
#include <string>
#include <vector>
#include <sys/types.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unordered_map>
#include <iomanip>
using namespace std;

struct fd
{
    string fd_name;
    string link_name;
};
const vector<fd> fd_list = {{"cwd", "cwd"}, {"rtd", "root"}, {"txt", "exe"}, {"mem", "maps"}, {"NOFD", "fd"}};
struct filter
{
    string filter_com;
    string filter_name;
    string filter_type;
};
struct proc_output
{
    string Command, PID, user, FD, TYPE, NODE, NAME = "";
};
struct user_list
{
    string user_name = "";
    string UID = "";
};
vector<string> split(string s, char token)
{
    vector<string> res;
    stringstream ss(s);
    string line;
    while (getline(ss, line, token))
    {
        res.push_back(line);
    }
    return res;
}

filter get_config(int argc, char *argv[])
{
    filter config;
    string filter_com = "";
    string filter_name = "";
    string filter_type = "";
    bool loadparam = false;
    vector<string> type_option = {"REG", "CHR", "DIR", "FIFO", "SOCK", "unknown"};
    for (int i = 0; i < argc; ++i)
    {
        if (loadparam)
        {
            if (i + 1 >= argc)
            {
                printf("Nonlegal prameters!\n");
                exit(-1);
            }

            if (strcmp(argv[i], "-c") == 0)
            {
                filter_com = argv[i + 1];
                loadparam = false;
            }
            else if (strcmp(argv[i], "-f") == 0)
            {
                filter_name = argv[i + 1];
                loadparam = false;
            }
            else if (strcmp(argv[i], "-t") == 0)
            {
                filter_type = argv[i + 1];
                if (find(type_option.begin(), type_option.end(), filter_type) == type_option.end())
                {
                    cout << "Invalid TYPE option.\n";
                    exit(-1);
                }
                else
                {
                    loadparam = false;
                }
            }
            else
            {
                cout << "Nonlegal prameters!\n";
                exit(-1);
            }
        }
        else
        {
            loadparam = true;
        }
    }
    config.filter_com = filter_com;
    config.filter_name = filter_name;
    config.filter_type = filter_type;
    return config;
}

vector<user_list> get_user_list()
{
    string link = "/etc/passwd";
    ifstream users(link);
    string line;
    vector<user_list> u_list;
    user_list user;
    if (users.is_open())
    {
        vector<string> i;
        while (getline(users, line))
        {
            i = split(line, ':');
            user.user_name = i[0];
            user.UID = i[2];
            u_list.push_back(user);
        }
    }

    return u_list;
}

void print_ans(vector<proc_output> output, filter config)
{
    cout << setw(16) << setfill(' ') << left << "COMMAND";
    cout << setw(16) << setfill(' ') << left << "PID";
    cout << setw(16) << setfill(' ') << left << "USER";
    cout << setw(16) << setfill(' ') << left << "FD";
    cout << setw(16) << setfill(' ') << left << "TYPE";
    cout << setw(16) << setfill(' ') << left << "NODE";
    cout << setw(16) << setfill(' ') << left << "NAME"
         << "\n";
    regex reg_com(config.filter_com);
    regex reg_name(config.filter_name);
    regex reg_type(config.filter_type);
    for (int i = 0; i < output.size(); i++)
    {
        smatch sm;
        if (regex_search(output[i].Command, sm, reg_com) && regex_search(output[i].NAME, sm, reg_name) && regex_search(output[i].TYPE, sm, reg_type))
        {
            cout << setw(16) << setfill(' ') << left << output[i].Command;
            cout << setw(16) << setfill(' ') << left << output[i].PID;
            cout << setw(16) << setfill(' ') << left << output[i].user;
            cout << setw(16) << setfill(' ') << left << output[i].FD;
            cout << setw(16) << setfill(' ') << left << output[i].TYPE;
            cout << setw(16) << setfill(' ') << left << output[i].NODE;
            cout << setw(16) << setfill(' ') << left << output[i].NAME << "\n";
            continue;
        }
    }
}
string fd_type(const char *buf)
{
    struct stat file;
    int n = stat(buf, &file);
    if (n == -1)
    {
        return "unknown";
    }
    if (S_ISREG(file.st_mode))
    {
        return "REG";
    }
    else if (S_ISDIR(file.st_mode))
    {
        return "DIR";
    }
    else if (S_ISCHR(file.st_mode))
    {
        return "CHR";
    }
    else if (S_ISFIFO(file.st_mode))
    {
        return "FIFO";
    }
    else if (S_ISSOCK(file.st_mode))
    {
        return "SOCK";
    }
    return "unknown";
}
string fd_rwu(const char *link)
{
    struct stat bb;
    int n = lstat(link, &bb);
    if (n == -1)
    {
        return "";
    }
    if ((bb.st_mode & S_IRUSR) && (bb.st_mode & S_IWUSR))
    {
        return "u";
    }
    else if (bb.st_mode & S_IRUSR)
    {
        return "r";
    }
    else if (bb.st_mode & S_IWUSR)
    {
        return "w";
    }
    return "";
}
bool isDeleted(string buf)
{
    if (split(buf, ' ').size() > 1)
    {
        if (split(buf, ' ')[1] == "(deleted)")
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}
vector<proc_output> parse(char *pid, vector<proc_output> output, string dir_name, vector<user_list> u_list)
{
    proc_output tmp_output;
    //  parse status file , get Command,user
    string status_link = dir_name + string(pid) + "/status";
    ifstream status(status_link);
    string line;
    if (status.is_open()) // get username and command
    {
        // get PID
        tmp_output.PID = string(pid);
        string uid;
        int i = 0;
        while (getline(status, line))
        {
            if (i == 0)
            {
                tmp_output.Command = line.substr(6);
            }
            else if (i == 8)
            {
                vector<string> test = split(line, '\t');
                uid = test[1];
                for (auto user : u_list)
                {
                    if (user.UID == uid)
                    {
                        tmp_output.user = user.user_name;
                    }
                }
            }
            i++;
        }
    }
    else
    {
        return output;
    }
    unordered_map<string, bool> rem_list;
    for (auto fd : fd_list)
    {
        char cur_work[10240];
        struct stat buf;
        int fd_num, ret;
        ino_t inode;
        string fd_link = dir_name + tmp_output.PID + "/" + fd.link_name;
        ssize_t res;
        if (fd.fd_name == "cwd" || fd.fd_name == "rtd" || fd.fd_name == "txt")
        {
            tmp_output.FD = fd.fd_name;
            res = readlink(fd_link.c_str(), cur_work, sizeof(cur_work));
            if (res != -1)
            {
                cur_work[res] = '\0';
                tmp_output.NAME = cur_work;
                if (fd.fd_name == "cwd" || fd.fd_name == "rtd")
                {
                    tmp_output.TYPE = "DIR";
                }
                else if (fd.fd_name == "txt")
                {
                    tmp_output.TYPE = "REG";
                }
                ret = stat(cur_work, &buf);
                if (ret == -1)
                {
                    continue;
                }
                else
                {
                    inode = buf.st_ino;
                    tmp_output.NODE = to_string(inode);
                    rem_list[to_string(inode)] = true;
                }
            }
            else
            {
                tmp_output.NAME = fd_link + " (Permission denied)";
                tmp_output.TYPE = "unknown";
                tmp_output.NODE = "";
            }
            output.push_back(tmp_output);
            continue;
        }
        else if (fd.fd_name == "mem")
        {
            tmp_output.FD = fd.fd_name;
            ifstream maps(fd_link);
            string map;

            if (status.is_open())
            {
                while (getline(maps, map))
                {
                    vector<string> ins = split(map, ' ');
                    if (ins[4] != "0")
                    {
                        if (rem_list.find(ins[4]) == rem_list.end())
                        {
                            tmp_output.NODE = ins[4];
                            rem_list[ins[4]] = true;
                            if (ins.back() == "(deleted)")
                            {
                                tmp_output.NAME = ins[ins.size() - 2];
                                tmp_output.FD = "DEL";
                                tmp_output.TYPE = "REG";
                            }

                            else
                            {
                                tmp_output.NAME = ins.back();
                                tmp_output.FD = "mem";
                                tmp_output.TYPE = "REG";
                            }
                            output.push_back(tmp_output);
                            continue;
                        }
                    }
                }
            }
            else
            {
                continue;
            }
        }
        else if (fd.fd_name == "NOFD")
        {
            DIR *fd_ptr;
            vector<string> fds;
            int fd_count = 0;
            struct dirent *fd_folder;

            fd_ptr = opendir(fd_link.c_str());
            if (fd_ptr == NULL) // Permission denied for /proc/[pid]/fd
            {
                tmp_output.FD = "NOFD";
                tmp_output.TYPE = "";
                tmp_output.NODE = "";
                tmp_output.NAME = fd_link + " (Permission denied)";
                output.push_back(tmp_output);
                continue;
            }
            else
            {
                while ((fd_folder = readdir(fd_ptr)) != nullptr)
                {
                    if (isdigit(fd_folder->d_name[0]))
                    {
                        fds.push_back(string(fd_folder->d_name));
                        fd_count++;
                    }
                }
                closedir(fd_ptr);

                for (auto i : fds)
                {
                    char buf[10240];
                    string fd_pid_link = fd_link + "/" + i;
                    ssize_t fd_res;
                    fd_res = readlink(fd_pid_link.c_str(), buf, sizeof(buf));
                    if (fd_res != -1)
                    {
                        buf[fd_res] = '\0';
                        auto name = buf;
                        tmp_output.TYPE = fd_type(buf);
                        if (tmp_output.TYPE == "unknown")
                        {
                            if (string(buf).substr(0, 4) == "pipe")
                            {
                                tmp_output.TYPE = "FIFO";
                                string inode = split(string(buf), '[')[1];
                                tmp_output.NODE = inode.substr(0, inode.size() - 1);
                                if (isDeleted(name))
                                {
                                    tmp_output.NAME = split(name, ' ')[0];
                                }
                                else
                                {
                                    tmp_output.NAME = name;
                                }
                                tmp_output.FD = i + fd_rwu(fd_pid_link.c_str());
                            }
                            else if (string(buf).substr(0, 6) == "socket")
                            {
                                tmp_output.TYPE = "SOCK";
                                string inode = split(string(buf), '[')[1];
                                tmp_output.NODE = inode.substr(0, inode.size() - 1);
                                if (isDeleted(name))
                                {
                                    tmp_output.NAME = split(name, ' ')[0];
                                }
                                else
                                {
                                    tmp_output.NAME = name;
                                }
                                tmp_output.FD = i + fd_rwu(fd_pid_link.c_str());
                            }
                            else
                            {
                                struct stat temp_buf;
                                int n = stat(fd_pid_link.c_str(), &temp_buf);
                                if (n == -1)
                                {
                                    continue;
                                }
                                else
                                {
                                    tmp_output.TYPE = fd_type(fd_pid_link.c_str());
                                    int ino = temp_buf.st_ino;
                                    tmp_output.NODE = to_string(ino);
                                    if (isDeleted(name))
                                    {
                                        tmp_output.NAME = split(name, ' ')[0];
                                    }
                                    else
                                    {
                                        tmp_output.NAME = name;
                                    }
                                    tmp_output.FD = i + fd_rwu(fd_pid_link.c_str());
                                }
                            }
                        }
                        else
                        {
                            struct stat temp_buf;
                            int n = stat(buf, &temp_buf);
                            if (n == -1)
                            {
                                continue;
                            }
                            else
                            {
                                int ino = temp_buf.st_ino;
                                tmp_output.NODE = to_string(ino);
                                tmp_output.FD = i + fd_rwu(fd_pid_link.c_str());
                                tmp_output.NAME = name;
                            }
                        }
                        output.push_back(tmp_output);
                        continue;
                    }
                    else
                    {
                        continue;
                    }
                }
            }
        }
    }
    return output;
}
vector<proc_output> get_proc()
{
    vector<proc_output> output;
    auto u_list = get_user_list();
    string dir_name = "/proc/";
    // get current PID
    DIR *proc_ptr;
    int num = 0;
    struct dirent *proc_folder;
    proc_ptr = opendir(dir_name.c_str());

    while ((proc_folder = readdir(proc_ptr)) != nullptr)
    {
        if (isdigit(proc_folder->d_name[0]))
        {
            output = parse(proc_folder->d_name, output, dir_name, u_list); // parse each PID folder
        }
    }
    closedir(proc_ptr);
    return output;
}

int main(int argc, char *argv[])
{
    auto config = get_config(argc, argv); // get filter//
    auto output = get_proc();
    print_ans(output, config);
    return 0;
}
