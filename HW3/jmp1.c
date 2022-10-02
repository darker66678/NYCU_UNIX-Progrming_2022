#include "libmini.h"

typedef void (*proc_t)();
static jmp_buf jb;

#define FUNBODY(m, from)        \
    {                           \
        write(1, m, strlen(m)); \
        longjmp(jb, from);      \
    }

void a() FUNBODY("This is function a().\n", 1);
void b() FUNBODY("This is function b().\n", 2);
void c() FUNBODY("This is function c().\n", 3);
void d() FUNBODY("This is function d().\n", 4);
void e() FUNBODY("This is function e().\n", 5);
void f() FUNBODY("This is function f().\n", 6);
void g() FUNBODY("This is function g().\n", 7);
void h() FUNBODY("This is function h().\n", 8);
void i() FUNBODY("This is function i().\n", 9);
void j() FUNBODY("This is function j().\n", 10);

proc_t funs[] = {a, b, c, d, e, f, g, h, i, j};

int main()
{
    volatile int i = 0;
    char ma[] = "a changed!\n";
    char mb[] = "mask is incorrect!_1\n";
    char mret[] = "ret is incorrect!\n";
    char m_mask[] = "mask is incorrect!_2\n";

    register int a;
    volatile int ret = -1;

    // jb->mask.sig[0] = 6;
    sigset_t current_mask;
    sigemptyset(&current_mask); // set a empty mask
    sigaddset(&current_mask, SIGALRM);
    sigprocmask(SIG_BLOCK, &current_mask, NULL); // set SIGALRM
    a = 0;
    if ((ret = setjmp(jb)) != 0)
    {
        i++;
        if (ret != i)
        {
            write(1, mret, strlen(mret));
        }
    }
    if (a != 0)
    {
        write(1, ma, strlen(ma));
    }

    sigset_t new_mask;
    sigemptyset(&new_mask);
    int get = sigprocmask(SIG_BLOCK, NULL, &new_mask); // get setting mask
    if (get >= 0)
    {
        if (sigismember(&new_mask, SIGALRM) == 1) // check
        {
            if (sigismember(&new_mask, SIGINT) == 1)
                write(1, mb, strlen(mb));
        }
        else
        {
            write(1, m_mask, strlen(m_mask));
        }
    }

    // jb->mask.sig[0] = 100;
    sigaddset(&current_mask, SIGINT);
    sigprocmask(SIG_BLOCK, &current_mask, NULL); // set SIGINT

    a = 100;
    if (i < 10)
        funs[i]();
    return 0;
}
