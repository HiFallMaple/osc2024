#include "shell.h"
#include "mbox.h"
#include "power.h"
#include "stdio.h"
#include "string.h"
#include "cpio.h"
#include "heap.h"
#include "dtb.h"

struct CLI_CMDS cmd_list[CLI_MAX_CMD] = {
    {.command = "cat", .help = "concatenate files and print on the standard output", .func = do_cmd_cat},
    {.command = "dtb", .help = "show device tree", .func = do_cmd_dtb},
    {.command = "hello", .help = "print Hello World!", .func = do_cmd_hello},
    {.command = "help", .help = "print all available commands", .func = do_cmd_help},
    {.command = "info", .help = "get device information via mailbox", .func = do_cmd_info},
    {.command = "ls", .help = "list directory contents", .func = do_cmd_ls},
    {.command = "malloc", .help = "test malloc", .func = do_cmd_malloc},
    {.command = "reboot", .help = "reboot the device", .func = do_cmd_reboot},
};

extern char *dtb_ptr;

extern void *CPIO_DEFAULT_PLACE;

int start_shell()
{
    char input_buffer[CMD_MAX_LEN];
    cli_print_banner();
    while (1)
    {
        cli_flush_buffer(input_buffer, CMD_MAX_LEN);
        puts("[ ( ´＿ゝ｀）...( •́ὤ•̀) < fuck ] $ ");
        cli_cmd_read(input_buffer);
        cli_cmd_exec(input_buffer);
    }
    return 0;
}

void cli_flush_buffer(char *buffer, int length)
{
    for (int i = 0; i < length; i++)
    {
        buffer[i] = '\0';
    }
};

void cli_cmd_read(char *buffer)
{
    char c = '\0';
    int idx = 0;
    while (idx < CMD_MAX_LEN - 1)
    {
        c = getchar();
        if (c == 127) // backspace
        {
            if (idx != 0)
            {
                puts("\b \b");
                idx--;
            }
        }
        else if (c == '\n')
        {
            break;
        }
        else if (c <= 16 || c >= 32 || c < 127)
        {
            putchar(c);
            buffer[idx++] = c;
        }
    }
    buffer[idx] = '\0';
    puts("\r\n");
}

int _parse_args(char *buffer, int *argc, char **argv)
{
    char get_cmd = 0;
    for (int i = 0; buffer[i] != '\0'; i++)
    {
        if (!get_cmd)
        {
            if (buffer[i] == ' ')
            {
                buffer[i] = '\0';
                get_cmd = 1;
            }
        }
        else
        {
            if (buffer[i - 1] == '\0' && buffer[i] != ' ' && buffer[i] != '\0')
            {
                if (*argc >= CMD_MAX_PARAM)
                {
                    return -1;
                }
                argv[*argc] = buffer + i;
                (*argc)++;
            }
            else if (buffer[i] == ' ')
            {
                buffer[i] = '\0';
            }
        }
    }
    return 0;
}

void print_args(int argc, char **argv)
{
    puts("argc: ");
    put_int(argc);
    puts("\r\n");
    for (int i = 0; i < argc; i++)
    {
        puts("argv[");
        put_int(i);
        puts("]: ");
        puts(argv[i]);
        puts("\r\n");
    }
}

void cli_cmd_exec(char *buffer)
{
    char *cmd = buffer;
    int argc = 0;
    char *argv[CMD_MAX_PARAM];
    if (_parse_args(buffer, &argc, argv) == -1)
    {
        puts("Too many arguments\r\n");
        return;
    }
    // print_args(argc, argv);

    for (int i = 0; i < CLI_MAX_CMD; i++)
    {
        if (strcmp(cmd, cmd_list[i].command) == 0)
        {
            cmd_list[i].func(argc, argv);
            return;
        }
    }
    if (*buffer)
    {
        puts(buffer);
        puts(": command not found\r\n");
    }
}

void cli_print_banner()
{
    puts("            ,.  ,.                                                 \r\n");
    puts("            ||  ||        _____     _ _ _____         _            \r\n");
    puts("           ,''--''.      |   __|___| | |     |___ ___| |___        \r\n");
    puts("          : (.)(.) :     |   __| .'| | | | | | .'| . | | -_|       \r\n");
    puts("         ,'        `.    |__|  |__,|_|_|_|_|_|__,|  _|_|___|       \r\n");
    puts("         :          :                            |_|               \r\n");
    puts("         :          :                                              \r\n");
    puts("   -ctr- `._m____m_,'         https://github.com/HiFallMaple       \r\n");
    puts("                                                                   \r\n");
}

int do_cmd_help(int argc, char **argv)
{
    for (int i = 0; i < CLI_MAX_CMD; i++)
    {
        puts(cmd_list[i].command);
        puts("\t\t\t: ");
        puts(cmd_list[i].help);
        puts("\r\n");
    }
    return 0;
}

int do_cmd_hello(int argc, char **argv)
{
    puts("Hello World!\r\n");
    return 0;
}

int do_cmd_info(int argc, char **argv)
{
    // print hw revision
    pt[0] = 8 * 4;
    pt[1] = MBOX_REQUEST_PROCESS;
    pt[2] = MBOX_TAG_GET_BOARD_REVISION;
    pt[3] = 4;
    pt[4] = MBOX_TAG_REQUEST_CODE;
    pt[5] = 0;
    pt[6] = 0;
    pt[7] = MBOX_TAG_LAST_BYTE;

    if (mbox_call(MBOX_TAGS_ARM_TO_VC, (unsigned int)((unsigned long)&pt)))
    {
        puts("Hardware Revision\t: 0x");
        // put_hex(pt[6]);
        put_hex(pt[5]);
        puts("\r\n");
    }
    // print arm memory
    pt[0] = 8 * 4;
    pt[1] = MBOX_REQUEST_PROCESS;
    pt[2] = MBOX_TAG_GET_ARM_MEMORY;
    pt[3] = 8;
    pt[4] = MBOX_TAG_REQUEST_CODE;
    pt[5] = 0;
    pt[6] = 0;
    pt[7] = MBOX_TAG_LAST_BYTE;

    if (mbox_call(MBOX_TAGS_ARM_TO_VC, (unsigned int)((unsigned long)&pt)))
    {
        puts("ARM Memory Base Address\t: 0x");
        put_hex(pt[5]);
        puts("\r\n");
        puts("ARM Memory Size\t\t: 0x");
        put_hex(pt[6]);
        puts("\r\n");
    }
    return 0;
}

int do_cmd_reboot(int argc, char **argv)
{
    if (argc == 0)
    {

        puts("Reboot in 10 seconds ...\r\n\r\n");
        volatile unsigned int *rst_addr = (unsigned int *)PM_RSTC;
        *rst_addr = PM_PASSWORD | 0x20;
        volatile unsigned int *wdg_addr = (unsigned int *)PM_WDOG;
        *wdg_addr = PM_PASSWORD | 0x70000;
    }
    else if (argc == 1 && strcmp(argv[0], "-c") == 0)
    {
        puts("Cancel reboot...\r\n");
        volatile unsigned int *rst_addr = (unsigned int *)PM_RSTC;
        *rst_addr = PM_PASSWORD | 0x0;
        volatile unsigned int *wdg_addr = (unsigned int *)PM_WDOG;
        *wdg_addr = PM_PASSWORD | 0x0;
    }
    return 0;
}

int do_cmd_ls(int argc, char **argv)
{
    char *workdir;
    char *c_filepath;
    char *c_filedata;
    unsigned int c_filesize;

    if (argc == 0)
    {
        workdir = ".";
    }
    else
    {
        workdir = argv[0];
    }
    int error;
    CPIO_FOR_EACH(&c_filepath, &c_filesize, &c_filedata, error, {
        // if this is not TRAILER!!! (last of file)
        if (error != TRAILER)
        {
            puts(c_filepath);
            puts("\r\n");
        }
    });
    if (error == ERROR)
    {
        puts("cpio parse error");
        return -1;
    }
    return 0;
}

int do_cmd_cat(int argc, char **argv)
{
    char *filepath;
    char *c_filedata;
    unsigned int c_filesize;

    if (argc == 1)
    {
        filepath = argv[0];
    }
    else
    {
        puts("Incorrect number of parameters\r\n");
        return -1;
    }

    int result = cpio_get_file(filepath, &c_filesize, &c_filedata);

    if (result == ERROR)
    {
        puts("cpio parse error\r\n");
        return -1;
    }
    else if (result == TRAILER)
    {
        puts("cat: ");
        puts(filepath);
        puts(": No such file or directory\r\n");
        return -1;
    }
    else if (result == SUCCESS)
    {
        puts(c_filedata);
    }
    return 0;
}

int do_cmd_malloc(int argc, char **argv)
{
    // test malloc
    char *test1 = malloc(0x18);
    strcpy(test1, "test malloc1");
    puts(test1);
    puts("\r\n");

    char *test2 = malloc(0x20);
    strcpy(test2, "test malloc2");
    puts(test2);
    puts("\r\n");

    char *test3 = malloc(0x28);
    strcpy(test3, "test malloc3");
    puts(test3);
    puts("\r\n");
    return 0;
}

int do_cmd_dtb(int argc, char **argv)
{
    traverse_device_tree(dtb_ptr, dtb_callback_show_tree);
    return 0;
}