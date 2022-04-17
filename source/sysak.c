#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#define KVERSION 64
#define MAX_SUBCMD_ARGS 128
#define MAX_NAME_LEM 64
#define MAX_WORK_PATH 256
#define bool int
#define true 1
#define false 0

char *module = "/sysak.ko";
char *log_path="/var/log/sysak";
char *system_modules = "/proc/modules";

char kern_version[KVERSION];
char modin[MAX_SUBCMD_ARGS];
char modun[MAX_SUBCMD_ARGS];
char tools_path[MAX_WORK_PATH];
char sysak_rule[MAX_WORK_PATH];
char module_path[MAX_WORK_PATH];
char sysak_other_rule[MAX_WORK_PATH];
bool pre_module = false;
bool post_module = false;

static void usage(void)
{
	fprintf(stdout,
	            "Usage: sysak [cmd] [subcmd [cmdargs]]\n"
                "       cmd:\n"
                "              list, show all of subcmds\n"
                "              help, help information for specify subcmd\n"
                "       subcmd: see the result of list\n");
}

static void kern_release(void)
{
    struct utsname name;

    if (uname (&name) == -1){
        printf("cannot get system name\n");
        return;
    }
    strncpy(kern_version,name.release,sizeof(name.release));
}

static void mod_ctrl(bool enable)
{
    FILE *modlist_fp;
    char exec_mod[4*KVERSION];
    bool has_ko = false;
    char modinfo[MAX_SUBCMD_ARGS];

    modlist_fp = fopen(system_modules, "r");
    if (!modlist_fp){
        printf("open %s failed\n", system_modules);
		return;
    }
    while(fgets(modinfo, sizeof(modinfo), modlist_fp))
    {
        if (strstr(modinfo,"sysak")){
            has_ko = true;
            break;
        }

    }
    fclose(modlist_fp); 

    if (enable && !has_ko) {
        snprintf(exec_mod, sizeof(exec_mod), "insmod %s%s%s", module_path, kern_version, module);
        system(exec_mod);

    }
    else if (!enable && has_ko) {
        snprintf(exec_mod, sizeof(exec_mod), "rmmod %s%s%s", module_path, kern_version, module);
        system(exec_mod);
    }
}

static void exectue(int argc, char *argv[])
{
    int i;
    char subcmd_name[MAX_NAME_LEM+MAX_SUBCMD_ARGS];
    char subcmd_args[MAX_SUBCMD_ARGS];

    if (pre_module)
        mod_ctrl(true);

    snprintf(subcmd_name, sizeof(subcmd_name), "%s%s", tools_path, argv[1]);

    if (access(subcmd_name,0) != 0)
        snprintf(subcmd_name, sizeof(subcmd_name), "%s%s%s", tools_path, kern_version, argv[1]);

    for(i = 2; i <= (argc-1); i++){
        snprintf(subcmd_args, sizeof(subcmd_args), " \"%s\"", argv[i]);
        strcat(subcmd_name,subcmd_args);
    }
    system(subcmd_name);
    
    if (post_module)
        mod_ctrl(false);
}

static void print_each_tool(char *path)
{
    FILE *fp;
    char buf[MAX_NAME_LEM + MAX_SUBCMD_ARGS];
    char tools_name[MAX_NAME_LEM];

    fp = fopen(path, "r");
    if (!fp){
        printf("open %s failed\n", path);
		return;
    }

    while(fgets(buf, sizeof(buf), fp))
    {
        sscanf(buf,"%[^:]",tools_name);
        printf("  %s\n",tools_name);
    }
    fclose(fp);
}

static void subcmd_list(void)
{
    fputs("subcmd list:\n",stdout);
    print_each_tool(sysak_rule);
    print_each_tool(sysak_other_rule);
}

static bool tool_lookup(char *path, char *tool)
{
    FILE *fp;
    char buf[MAX_NAME_LEM + MAX_SUBCMD_ARGS];

    fp = fopen(path, "r");
    if (!fp){
        printf("open %s failed\n", path);
		return false;
    }
    while(fgets(buf, sizeof(buf), fp))
    {
        char tools_name[MAX_NAME_LEM];

        sscanf(buf,"%[^:]",tools_name);
        if (strcmp(tools_name, tool)){
            continue;
        }

        sscanf(buf,"%*[^:]:prev{%[^}]};post{%[^}]}", modin, modun);
        fclose(fp);
        return true;
    }
    fclose(fp);
    return false;
}

static void subcmd_parse(int argc, char *argv[])
{
    int i;
    
    if (!tool_lookup(sysak_other_rule, argv[1]) && 
            !tool_lookup(sysak_rule, argv[1])){
        printf("no components, you should get first\n");
        return;
    }

    if (strstr(modin, "default") != NULL|| strstr(modun, "default") != NULL){
        pre_module = true;
        post_module = true;
        goto exec;
    }

    for(i = 2; i <= (argc-1); i++)
    {
        if (strstr(modin, argv[i])){
            pre_module = true;
            break;
        }
        else if (strstr(modun, argv[i])){
            post_module = true;
            break;
        }
    }
exec:
    exectue(argc, argv);
}

static void parse_arg(int argc, char *argv[])
{
	if (argc < 2)
		usage();
    
    if (!strcmp(argv[1],"list")){
        subcmd_list();
        return;
    }

    if (!strcmp(argv[1],"help")){
        usage();
        return;
    }
    subcmd_parse(argc, argv);
}

int main(int argc, char *argv[])
{
    char tmp[MAX_WORK_PATH];
    char *work_path;

    if (access(log_path,0) != 0)
        mkdir(log_path, 0755 );

    kern_release();
    work_path = getcwd(tmp,MAX_WORK_PATH);

    snprintf(tools_path, sizeof(tools_path), "%s%s", work_path, 
            "/.sysak_compoents/tools/");
    snprintf(module_path, sizeof(module_path), "%s%s", work_path, 
            "/.sysak_compoents/lib/");
    snprintf(sysak_rule, sizeof(sysak_rule), "%s%s", work_path, 
            "/.sysak_compoents/tools/.sysak.rules");
    snprintf(sysak_other_rule, sizeof(sysak_other_rule), "%s%s%s%s", work_path, 
            "/.sysak_compoents/tools/",kern_version,"/.sysak.rules");
 
	parse_arg(argc, argv);
	return 0;
}