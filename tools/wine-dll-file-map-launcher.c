#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/memfd.h>
#include <sys/syscall.h>
#endif

#if defined(__APPLE__) || defined(HAVE_SHM_OPEN)
#include <sys/mman.h>
#endif

static void usage( const char *argv0 )
{
    fprintf( stderr,
             "Usage: %s <wine-binary> <source-file> <nt-name> [--] [wine-args...]\n"
             "\n"
             "Creates anonymous backing from <source-file>, appends one WINE_DLL_FILE_MAP entry,\n"
             "then execs <wine-binary>. If no wine-args are provided, <nt-name> is passed as\n"
             "the target executable argument.\n",
             argv0 );
}

#ifdef __linux__
static int create_memfd( void )
{
    return syscall( SYS_memfd_create, "wine-dll-file-map", MFD_CLOEXEC );
}
#endif

static int create_shared_backing( void )
{
#ifdef __linux__
    int fd = create_memfd();
    if (fd != -1) return fd;
#endif

#if defined(SHM_ANON)
    int fd;
    fd = shm_open( SHM_ANON, O_RDWR | O_CLOEXEC, 0600 );
    if (fd != -1) return fd;
#endif

    // {
    //     const char *tmpdir = getenv( "TMPDIR" );
    //     char path[PATH_MAX];
    //     int fd;

    //     if (!tmpdir || !tmpdir[0]) tmpdir = "/tmp";
    //     snprintf( path, sizeof(path), "%s/%s", tmpdir, "wine-dll-file-map-XXXXXX" );
    //     fd = mkstemp( path );
    //     if (fd == -1) return -1;
    //     unlink( path );
    //     return fd;
    // }

    errno = ENOSYS;
    return -1;
}

static int copy_file_to_fd( const char *src_path, int dst_fd )
{
    char buffer[65536];
    ssize_t read_ret;
    int src_fd = open( src_path, O_RDONLY );

    if (src_fd == -1)
    {
        perror( "open source-file" );
        return -1;
    }

    while ((read_ret = read( src_fd, buffer, sizeof(buffer) )) > 0)
    {
        ssize_t written = 0;
        while (written < read_ret)
        {
            ssize_t write_ret = write( dst_fd, buffer + written, read_ret - written );
            if (write_ret == -1)
            {
                perror( "write shared backing" );
                close( src_fd );
                return -1;
            }
            written += write_ret;
        }
    }

    if (read_ret == -1)
    {
        perror( "read source-file" );
        close( src_fd );
        return -1;
    }

    close( src_fd );
    if (lseek( dst_fd, 0, SEEK_SET ) == -1)
    {
        perror( "lseek shared backing" );
        return -1;
    }
    return 0;
}

static int clear_cloexec( int fd )
{
    int flags = fcntl( fd, F_GETFD );
    if (flags == -1)
    {
        perror( "fcntl(F_GETFD)" );
        return -1;
    }
    if (fcntl( fd, F_SETFD, flags & ~FD_CLOEXEC ) == -1)
    {
        perror( "fcntl(F_SETFD)" );
        return -1;
    }
    return 0;
}

static char *build_env_value( const char *existing, int fd, const char *nt_name )
{
    int len = snprintf( NULL, 0, "%s%s%d:%s",
                        existing && *existing ? existing : "",
                        existing && *existing ? "|" : "",
                        fd, nt_name );
    char *ret = malloc( len + 1 );

    if (!ret) return NULL;

    snprintf( ret, len + 1, "%s%s%d:%s",
              existing && *existing ? existing : "",
              existing && *existing ? "|" : "",
              fd, nt_name );
    return ret;
}

static const char *default_wine_target( const char *nt_name )
{
    if (!strncmp( nt_name, "\\??\\", 4 )) return nt_name + 4;
    return nt_name;
}

int main( int argc, char **argv )
{
    const char *wine_binary, *source_file, *nt_name;
    const char *wine_target;
    const char *existing_env;
    char *env_value;
    char **child_argv;
    int fd, i, child_argc;

    if (argc < 4)
    {
        usage( argv[0] );
        return 2;
    }

    wine_binary = argv[1];
    source_file = argv[2];
    nt_name = argv[3];
    wine_target = default_wine_target( nt_name );

    fd = create_shared_backing();
    if (fd == -1)
    {
        perror( "create shared backing" );
        return 1;
    }

    if (copy_file_to_fd( source_file, fd ) == -1) return 1;
    if (clear_cloexec( fd ) == -1) return 1;

    existing_env = getenv( "WINE_DLL_FILE_MAP" );
    env_value = build_env_value( existing_env, fd, nt_name );
    if (!env_value)
    {
        fprintf( stderr, "failed to allocate WINE_DLL_FILE_MAP value\n" );
        return 1;
    }
    if (setenv( "WINE_DLL_FILE_MAP", env_value, 1 ) == -1)
    {
        perror( "setenv(WINE_DLL_FILE_MAP)" );
        return 1;
    }

    if (argc > 4 && !strcmp( argv[4], "--" ))
    {
        child_argc = argc - 5;
        child_argv = calloc( child_argc + 2, sizeof(*child_argv) );
        if (!child_argv)
        {
            fprintf( stderr, "failed to allocate argv\n" );
            return 1;
        }

        child_argv[0] = argv[1];
        if (!child_argc)
        {
            child_argv[1] = (char *)wine_target;
        }
        else
        {
            for (i = 0; i < child_argc; i++) child_argv[i + 1] = argv[i + 5];
        }
    }
    else if (argc == 4)
    {
        child_argv = calloc( 3, sizeof(*child_argv) );
        if (!child_argv)
        {
            fprintf( stderr, "failed to allocate argv\n" );
            return 1;
        }
        child_argv[0] = argv[1];
        child_argv[1] = (char *)wine_target;
    }
    else
    {
        child_argc = argc - 4;
        child_argv = calloc( child_argc + 2, sizeof(*child_argv) );
        if (!child_argv)
        {
            fprintf( stderr, "failed to allocate argv\n" );
            return 1;
        }

        child_argv[0] = argv[1];
        for (i = 0; i < child_argc; i++) child_argv[i + 1] = argv[i + 4];
    }

    execv( wine_binary, child_argv );
    perror( "execv(wine-binary)" );
    return 1;
}
