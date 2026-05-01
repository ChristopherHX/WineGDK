#include "XGameLaunch.h"

WINE_DEFAULT_DEBUG_CHANNEL(gdkc);

static const struct IXGameLaunchImplVtbl x_gamelaunch_vtbl;

static HRESULT read_microsoft_game_config( char **buffer )
{
    WCHAR path[MAX_PATH], *slash;
    FILE *file;
    long size;

    *buffer = NULL;
    if (!GetModuleFileNameW( NULL, path, ARRAY_SIZE( path ) )) return HRESULT_FROM_WIN32( GetLastError() );
    if ((slash = wcsrchr( path, '\\' ))) slash[1] = 0;
    else path[0] = 0;
    lstrcatW( path, L"MicrosoftGame.Config" );

    if (!(file = _wfopen( path, L"rb" ))) return HRESULT_FROM_WIN32( GetLastError() );
    if (fseek( file, 0, SEEK_END ) || (size = ftell( file )) < 0)
    {
        fclose( file );
        return E_FAIL;
    }
    rewind( file );

    if (!(*buffer = calloc( size + 1, sizeof( char ) )))
    {
        fclose( file );
        return E_OUTOFMEMORY;
    }
    if (size && fread( *buffer, 1, size, file ) != size)
    {
        free( *buffer );
        *buffer = NULL;
        fclose( file );
        return E_FAIL;
    }

    fclose( file );
    return S_OK;
}

static BOOL find_config_value( const char *config, const char *key, char *value, size_t value_size )
{
    char open_tag[64], close_tag[64], attr[64];
    const char *start, *end;
    size_t len;

    sprintf( open_tag, "<%s>", key );
    sprintf( close_tag, "</%s>", key );
    if ((start = strstr( config, open_tag )) && (end = strstr( start, close_tag )))
    {
        start += strlen( open_tag );
        len = end - start;
        if (len >= value_size) len = value_size - 1;
        memcpy( value, start, len );
        value[len] = 0;
        return TRUE;
    }

    sprintf( attr, "%s=\"", key );
    if ((start = strstr( config, attr )))
    {
        start += strlen( attr );
        if ((end = strchr( start, '"' )))
        {
            len = end - start;
            if (len >= value_size) len = value_size - 1;
            memcpy( value, start, len );
            value[len] = 0;
            return TRUE;
        }
    }

    return FALSE;
}

static inline struct x_game_launch *impl_from_IXGameLaunchImpl( IXGameLaunchImpl *iface )
{
    return CONTAINING_RECORD( iface, struct x_game_launch, IXGameLaunch_iface );
}

static HRESULT WINAPI x_game_launch_QueryInterface( IXGameLaunchImpl *iface, REFIID iid, void **out )
{
    struct x_game_launch *impl = impl_from_IXGameLaunchImpl( iface );

    TRACE( "iface %p, iid %s, out %p\n", iface, debugstr_guid( iid ), out );

    if (!out) return E_POINTER;

    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IXGameLaunch ))
    {
        *out = &impl->IXGameLaunch_iface;
        IXGameLaunchImpl_AddRef( *out );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI x_game_launch_AddRef( IXGameLaunchImpl *iface )
{
    struct x_game_launch *impl = impl_from_IXGameLaunchImpl( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu\n", iface, ref );
    return ref;
}

static ULONG WINAPI x_game_launch_Release( IXGameLaunchImpl *iface )
{
    struct x_game_launch *impl = impl_from_IXGameLaunchImpl( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu\n", iface, ref );
    if (!ref)
    {
        free( impl );
    }
    return ref;
}

/*** IXGameLaunch methods ***/
HRESULT XGameGetXboxTitleId(IXGameLaunchImpl *This, uint32_t *titleId)
{
    char *config = NULL, value[64];
    char *end;
    HRESULT hr;
    ULONG id;

    TRACE( "iface %p, titleId %p\n", This, titleId );

    if (!titleId) return E_POINTER;

    if (SUCCEEDED( hr = read_microsoft_game_config( &config ) ))
    {
        if (find_config_value( config, "TitleId", value, sizeof( value ) ) ||
            find_config_value( config, "XboxTitleId", value, sizeof( value ) ))
        {
            id = strtoul( value, &end, 0 );
            if (end != value)
            {
                *titleId = id;
                free( config );
                return S_OK;
            }
        }
        free( config );
    }

    FIXME( "failed to read TitleId from MicrosoftGame.Config, falling back to Minecraft title id\n" );
    *titleId = 0x35760C07;
    return S_OK;
}

HRESULT STUB1(IXGameLaunchImpl *This) {
    return E_NOTIMPL;
}


HRESULT STUB2(IXGameLaunchImpl *This) {
    return E_NOTIMPL;
}


static const struct IXGameLaunchImplVtbl x_gamelaunch_vtbl =
{
    /* IUnknown methods */
    x_game_launch_QueryInterface,
    x_game_launch_AddRef,
    x_game_launch_Release,
    /*** IXGameLaunch methods ***/
    XGameGetXboxTitleId,
    STUB1,
    STUB2
};

static struct x_game_launch x_game_launch = {
    {&x_gamelaunch_vtbl},
    0,
};

IXGameLaunchImpl *x_game_launch_impl = &x_game_launch.IXGameLaunch_iface;
