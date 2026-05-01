/*
 * Copyright 2026 Olivia Ryan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "Token.h"

WINE_DEFAULT_DEBUG_CHANNEL(gdkc);

#define TOKEN_STORE_REG_KEY "Software\\Wine\\WineGDK\\XUser"
#define TOKEN_STORE_CLIENT_ID_VALUE "ClientId"
#define TOKEN_STORE_REFRESH_TOKEN_VALUE "RefreshToken"

#define GetJsonValue( obj_type, ret_type )                                                          \
static inline HRESULT GetJson##obj_type##Value( IJsonObject *object, LPCWSTR key, ret_type value )  \
{                                                                                                   \
    HSTRING_HEADER key_hdr;                                                                         \
    HSTRING key_hstr;                                                                               \
    HRESULT hr;                                                                                     \
                                                                                                    \
    if (FAILED( hr = WindowsCreateStringReference( key, wcslen( key ), &key_hdr, &key_hstr ) ))     \
        return hr;                                                                                  \
                                                                                                    \
    if (FAILED( hr = IJsonObject_GetNamed##obj_type( object, key_hstr, value ) ))                   \
        return hr;                                                                                  \
                                                                                                    \
    return S_OK;                                                                                    \
}

GetJsonValue( Array, IJsonArray** );
GetJsonValue( Number, DOUBLE* );
GetJsonValue( Object, IJsonObject** );
GetJsonValue( String, HSTRING* );

HRESULT HSTRINGToMultiByte( HSTRING hstr, LPSTR *str, UINT32 *str_len )
{
    UINT32 wstr_len;
    LPCWSTR wstr = WindowsGetStringRawBuffer( hstr, &wstr_len );

    if (!(*str_len = WideCharToMultiByte( CP_UTF8, 0, wstr, wstr_len, NULL, 0, NULL, NULL )))
        return HRESULT_FROM_WIN32( GetLastError() );

    if (!(*str = calloc( 1, *str_len ))) return E_OUTOFMEMORY;

    if (!(*str_len = WideCharToMultiByte( CP_UTF8, 0, wstr, wstr_len, *str, *str_len, NULL, NULL )))
    {
        free( *str );
        *str = NULL;
        return HRESULT_FROM_WIN32( GetLastError() );
    }

    return S_OK;
}

static HRESULT HttpRequest( LPCWSTR method, LPCWSTR domain, LPCWSTR object, LPSTR data, LPCWSTR headers, LPCWSTR *accept, LPSTR *buffer, SIZE_T *bufferSize )
{
    HINTERNET connection = NULL;
    DWORD size = sizeof( DWORD );
    HINTERNET session = NULL;
    HINTERNET request = NULL;
    HRESULT hr = S_OK;
    DWORD status;

    if (!(session = WinHttpOpen(
        L"WineGDK/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    ))) return HRESULT_FROM_WIN32( GetLastError() );

    if (!(connection = WinHttpConnect(
        session,
        domain,
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    ))) hr = HRESULT_FROM_WIN32( GetLastError() );

    if (SUCCEEDED( hr ) && !(request = WinHttpOpenRequest(
        connection,
        method,
        object,
        NULL,
        WINHTTP_NO_REFERER,
        accept,
        WINHTTP_FLAG_SECURE
    ))) hr = HRESULT_FROM_WIN32( GetLastError() );

    if (SUCCEEDED( hr ) && !WinHttpSendRequest(
        request,
        headers,
        -1,
        data,
        strlen( data ),
        strlen( data ),
        0
    )) hr = HRESULT_FROM_WIN32( GetLastError() );

    if (SUCCEEDED( hr ) && !WinHttpReceiveResponse( request, NULL ))
        hr = HRESULT_FROM_WIN32( GetLastError() );

    if (SUCCEEDED( hr ) && !WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status,
        &size,
        WINHTTP_NO_HEADER_INDEX
    )) hr = HRESULT_FROM_WIN32( GetLastError() );

    if (SUCCEEDED( hr ) && status / 100 != 2) hr = E_FAIL;

    /* buffer response data */
    *buffer = NULL;
    *bufferSize = 0;
    if (SUCCEEDED( hr ))
    {
        do
        {
            if (!(WinHttpQueryDataAvailable( request, &size )))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                break;
            }

            if (!size) break;
            if (!(*buffer = realloc( *buffer, *bufferSize + size )))
            {
                hr = E_OUTOFMEMORY;
                break;
            }

            if (!(WinHttpReadData( request, *buffer + *bufferSize, size, &size )))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                break;
            }

            *bufferSize += size;
        }
        while (size);
    }

    if (connection) WinHttpCloseHandle( connection );
    if (request) WinHttpCloseHandle( request );
    if (session) WinHttpCloseHandle( session );
    if (FAILED( hr ) && *buffer) free( *buffer );

    return hr;
}

static HRESULT ParseJsonObject( LPCSTR str, UINT32 str_size, IJsonObject **object )
{
    LPCWSTR class_str = RuntimeClass_Windows_Data_Json_JsonValue;
    IJsonValueStatics *statics;
    HSTRING_HEADER content_hdr;
    HSTRING_HEADER class_hdr;
    IJsonValue *value;
    UINT32 wstr_size;
    HSTRING content;
    HSTRING class;
    LPWSTR wstr;
    HRESULT hr;

    if (!(wstr_size = MultiByteToWideChar( CP_UTF8, 0, str, str_size, NULL, 0 )))
        return HRESULT_FROM_WIN32( GetLastError() );

    if (!(wstr = calloc( wstr_size, sizeof( WCHAR ) )))
        return E_OUTOFMEMORY;

    if (!(wstr_size = MultiByteToWideChar( CP_UTF8, 0, str, str_size, wstr, wstr_size )))
    {
        free( wstr );
        return HRESULT_FROM_WIN32( GetLastError() );
    }

    if (FAILED( hr = WindowsCreateStringReference( wstr, wstr_size, &content_hdr, &content ) ))
    {
        free( wstr );
        return hr;
    }

    if (FAILED( hr = WindowsCreateStringReference( class_str, wcslen( class_str ), &class_hdr, &class ) ))
    {
        free( wstr );
        return hr;
    }

    if (FAILED( hr = RoGetActivationFactory( class, &IID_IJsonValueStatics, (void**)&statics ) ))
    {
        free( wstr );
        return hr;
    }

    hr = IJsonValueStatics_Parse( statics, content, &value );
    IJsonValueStatics_Release( statics );
    free( wstr );
    if (FAILED( hr )) return hr;

    hr = IJsonValue_GetObject( value, object );
    IJsonValue_Release( value );
    if (FAILED( hr )) IJsonObject_Release( *object );

    return hr;
}

static HRESULT ReadFileBytesA( LPCSTR path, LPSTR *buffer, SIZE_T *size )
{
    FILE *file;
    long file_size;

    *buffer = NULL;
    *size = 0;

    if (!(file = fopen( path, "rb" ))) return HRESULT_FROM_WIN32( GetLastError() );
    if (fseek( file, 0, SEEK_END ) || (file_size = ftell( file )) < 0)
    {
        fclose( file );
        return E_FAIL;
    }
    rewind( file );

    if (!(*buffer = calloc( file_size + 1, sizeof( CHAR ) )))
    {
        fclose( file );
        return E_OUTOFMEMORY;
    }
    if (file_size && fread( *buffer, 1, file_size, file ) != file_size)
    {
        free( *buffer );
        *buffer = NULL;
        fclose( file );
        return E_FAIL;
    }
    fclose( file );
    *size = file_size;
    return S_OK;
}

static HRESULT ReadFileBytesW( LPCWSTR path, LPSTR *buffer, SIZE_T *size )
{
    FILE *file;
    long file_size;

    *buffer = NULL;
    *size = 0;

    if (!(file = _wfopen( path, L"rb" ))) return HRESULT_FROM_WIN32( GetLastError() );
    if (fseek( file, 0, SEEK_END ) || (file_size = ftell( file )) < 0)
    {
        fclose( file );
        return E_FAIL;
    }
    rewind( file );

    if (!(*buffer = calloc( file_size + 1, sizeof( CHAR ) )))
    {
        fclose( file );
        return E_OUTOFMEMORY;
    }
    if (file_size && fread( *buffer, 1, file_size, file ) != file_size)
    {
        free( *buffer );
        *buffer = NULL;
        fclose( file );
        return E_FAIL;
    }
    fclose( file );
    *size = file_size;
    return S_OK;
}

static HRESULT ExtractJsonStringA( LPCSTR json, LPCSTR key, LPSTR *value )
{
    LPCSTR pos, start, end;
    SIZE_T key_len, len;

    *value = NULL;
    key_len = strlen( key );
    if (!(pos = strstr( json, key ))) return E_FAIL;
    pos += key_len;
    if (!(pos = strchr( pos, ':' ))) return E_FAIL;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != '"') return E_FAIL;
    start = ++pos;
    while (*pos)
    {
        if (*pos == '"' && (pos == start || pos[-1] != '\\')) break;
        pos++;
    }
    if (*pos != '"') return E_FAIL;
    end = pos;
    len = end - start;
    if (!(*value = calloc( len + 1, sizeof( CHAR ) ))) return E_OUTOFMEMORY;
    memcpy( *value, start, len );
    return S_OK;
}

static HRESULT ExtractJsonNumberA( LPCSTR json, LPCSTR key, DWORD *value )
{
    LPCSTR pos;

    if (!(pos = strstr( json, key ))) return E_FAIL;
    pos += strlen( key );
    if (!(pos = strchr( pos, ':' ))) return E_FAIL;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    *value = strtoul( pos, NULL, 10 );
    return S_OK;
}

static HRESULT HStringToNulString( HSTRING hstr, LPSTR *str )
{
    UINT32 len;
    LPSTR tmp;
    HRESULT hr;

    if (FAILED( hr = HSTRINGToMultiByte( hstr, str, &len ) )) return hr;
    if (!(tmp = realloc( *str, len + 1 )))
    {
        free( *str );
        *str = NULL;
        return E_OUTOFMEMORY;
    }
    *str = tmp;
    (*str)[len] = 0;
    return S_OK;
}

static HRESULT CreateHStringFromUtf8( LPCSTR str, HSTRING *hstr )
{
    int len;
    LPWSTR wide;
    HRESULT hr;

    *hstr = NULL;
    if (!(len = MultiByteToWideChar( CP_UTF8, 0, str, -1, NULL, 0 )))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!(wide = calloc( len, sizeof( WCHAR ) ))) return E_OUTOFMEMORY;
    if (!MultiByteToWideChar( CP_UTF8, 0, str, -1, wide, len ))
    {
        free( wide );
        return HRESULT_FROM_WIN32( GetLastError() );
    }
    hr = WindowsCreateString( wide, len - 1, hstr );
    free( wide );
    return hr;
}

static HRESULT LoadRegistryStringHString( HKEY key, LPCSTR name, HSTRING *value )
{
    char *buffer;
    DWORD type, size = 0;
    LSTATUS status;
    HRESULT hr;

    *value = NULL;

    status = RegQueryValueExA( key, name, NULL, &type, NULL, &size );
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32( status );
    if (type != REG_SZ || !size) return E_INVALIDARG;
    if (!(buffer = calloc( size + 1, sizeof( CHAR ) ))) return E_OUTOFMEMORY;

    status = RegQueryValueExA( key, name, NULL, &type, (BYTE *)buffer, &size );
    if (status == ERROR_SUCCESS && type == REG_SZ)
        hr = CreateHStringFromUtf8( buffer, value );
    else
        hr = status == ERROR_SUCCESS ? E_INVALIDARG : HRESULT_FROM_WIN32( status );

    free( buffer );
    return hr;
}

static HRESULT LoadTokenStoreFromRegistry( HSTRING *client_id, HSTRING *refresh_token )
{
    HKEY key;
    LSTATUS status;
    HRESULT hr;

    *client_id = NULL;
    *refresh_token = NULL;

    status = RegOpenKeyExA( HKEY_CURRENT_USER, TOKEN_STORE_REG_KEY, 0, KEY_READ, &key );
    if (status != ERROR_SUCCESS) return E_GAMEUSER_NO_DEFAULT_USER;

    hr = LoadRegistryStringHString( key, TOKEN_STORE_CLIENT_ID_VALUE, client_id );
    if (SUCCEEDED( hr ))
        hr = LoadRegistryStringHString( key, TOKEN_STORE_REFRESH_TOKEN_VALUE, refresh_token );
    RegCloseKey( key );
    if (FAILED( hr ))
    {
        if (*client_id) WindowsDeleteString( *client_id );
        if (*refresh_token) WindowsDeleteString( *refresh_token );
        *client_id = NULL;
        *refresh_token = NULL;
        return E_GAMEUSER_NO_DEFAULT_USER;
    }

    return S_OK;
}

static HRESULT SaveTokenStoreToRegistry( LPCSTR client_id, LPCSTR refresh_token )
{
    HKEY key;
    LSTATUS status;

    status = RegCreateKeyExA( HKEY_CURRENT_USER, TOKEN_STORE_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                              KEY_READ | KEY_WRITE, NULL, &key, NULL );
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32( status );

    status = RegSetValueExA( key, TOKEN_STORE_CLIENT_ID_VALUE, 0, REG_SZ, (const BYTE *)client_id, strlen( client_id ) + 1 );
    if (status == ERROR_SUCCESS)
        status = RegSetValueExA( key, TOKEN_STORE_REFRESH_TOKEN_VALUE, 0, REG_SZ, (const BYTE *)refresh_token, strlen( refresh_token ) + 1 );
    RegCloseKey( key );

    return status == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32( status );
}

HRESULT SaveTokenStoreRefreshToken( HSTRING client_id_hstr, HSTRING refresh_token_hstr )
{
    LPSTR client_id = NULL, refresh_token = NULL;
    HRESULT hr;

    if (FAILED( hr = HStringToNulString( client_id_hstr, &client_id ) )) return hr;
    if (FAILED( hr = HStringToNulString( refresh_token_hstr, &refresh_token ) ))
    {
        free( client_id );
        return hr;
    }

    hr = SaveTokenStoreToRegistry( client_id, refresh_token );
    free( client_id );
    free( refresh_token );
    return hr;
}

static HRESULT HttpRequestWithStatus( LPCWSTR method, LPCWSTR domain, LPCWSTR object, LPCSTR data, LPCWSTR headers, LPSTR *buffer, SIZE_T *bufferSize, DWORD *status )
{
    HINTERNET connection = NULL, session = NULL, request = NULL;
    DWORD size = sizeof( DWORD ), data_len;
    HRESULT hr = S_OK;

    *buffer = NULL;
    *bufferSize = 0;
    *status = 0;
    data_len = data ? strlen( data ) : 0;

    if (!(session = WinHttpOpen( L"WineGDK/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 )))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!(connection = WinHttpConnect( session, domain, INTERNET_DEFAULT_HTTPS_PORT, 0 ))) hr = HRESULT_FROM_WIN32( GetLastError() );
    if (SUCCEEDED( hr ) && !(request = WinHttpOpenRequest( connection, method, object, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE )))
        hr = HRESULT_FROM_WIN32( GetLastError() );
    if (SUCCEEDED( hr ) && !WinHttpSendRequest( request, headers, -1, (LPVOID)data, data_len, data_len, 0 ))
        hr = HRESULT_FROM_WIN32( GetLastError() );
    if (SUCCEEDED( hr ) && !WinHttpReceiveResponse( request, NULL )) hr = HRESULT_FROM_WIN32( GetLastError() );
    if (SUCCEEDED( hr ) && !WinHttpQueryHeaders( request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, status, &size, WINHTTP_NO_HEADER_INDEX ))
        hr = HRESULT_FROM_WIN32( GetLastError() );

    if (SUCCEEDED( hr ))
    {
        do
        {
            if (!WinHttpQueryDataAvailable( request, &size ))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                break;
            }
            if (!size) break;
            if (!(*buffer = realloc( *buffer, *bufferSize + size + 1 )))
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            if (!WinHttpReadData( request, *buffer + *bufferSize, size, &size ))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                break;
            }
            *bufferSize += size;
            (*buffer)[*bufferSize] = 0;
        }
        while (size);
    }

    if (request) WinHttpCloseHandle( request );
    if (connection) WinHttpCloseHandle( connection );
    if (session) WinHttpCloseHandle( session );
    if (FAILED( hr ) && *buffer)
    {
        free( *buffer );
        *buffer = NULL;
        *bufferSize = 0;
    }
    return hr;
}

HRESULT LoadTokenStore( LPCSTR path, HSTRING *client_id, HSTRING *refresh_token )
{
    IJsonObject *root = NULL, *app_params = NULL, *live_token = NULL;
    LPSTR buffer;
    SIZE_T size;
    HRESULT hr;

    *client_id = NULL;
    *refresh_token = NULL;

    if (SUCCEEDED( LoadTokenStoreFromRegistry( client_id, refresh_token ) )) return S_OK;

    if (FAILED( hr = ReadFileBytesA( path, &buffer, &size ) )) return E_GAMEUSER_NO_DEFAULT_USER;
    hr = ParseJsonObject( buffer, size, &root );
    free( buffer );
    if (FAILED( hr )) return E_GAMEUSER_NO_DEFAULT_USER;

    if (SUCCEEDED( hr = GetJsonObjectValue( root, L"app_params", &app_params ) ))
        hr = GetJsonStringValue( app_params, L"client_id", client_id );
    if (app_params) IJsonObject_Release( app_params );
    if (FAILED( hr )) goto failed;

    if (SUCCEEDED( hr = GetJsonObjectValue( root, L"live_token", &live_token ) ))
        hr = GetJsonStringValue( live_token, L"refresh_token", refresh_token );
    if (live_token) IJsonObject_Release( live_token );
    if (FAILED( hr )) goto failed;

    IJsonObject_Release( root );
    SaveTokenStoreRefreshToken( *client_id, *refresh_token );
    return S_OK;

failed:
    if (*client_id) WindowsDeleteString( *client_id );
    if (*refresh_token) WindowsDeleteString( *refresh_token );
    *client_id = NULL;
    *refresh_token = NULL;
    IJsonObject_Release( root );
    return E_GAMEUSER_NO_DEFAULT_USER;
}

HRESULT LoadClientIdFromGameConfig( HSTRING *client_id )
{
    WCHAR path[MAX_PATH], *slash;
    LPSTR buffer, value = NULL;
    SIZE_T size;
    HRESULT hr;
    LPCSTR keys[] =
    {
        "MSAAppId",
        "MSAApplicationId",
        "ClientId",
        "ClientID",
        "Identity",
    };

    *client_id = NULL;
    if (!GetModuleFileNameW( NULL, path, ARRAY_SIZE( path ) )) return HRESULT_FROM_WIN32( GetLastError() );
    if ((slash = wcsrchr( path, '\\' ))) slash[1] = 0;
    else path[0] = 0;
    lstrcatW( path, L"MicrosoftGame.Config" );

    if (FAILED( hr = ReadFileBytesW( path, &buffer, &size ) )) return hr;

    for (UINT i = 0; i < ARRAY_SIZE( keys ); i++)
    {
        char open_tag[64], close_tag[64], attr[64];
        LPSTR start, end;

        sprintf( open_tag, "<%s>", keys[i] );
        sprintf( close_tag, "</%s>", keys[i] );
        if ((start = strstr( buffer, open_tag )) && (end = strstr( start, close_tag )))
        {
            start += strlen( open_tag );
            if (!(value = calloc( end - start + 1, sizeof( CHAR ) )))
            {
                free( buffer );
                return E_OUTOFMEMORY;
            }
            memcpy( value, start, end - start );
            break;
        }

        sprintf( attr, "%s=\"", keys[i] );
        if ((start = strstr( buffer, attr )))
        {
            start += strlen( attr );
            if ((end = strchr( start, '"' )))
            {
                if (!(value = calloc( end - start + 1, sizeof( CHAR ) )))
                {
                    free( buffer );
                    return E_OUTOFMEMORY;
                }
                memcpy( value, start, end - start );
                break;
            }
        }
    }

    free( buffer );
    if (!value) return E_GAMEUSER_NO_MSAAPPID;
    hr = CreateHStringFromUtf8( value, client_id );
    free( value );
    return hr;
}

static HRESULT SaveTokenStore( LPCSTR path, LPCSTR client_id, LPCSTR access_token, LPCSTR refresh_token, DWORD expires_in, LPCSTR scope, LPCSTR token_type )
{
    FILE *file;
    HRESULT hr;

    if (SUCCEEDED( hr = SaveTokenStoreToRegistry( client_id, refresh_token ) )) return S_OK;

    if (!(file = fopen( path, "wb" ))) return HRESULT_FROM_WIN32( GetLastError() );
    fprintf( file,
             "{\"app_params\":{\"client_id\":\"%s\",\"auth_scopes\":[\"service::user.auth.xboxlive.com::MBI_SSL\"],\"redirect_uri\":\"https://login.live.com/oauth20_desktop.srf\"},"
             "\"client_params\":{\"user_agent\":\"WineGDK\",\"device_type\":\"PC\",\"client_version\":\"1.0\",\"query_display\":\"touch\"},"
             "\"sandbox_id\":\"RETAIL\","
             "\"live_token\":{\"access_token\":\"%s\",\"token_type\":\"%s\",\"expires_in\":%lu,\"refresh_token\":\"%s\",\"scope\":\"%s\"}}",
             client_id, access_token, token_type ? token_type : "bearer", expires_in, refresh_token, scope ? scope : "service::user.auth.xboxlive.com::MBI_SSL" );
    fclose( file );
    return S_OK;
}

HRESULT DeviceCodeLoginAndSaveTokenStore( HSTRING client_id_hstr, LPCSTR path )
{
    LPSTR client_id = NULL, data = NULL, buffer = NULL;
    LPSTR device_code = NULL, user_code = NULL, verification_uri = NULL;
    DWORD status, expires_in = 900, interval = 5, elapsed = 0;
    SIZE_T size;
    HRESULT hr;

    if (FAILED( hr = HStringToNulString( client_id_hstr, &client_id ) )) return hr;

    if (!(data = calloc( strlen( "client_id=&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=device_code" ) + strlen( client_id ) + 1, sizeof( CHAR ) )))
    {
        free( client_id );
        return E_OUTOFMEMORY;
    }
    strcpy( data, "client_id=" );
    strcat( data, client_id );
    strcat( data, "&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=device_code" );

    hr = HttpRequestWithStatus( L"POST", L"login.live.com", L"/oauth20_connect.srf", data, L"content-type: application/x-www-form-urlencoded", &buffer, &size, &status );
    free( data );
    if (FAILED( hr ) || status / 100 != 2)
    {
        free( client_id );
        free( buffer );
        return E_GAMEUSER_FAILED_TO_GET_TOKEN;
    }

    if (FAILED( ExtractJsonStringA( buffer, "\"device_code\"", &device_code ) ) ||
        FAILED( ExtractJsonStringA( buffer, "\"user_code\"", &user_code ) ) ||
        FAILED( ExtractJsonStringA( buffer, "\"verification_uri\"", &verification_uri ) ))
    {
        free( client_id );
        free( buffer );
        return E_GAMEUSER_FAILED_TO_GET_TOKEN;
    }
    ExtractJsonNumberA( buffer, "\"expires_in\"", &expires_in );
    ExtractJsonNumberA( buffer, "\"interval\"", &interval );
    free( buffer );
    buffer = NULL;

    FIXME( "WineGDK Xbox sign-in required: open https://login.live.com/oauth20_remoteconnect.srf?lc=1033&otc=%s or %s and enter code %s\n",
           user_code, verification_uri, user_code );

    while (elapsed < expires_in)
    {
        LPSTR access_token = NULL, refresh_token = NULL, scope = NULL, token_type = NULL, error = NULL;

        Sleep( interval * 1000 );
        elapsed += interval;

        if (!(data = calloc( strlen( "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=&device_code=" ) + strlen( client_id ) + strlen( device_code ) + 1, sizeof( CHAR ) )))
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        strcpy( data, "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=" );
        strcat( data, client_id );
        strcat( data, "&device_code=" );
        strcat( data, device_code );

        hr = HttpRequestWithStatus( L"POST", L"login.live.com", L"/oauth20_token.srf", data, L"content-type: application/x-www-form-urlencoded", &buffer, &size, &status );
        free( data );
        data = NULL;
        if (FAILED( hr )) break;

        if (status / 100 == 2 &&
            SUCCEEDED( ExtractJsonStringA( buffer, "\"access_token\"", &access_token ) ) &&
            SUCCEEDED( ExtractJsonStringA( buffer, "\"refresh_token\"", &refresh_token ) ))
        {
            ExtractJsonStringA( buffer, "\"scope\"", &scope );
            ExtractJsonStringA( buffer, "\"token_type\"", &token_type );
            ExtractJsonNumberA( buffer, "\"expires_in\"", &expires_in );
            hr = SaveTokenStore( path, client_id, access_token, refresh_token, expires_in, scope, token_type );
            free( access_token );
            free( refresh_token );
            free( scope );
            free( token_type );
            free( buffer );
            goto done;
        }

        if (SUCCEEDED( ExtractJsonStringA( buffer, "\"error\"", &error ) ))
        {
            if (!strcmp( error, "slow_down" )) interval += 5;
            else if (strcmp( error, "authorization_pending" ))
            {
                free( error );
                free( buffer );
                hr = E_GAMEUSER_FAILED_TO_GET_TOKEN;
                break;
            }
            free( error );
        }
        free( buffer );
        buffer = NULL;
    }

    hr = E_GAMEUSER_FAILED_TO_GET_TOKEN;

done:
    free( client_id );
    free( device_code );
    free( user_code );
    free( verification_uri );
    free( data );
    return hr;
}

HRESULT RefreshOAuth( LPCSTR client_id, LPCSTR refresh_token, time_t *new_expiry, HSTRING *new_refresh_token, HSTRING *new_oauth_token )
{
    LPCSTR template = "grant_type=refresh_token&scope=service::user.auth.xboxlive.com::MBI_SSL&client_id=";
    LPCWSTR accept[] = {L"application/json", NULL};
    IJsonObject *object;
    time_t expiry;
    LPSTR buffer;
    DOUBLE delta;
    SIZE_T size;
    HRESULT hr;
    LPSTR data;

    if (!(data = calloc( strlen( template ) + strlen( client_id ) + strlen( "&refresh_token=" ) + strlen( refresh_token ) + 1, sizeof( CHAR ) )))
        return E_OUTOFMEMORY;

    strcpy( data, template );
    strcat( data, client_id );
    strcat( data, "&refresh_token=" );
    strcat( data, refresh_token );

    hr = HttpRequest(
        L"POST",
        L"login.live.com",
        L"/oauth20_token.srf",
        data,
        L"content-type: application/x-www-form-urlencoded",
        accept,
        &buffer,
        &size
    );

    free( data );
    if (FAILED( hr )) return hr;
    hr = ParseJsonObject( buffer, size, &object );
    free( buffer );
    if (FAILED( hr )) return hr;

    if (FAILED( hr = GetJsonStringValue( object, L"access_token", new_oauth_token ) ))
    {
        IJsonObject_Release( object );
        return hr;
    }

    if (FAILED( hr = GetJsonStringValue( object, L"refresh_token", new_refresh_token ) ))
    {
        IJsonObject_Release( object );
        return hr;
    }

    if (FAILED( hr = GetJsonNumberValue( object, L"expires_in", &delta ) ))
    IJsonObject_Release( object );
    if (FAILED( hr )) return hr;

    if ((expiry = time( NULL )) == -1) return E_FAIL;
    *new_expiry = expiry + delta;

    return S_OK;
}

HRESULT RequestUserToken( HSTRING oauth_token, HSTRING *token, XUserLocalId *local_id )
{
    LPCSTR template = "{\"RelyingParty\":\"http://auth.xboxlive.com\",\"TokenType\":\"JWT\",\"Properties\":{\"AuthMethod\":\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"RpsTicket\":\"";
    LPCWSTR accept[] = {L"application/json", NULL};
    IJsonObject *display_claims;
    UINT32 token_str_len;
    IJsonObject *object;
    UINT32 uhs_str_len;
    LPSTR token_str;
    IJsonArray *xui;
    LPSTR uhs_str;
    LPSTR buffer;
    SIZE_T size;
    HSTRING uhs;
    LPSTR data;
    HRESULT hr;

    if (FAILED( hr = HSTRINGToMultiByte( oauth_token, &token_str, &token_str_len ) ))
    {
        FIXME( "RequestUserToken HSTRINGToMultiByte returned %#lx\n", hr );
        return hr;
    }

    if (!(data = calloc( strlen( template ) + token_str_len + strlen( "\"}}" ) + 1, sizeof( CHAR ) )))
    {
        free( token_str );
        FIXME( "RequestUserToken request allocation returned %#lx\n", E_OUTOFMEMORY );
        return E_OUTOFMEMORY;
    }

    strcpy( data, template );
    strncat( data, token_str, token_str_len );
    free( token_str );
    strcat( data, "\"}}" );

    hr = HttpRequest(
        L"POST",
        L"user.auth.xboxlive.com",
        L"/user/authenticate",
        data,
        L"content-type: application/json",
        accept,
        &buffer,
        &size
    );

    free( data );
    if (FAILED( hr ))
    {
        FIXME( "RequestUserToken HttpRequest returned %#lx\n", hr );
        return hr;
    }
    hr = ParseJsonObject( buffer, size, &object );
    free( buffer );
    if (FAILED( hr ))
    {
        FIXME( "RequestUserToken ParseJsonObject returned %#lx\n", hr );
        return hr;
    }

    if (FAILED( hr = GetJsonStringValue( object, L"Token", token ) ))
    {
        IJsonObject_Release( object );
        FIXME( "RequestUserToken Token field returned %#lx\n", hr );
        return hr;
    }

    hr = GetJsonObjectValue( object, L"DisplayClaims", &display_claims );
    IJsonObject_Release( object );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        FIXME( "RequestUserToken DisplayClaims returned %#lx\n", hr );
        return hr;
    }

    hr = GetJsonArrayValue( display_claims, L"xui", &xui );
    IJsonObject_Release( display_claims );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        FIXME( "RequestUserToken xui returned %#lx\n", hr );
        return hr;
    }

    hr = IJsonArray_GetObjectAt( xui, 0, &object );
    IJsonArray_Release( xui );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        FIXME( "RequestUserToken xui[0] returned %#lx\n", hr );
        return hr;
    }

    hr = GetJsonStringValue( object, L"uhs", &uhs );
    IJsonObject_Release( object );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        FIXME( "RequestUserToken uhs returned %#lx\n", hr );
        return hr;
    }

    hr = HSTRINGToMultiByte( uhs, &uhs_str, &uhs_str_len );
    WindowsDeleteString( uhs );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        FIXME( "RequestUserToken uhs conversion returned %#lx\n", hr );
        return hr;
    }

    local_id->value = strtoull( uhs_str, NULL, 10 );
    free( uhs_str );
    if (errno == ERANGE)
    {
        WindowsDeleteString( *token );
        errno = 0;
        FIXME( "RequestUserToken local id parse returned %#lx\n", E_FAIL );
        return E_FAIL;
    }

    FIXME( "RequestUserToken returning %#lx\n", hr );
    return hr;
}

HRESULT RequestXstsTokenWithUserHash( HSTRING user_token, HSTRING *token, HSTRING *user_hash, HSTRING *gamertag, UINT64 *xuid, XUserAgeGroup *age_group )
{
    LPCSTR template = "{\"RelyingParty\":\"http://xboxlive.com\",\"TokenType\":\"JWT\",\"Properties\":{\"SandboxId\":\"RETAIL\",\"UserTokens\":[\"";
    LPCWSTR accept[] = {L"application/json", NULL};
    IJsonObject *display_claims;
    UINT32 token_str_len;
    IJsonObject *object;
    UINT32 xid_str_len;
    LPCWSTR agg_str;
    LPSTR token_str;
    IJsonArray *xui;
    UINT32 agg_len;
    LPSTR xid_str;
    LPSTR buffer;
    HSTRING agg;
    SIZE_T size;
    HSTRING xid;
    HRESULT hr;
    LPSTR data;

    *user_hash = NULL;
    if (gamertag) *gamertag = NULL;

    if (FAILED( hr = HSTRINGToMultiByte( user_token, &token_str, &token_str_len ) ))
        return hr;

    if (!(data = calloc( strlen( template ) + token_str_len + strlen( "\"]}}" ) + 1, sizeof( CHAR ) )))
    {
        free( token_str );
        return E_OUTOFMEMORY;
    }

    strcpy( data, template );
    strncat(data, token_str, token_str_len);
    free( token_str );
    strcat( data, "\"]}}" );

    hr = HttpRequest(
        L"POST",
        L"xsts.auth.xboxlive.com",
        L"/xsts/authorize",
        data,
        L"content-type: application/json",
        accept,
        &buffer,
        &size
    );

    free( data );
    if (FAILED( hr )) return hr;
    hr = ParseJsonObject( buffer, size, &object );
    free( buffer );
    if (FAILED( hr )) return hr;

    if (FAILED( hr = GetJsonStringValue( object, L"Token", token ) ))
    {
        IJsonObject_Release( object );
        return hr;
    }

    hr = GetJsonObjectValue( object, L"DisplayClaims", &display_claims );
    IJsonObject_Release( object );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        return hr;
    }

    hr = GetJsonArrayValue( display_claims, L"xui", &xui );
    IJsonObject_Release( display_claims );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        return hr;
    }

    hr = IJsonArray_GetObjectAt( xui, 0, &object );
    IJsonArray_Release( xui );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        return hr;
    }

    if (FAILED( hr = GetJsonStringValue( object, L"uhs", user_hash )))
    {
        IJsonObject_Release( object );
        WindowsDeleteString( *token );
        return hr;
    }

    if (gamertag)
    {
        HSTRING tmp;
        if (SUCCEEDED( GetJsonStringValue( object, L"gtg", &tmp ) ))
            *gamertag = tmp;
    }

    if (FAILED( hr = GetJsonStringValue( object, L"agg", &agg )))
    {
        IJsonObject_Release( object );
        WindowsDeleteString( *token );
        WindowsDeleteString( *user_hash );
        return hr;
    }

    agg_str = WindowsGetStringRawBuffer( agg, &agg_len );
    if (agg_len >= 5 && !wcsncmp( agg_str, L"Child", 5 )) *age_group = XUserAgeGroup_Child;
    else if (agg_len >= 4 && !wcsncmp( agg_str, L"Teen", 4 )) *age_group = XUserAgeGroup_Teen;
    else if (agg_len >= 5 && !wcsncmp( agg_str, L"Adult", 5 )) *age_group = XUserAgeGroup_Adult;
    else *age_group = XUserAgeGroup_Unknown;
    WindowsDeleteString( agg );

    hr = GetJsonStringValue( object, L"xid", &xid );
    IJsonObject_Release( object );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        WindowsDeleteString( *user_hash );
        return hr;
    }

    hr = HSTRINGToMultiByte( xid, &xid_str, &xid_str_len );
    WindowsDeleteString( xid );
    if (FAILED( hr ))
    {
        WindowsDeleteString( *token );
        WindowsDeleteString( *user_hash );
        return hr;
    }

    *xuid = strtoull( xid_str, NULL, 10 );
    free( xid_str );
    if (errno == ERANGE)
    {
        WindowsDeleteString( *token );
        WindowsDeleteString( *user_hash );
        errno = 0;
        return E_FAIL;
    }

    return hr;
}

HRESULT RequestXstsToken( HSTRING user_token, HSTRING *token, UINT64 *xuid, XUserAgeGroup *age_group )
{
    HSTRING user_hash, gamertag;
    HRESULT hr = RequestXstsTokenWithUserHash( user_token, token, &user_hash, &gamertag, xuid, age_group );

    if (SUCCEEDED( hr ))
    {
        WindowsDeleteString( user_hash );
        if (gamertag) WindowsDeleteString( gamertag );
    }
    return hr;
}
