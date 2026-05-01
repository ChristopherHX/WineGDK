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

/*
 * Xbox Game runtime Library
 * GDK Component: System API -> XUser
 */

#include "XUser.h"
#include "winhttp.h"
#include "wincrypt.h"
#include <ctype.h>

WINE_DEFAULT_DEBUG_CHANNEL(gdkc);

static const struct IXUserImplVtbl x_user_vtbl;
static const struct IXUserGamertagVtbl x_user_gt_vtbl;
static struct x_user x_user;
static struct x_user *default_user;
static SRWLOCK default_user_lock = SRWLOCK_INIT;

#define XUSER_SIGNATURE_POLICY_VERSION 1
#define XUSER_SIGNATURE_MAX_BODY_BYTES 8192

#undef TRACE
#define TRACE FIXME

static void x_user_free_members( struct x_user *impl )
{
    if (impl->refresh_token) WindowsDeleteString( impl->refresh_token );
    if (impl->oauth_token) WindowsDeleteString( impl->oauth_token );
    if (impl->user_token) WindowsDeleteString( impl->user_token );
    if (impl->xsts_token) WindowsDeleteString( impl->xsts_token );
    if (impl->user_hash) WindowsDeleteString( impl->user_hash );
    if (impl->gamertag) WindowsDeleteString( impl->gamertag );
    if (impl->client_id) WindowsDeleteString( impl->client_id );
    if (impl->authorization) free( impl->authorization );
    if (impl->signing_key) BCryptDestroyKey( impl->signing_key );
}

static HRESULT hstring_to_nul_string( HSTRING hstr, LPSTR *str )
{
    UINT32 len;
    HRESULT hr;
    LPSTR tmp;

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

static HRESULT create_authorization_header( struct x_user *impl )
{
    LPSTR user_hash = NULL, token = NULL;
    UINT32 user_hash_len, token_len;
    HRESULT hr;

    if (impl->authorization)
    {
        free( impl->authorization );
        impl->authorization = NULL;
    }

    if (FAILED( hr = HSTRINGToMultiByte( impl->user_hash, &user_hash, &user_hash_len ) )) return hr;
    if (FAILED( hr = HSTRINGToMultiByte( impl->xsts_token, &token, &token_len ) ))
    {
        free( user_hash );
        return hr;
    }

    if (!(impl->authorization = calloc( strlen( "XBL3.0 x=;" ) + user_hash_len + token_len + 1, sizeof( CHAR ) )))
    {
        free( user_hash );
        free( token );
        return E_OUTOFMEMORY;
    }

    strcpy( impl->authorization, "XBL3.0 x=" );
    strncat( impl->authorization, user_hash, user_hash_len );
    strcat( impl->authorization, ";" );
    strncat( impl->authorization, token, token_len );
    free( user_hash );
    free( token );
    return S_OK;
}

static HRESULT create_signing_key( BCRYPT_KEY_HANDLE *key )
{
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status;

    *key = NULL;
    if ((status = BCryptOpenAlgorithmProvider( &alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0 )))
        return HRESULT_FROM_NT( status );
    if ((status = BCryptGenerateKeyPair( alg, key, 256, 0 )))
    {
        BCryptCloseAlgorithmProvider( alg, 0 );
        return HRESULT_FROM_NT( status );
    }
    status = BCryptFinalizeKeyPair( *key, 0 );
    BCryptCloseAlgorithmProvider( alg, 0 );
    if (status)
    {
        BCryptDestroyKey( *key );
        *key = NULL;
        return HRESULT_FROM_NT( status );
    }
    return S_OK;
}

static HRESULT refresh_user_tokens( struct x_user *impl, BOOL force )
{
    HSTRING refresh_token = NULL, oauth_token = NULL, user_token = NULL, xsts_token = NULL, user_hash = NULL, gamertag = NULL;
    LPSTR client_id = NULL, old_refresh = NULL;
    time_t expiry, now;
    HRESULT hr;

    now = time( NULL );
    if (!force && impl->authorization && impl->oauth_token_expiry > now + 300) return S_OK;

    if (FAILED( hr = hstring_to_nul_string( impl->client_id, &client_id ) )) return hr;
    if (FAILED( hr = hstring_to_nul_string( impl->refresh_token, &old_refresh ) ))
    {
        free( client_id );
        return hr;
    }

    hr = RefreshOAuth( client_id, old_refresh, &expiry, &refresh_token, &oauth_token );
    free( client_id );
    free( old_refresh );
    if (FAILED( hr )) return E_GAMEUSER_FAILED_TO_GET_TOKEN;

    if (FAILED( hr = RequestUserToken( oauth_token, &user_token, &impl->local_id ) )) goto failed;
    if (FAILED( hr = RequestXstsTokenWithUserHash( user_token, &xsts_token, &user_hash, &gamertag, &impl->xuid, &impl->age_group ) )) goto failed;

    if (impl->refresh_token) WindowsDeleteString( impl->refresh_token );
    if (impl->oauth_token) WindowsDeleteString( impl->oauth_token );
    if (impl->user_token) WindowsDeleteString( impl->user_token );
    if (impl->xsts_token) WindowsDeleteString( impl->xsts_token );
    if (impl->user_hash) WindowsDeleteString( impl->user_hash );
    impl->refresh_token = refresh_token;
    impl->oauth_token = oauth_token;
    impl->user_token = user_token;
    impl->xsts_token = xsts_token;
    impl->user_hash = user_hash;
    if (gamertag)
    {
        if (impl->gamertag) WindowsDeleteString( impl->gamertag );
        impl->gamertag = gamertag;
    }
    impl->oauth_token_expiry = expiry;

    return create_authorization_header( impl );

failed:
    if (refresh_token) WindowsDeleteString( refresh_token );
    if (oauth_token) WindowsDeleteString( oauth_token );
    if (user_token) WindowsDeleteString( user_token );
    if (xsts_token) WindowsDeleteString( xsts_token );
    if (user_hash) WindowsDeleteString( user_hash );
    if (gamertag) WindowsDeleteString( gamertag );
    return E_GAMEUSER_FAILED_TO_GET_TOKEN;
}

static HRESULT create_default_user( struct x_user **out, XUserAddOptions options )
{
    HSTRING client_id = NULL, refresh_token = NULL;
    struct x_user *impl;
    HRESULT hr;

    *out = NULL;

    hr = LoadTokenStore( "tokens.json", &client_id, &refresh_token );
    if (FAILED( hr )/* && (options & XUserAddOptions_AddDefaultUserAllowingUI) */)
    {
        if (SUCCEEDED( hr = LoadClientIdFromGameConfig( &client_id ) ))
        {
            hr = DeviceCodeLoginAndSaveTokenStore( client_id, "tokens.json" );
            WindowsDeleteString( client_id );
            client_id = NULL;
            if (SUCCEEDED( hr )) hr = LoadTokenStore( "tokens.json", &client_id, &refresh_token );
        }
    }
    if (FAILED( hr )) return hr;

    if (!(impl = calloc( 1, sizeof( *impl ) )))
    {
        WindowsDeleteString( client_id );
        WindowsDeleteString( refresh_token );
        return E_OUTOFMEMORY;
    }

    impl->IXUserImpl_iface.lpVtbl = &x_user_vtbl;
    impl->IXUserGamertag_iface.lpVtbl = &x_user_gt_vtbl;
    impl->ref = 1;
    impl->heap_allocated = TRUE;
    impl->cached_default = TRUE;
    impl->client_id = client_id;
    impl->refresh_token = refresh_token;

    if (FAILED( hr = create_signing_key( &impl->signing_key ) ) ||
        FAILED( hr = refresh_user_tokens( impl, TRUE ) ))
    {
        x_user_free_members( impl );
        free( impl );
        return hr;
    }

    *out = impl;
    return S_OK;
}

static HRESULT LoadDefaultUser( XUserHandle *user, XUserAddOptions options )
{
    HRESULT hr = S_OK;

    if (!user) return E_POINTER;
    *user = NULL;

    AcquireSRWLockExclusive( &default_user_lock );
    if (!default_user)
        hr = create_default_user( &default_user, options );
    if (SUCCEEDED( hr ))
    {
        IXUserImpl_AddRef( &default_user->IXUserImpl_iface );
        *user = (XUserHandle)default_user;
    }
    ReleaseSRWLockExclusive( &default_user_lock );
    return hr;
}

static inline struct x_user *impl_from_IXUserImpl( IXUserImpl *iface )
{
    return CONTAINING_RECORD( iface, struct x_user, IXUserImpl_iface );
}

static HRESULT WINAPI x_user_QueryInterface( IXUserImpl *iface, REFIID iid, void **out )
{
    struct x_user *impl = impl_from_IXUserImpl( iface );

    TRACE( "iface %p, iid %s, out %p\n", iface, debugstr_guid( iid ), out );

    if (!out) return E_POINTER;

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IXUserBase ) ||
        IsEqualGUID( iid, &IID_IXUserAddWithUi ) ||
        IsEqualGUID( iid, &IID_IXUserMsa ) ||
        IsEqualGUID( iid, &IID_IXUserStore ) ||
        IsEqualGUID( iid, &IID_IXUserPlatform ) ||
        IsEqualGUID( iid, &IID_IXUserSignOut ))
    {
        *out = &impl->IXUserImpl_iface;
        IXUserImpl_AddRef( *out );
        return S_OK;
    }

    if (IsEqualGUID( iid, &IID_IXUserGamertag ))
    {
        *out = &impl->IXUserGamertag_iface;
        IXUserGamertag_AddRef( *out );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI x_user_AddRef( IXUserImpl *iface )
{
    struct x_user *impl = impl_from_IXUserImpl( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu\n", iface, ref );
    return ref;
}

static ULONG WINAPI x_user_Release( IXUserImpl *iface )
{
    struct x_user *impl = impl_from_IXUserImpl( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu\n", iface, ref );
    if (!ref)
    {
        x_user_free_members( impl );
        if (impl->heap_allocated) free( impl );
    }
    return ref;
}

static HRESULT WINAPI x_user_XUserDuplicateHandle( IXUserImpl *iface, XUserHandle user, XUserHandle *duplicated )
{
    TRACE( "iface %p, user %p, duplicated %p\n", iface, user, duplicated );
    if (!user || !duplicated) return E_POINTER;
    IXUserImpl_AddRef( &((struct x_user*)user)->IXUserImpl_iface );
    *duplicated = user;
    return S_OK;
}

static void WINAPI x_user_XUserCloseHandle( IXUserImpl *iface, XUserHandle user )
{
    TRACE( "iface %p, user %p\n", iface, user );
    if (user) IXUserImpl_Release( &((struct x_user*)user)->IXUserImpl_iface );
}

static INT32 WINAPI x_user_XUserCompare( IXUserImpl *iface, XUserHandle user1, XUserHandle user2 )
{
    TRACE( "iface %p, user1 %p, user2 %p\n", iface, user1, user2 );
    if (!user1 || !user2) return 1;
    return ((struct x_user*)user1)->xuid != ((struct x_user*)user2)->xuid;
}

static HRESULT WINAPI x_user_XUserGetMaxUsers( IXUserImpl *iface, UINT32 *maxUsers )
{
    FIXME( "iface %p, maxUsers %p stub!\n", iface, maxUsers );
    if(maxUsers) {
        *maxUsers = 1;
    }
    return 0;
}

struct XUserAddContext
{
    XUserAddOptions options;
    XUserHandle user;
};

static HRESULT XUserAddProvider( XAsyncOp operation, const XAsyncProviderData *providerData )
{
    struct XUserAddContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "operation %d, providerData %p\n", operation, providerData );

    if (!providerData) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    context = providerData->context;

    switch (operation)
    {
        case Begin:
            context->user = NULL;
            return impl->lpVtbl->XAsyncSchedule( impl, providerData->async, 0 );

        case GetResult:
            if (!context->user) return E_GAMEUSER_NO_DEFAULT_USER;
            memcpy( providerData->buffer, &context->user, sizeof( XUserHandle ) );
            break;

        case DoWork:
            hr = LoadDefaultUser( &context->user, context->options );

            impl->lpVtbl->XAsyncComplete( impl, providerData->async, hr, sizeof( XUserHandle ) );
            break;

        case Cleanup:
            free( context );
            break;

        case Cancel:
            break;
    }

    return S_OK;
}

static HRESULT WINAPI x_user_XUserAddAsync( IXUserImpl *iface, XUserAddOptions options, XAsyncBlock *asyncBlock )
{
    struct XUserAddContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, options %d, asyncBlock %p\n", iface, options, asyncBlock );

    if (!asyncBlock) return E_POINTER;
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return hr;
    if (!(context = calloc( 1, sizeof( struct XUserAddContext ) )))
    {
        impl->lpVtbl->Release( impl );
        return E_OUTOFMEMORY;
    }

    context->options = options;
    hr = impl->lpVtbl->XAsyncBegin( impl, asyncBlock, context, x_user_XUserAddAsync, "XUserAddAsync", XUserAddProvider );
    impl->lpVtbl->Release( impl );
    return hr;
}

static HRESULT WINAPI x_user_XUserAddResult( IXUserImpl *iface, XAsyncBlock *asyncBlock, XUserHandle *user )
{
    IXThreadingImpl *impl;

    TRACE( "iface %p, asyncBlock %p, user %p\n", iface, asyncBlock, user );

    if (!asyncBlock || !user) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) abort();
    return impl->lpVtbl->XAsyncGetResult( impl, asyncBlock, x_user_XUserAddAsync, sizeof( XUserHandle ), user, NULL );
}

static HRESULT WINAPI x_user_XUserGetLocalId( IXUserImpl *iface, XUserHandle user, XUserLocalId *localId )
{
    TRACE( "iface %p, user %p, localId %p\n", iface, user, localId );
    if (!user || !localId) return E_POINTER;
    *localId = ((struct x_user*)user)->local_id;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserFindUserByLocalId( IXUserImpl *iface, XUserLocalId localId, XUserHandle *user )
{
    abort();
    FIXME( "iface %p, localId %p, user %p stub!\n", iface, &localId, user );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetId( IXUserImpl *iface, XUserHandle user, UINT64 *userId )
{
    TRACE( "iface %p, user %p, userId %p\n", iface, user, userId );
    if (!user || !userId) return E_POINTER;
    *userId = ((struct x_user*)user)->xuid;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserFindUserById( IXUserImpl *iface, UINT64 userId, XUserHandle *user )
{
    abort();
    FIXME( "iface %p, userId %llu, user %p stub!\n", iface, userId, user );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetIsGuest( IXUserImpl *iface, XUserHandle user, BOOLEAN *isGuest )
{
    FIXME( "iface %p, user %p, isGuest %p stub!\n", iface, user, isGuest );
    if (!user || !isGuest) return E_POINTER;
    *isGuest = FALSE;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserGetState( IXUserImpl *iface, XUserHandle user, XUserState *state )
{
    TRACE( "iface %p, user %p, state %p\n", iface, user, state );
    if (!user || !state) return E_POINTER;
    *state = XUserState_SignedIn;
    return S_OK;
}

static HRESULT WINAPI __PADDING__( IXUserImpl *iface )
{
    WARN( "iface %p padding function called! It's unknown what this function does\n", iface );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetGamerPictureAsync( IXUserImpl *iface, XUserHandle user, XUserGamerPictureSize size, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, user %p, size %p, asyncBlock %p stub!\n", iface, user, &size, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetGamerPictureResultSize( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *size )
{
    FIXME( "iface %p, asyncBlock %p, size %p stub!\n", iface, asyncBlock, size );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetGamerPictureResult( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T size, PVOID buffer, SIZE_T *used )
{
    FIXME( "iface %p, asyncBlock %p, size %llu, buffer %p, used %p stub!\n", iface, asyncBlock, size, buffer, used );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetAgeGroup( IXUserImpl *iface, XUserHandle user, XUserAgeGroup *group )
{
    TRACE( "iface %p, user %p, group %p\n", iface, user, group );

    if (!user || !group) return E_POINTER;
    *group = ((struct x_user*)user)->age_group;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserCheckPrivilege( IXUserImpl *iface, XUserHandle user, XUserPrivilegeOptions options, XUserPrivilege privilege, BOOLEAN *hasPrivilege, XUserPrivilegeDenyReason *reason )
{
    TRACE( "iface %p, user %p, options %d, privilege %d, hasPrivilege %p, reason %p\n",
           iface, user, options, privilege, hasPrivilege, reason );

    if (!user || !hasPrivilege) return E_POINTER;

    *hasPrivilege = TRUE;
    if (reason) *reason = XUserPrivilegeDenyReason_None;
    return S_OK;
}

static HRESULT WINAPI x_user_XUserResolvePrivilegeWithUiAsync( IXUserImpl *iface, XUserHandle user, XUserPrivilegeOptions options, XUserPrivilege privilege, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, user %p, options %d, privilege %d, asyncBlock %p stub!\n", iface, user, options, privilege, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolvePrivilegeWithUiResult( IXUserImpl *iface, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, asyncBlock %p stub!\n", iface, asyncBlock );
    abort();
    return E_NOTIMPL;
}

struct XUserGetTokenAndSignatureContext
{
    BOOLEAN utf16;
    XUserHandle user;
    XUserGetTokenAndSignatureOptions options;
    LPCSTR method;
    LPCWSTR method_utf16;
    LPCSTR url;
    LPCWSTR url_utf16;
    SIZE_T count;
    XUserGetTokenAndSignatureHttpHeader *headers;
    XUserGetTokenAndSignatureUtf16HttpHeader *headers_utf16;
    SIZE_T size;
    const void *buffer;
    LPSTR token;
    LPSTR signature;
    LPWSTR token_utf16;
    LPWSTR signature_utf16;
    SIZE_T result_size;
};

static HRESULT sha256_hash( const BYTE *data, DWORD data_size, BYTE hash[32] )
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash_handle = NULL;
    DWORD object_size, result_size;
    BYTE *object = NULL;
    NTSTATUS status;

    if ((status = BCryptOpenAlgorithmProvider( &alg, BCRYPT_SHA256_ALGORITHM, NULL, 0 ))) goto done;
    if ((status = BCryptGetProperty( alg, BCRYPT_OBJECT_LENGTH, (BYTE *)&object_size, sizeof( object_size ), &result_size, 0 ))) goto done;
    if (!(object = calloc( 1, object_size )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    if ((status = BCryptCreateHash( alg, &hash_handle, object, object_size, NULL, 0, 0 ))) goto done;
    if ((status = BCryptHashData( hash_handle, (BYTE *)data, data_size, 0 ))) goto done;
    status = BCryptFinishHash( hash_handle, hash, 32, 0 );

done:
    if (hash_handle) BCryptDestroyHash( hash_handle );
    if (alg) BCryptCloseAlgorithmProvider( alg, 0 );
    free( object );
    return status ? HRESULT_FROM_NT( status ) : S_OK;
}

static void append_bytes( BYTE **ptr, const void *data, SIZE_T size )
{
    memcpy( *ptr, data, size );
    *ptr += size;
}

static HRESULT get_path_and_query( LPCWSTR url, LPSTR *path_and_query )
{
    URL_COMPONENTSW components;
    DWORD len;
    HRESULT hr = S_OK;
    LPWSTR wide;

    *path_and_query = NULL;
    memset( &components, 0, sizeof( components ) );
    components.dwStructSize = sizeof( components );
    components.dwUrlPathLength = -1;
    components.dwExtraInfoLength = -1;

    if (!WinHttpCrackUrl( url, 0, 0, &components )) return HRESULT_FROM_WIN32( GetLastError() );
    len = components.dwUrlPathLength + components.dwExtraInfoLength;
    if (!len) return E_FAIL;
    if (!(wide = calloc( len + 1, sizeof( WCHAR ) ))) return E_OUTOFMEMORY;
    if (components.dwUrlPathLength) memcpy( wide, components.lpszUrlPath, components.dwUrlPathLength * sizeof( WCHAR ) );
    if (components.dwExtraInfoLength) memcpy( wide + components.dwUrlPathLength, components.lpszExtraInfo, components.dwExtraInfoLength * sizeof( WCHAR ) );

    len = WideCharToMultiByte( CP_UTF8, 0, wide, len, NULL, 0, NULL, NULL );
    if (!len) hr = HRESULT_FROM_WIN32( GetLastError() );
    else if (!(*path_and_query = calloc( len + 1, sizeof( CHAR ) ))) hr = E_OUTOFMEMORY;
    else if (!WideCharToMultiByte( CP_UTF8, 0, wide, -1, *path_and_query, len + 1, NULL, NULL ))
    {
        free( *path_and_query );
        *path_and_query = NULL;
        hr = HRESULT_FROM_WIN32( GetLastError() );
    }

    free( wide );
    return hr;
}

static HRESULT sign_request( struct x_user *user, LPCSTR method, LPCWSTR url, const void *body, SIZE_T body_size, LPSTR *signature )
{
    BYTE version[4] = {0, 0, 0, XUSER_SIGNATURE_POLICY_VERSION};
    BYTE timestamp[8], hash[32], *message = NULL, *ptr, *sig = NULL, *blob = NULL;
    DWORD sig_size = 0, blob_size, base64_size;
    ULARGE_INTEGER filetime_int;
    FILETIME filetime;
    LPSTR path_and_query = NULL, method_upper = NULL;
    SIZE_T method_len, path_len, auth_len, body_hash_size, message_size;
    HRESULT hr;
    NTSTATUS status;

    *signature = NULL;
    if (!user->signing_key) return E_FAIL;
    if (FAILED( hr = get_path_and_query( url, &path_and_query ) )) return hr;

    method_len = strlen( method );
    if (!(method_upper = calloc( method_len + 1, sizeof( CHAR ) )))
    {
        free( path_and_query );
        return E_OUTOFMEMORY;
    }
    for (SIZE_T i = 0; i < method_len; i++) method_upper[i] = toupper( method[i] );

    GetSystemTimeAsFileTime( &filetime );
    filetime_int.LowPart = filetime.dwLowDateTime;
    filetime_int.HighPart = filetime.dwHighDateTime;
    for (int i = 0; i < 8; i++) timestamp[i] = (BYTE)(filetime_int.QuadPart >> ((7 - i) * 8));

    path_len = strlen( path_and_query );
    auth_len = user->authorization ? strlen( user->authorization ) : 0;
    body_hash_size = body_size < XUSER_SIGNATURE_MAX_BODY_BYTES ? body_size : XUSER_SIGNATURE_MAX_BODY_BYTES;
    message_size = sizeof( version ) + 1 + sizeof( timestamp ) + 1 + method_len + 1 + path_len + 1 + auth_len + 1 + body_hash_size + 1;
    if (!(message = calloc( 1, message_size )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    ptr = message;
    append_bytes( &ptr, version, sizeof( version ) ); ptr++;
    append_bytes( &ptr, timestamp, sizeof( timestamp ) ); ptr++;
    append_bytes( &ptr, method_upper, method_len ); ptr++;
    append_bytes( &ptr, path_and_query, path_len ); ptr++;
    if (auth_len) append_bytes( &ptr, user->authorization, auth_len );
    ptr++;
    if (body_hash_size) append_bytes( &ptr, body, body_hash_size );

    if (FAILED( hr = sha256_hash( message, message_size, hash ) )) goto done;
    if ((status = BCryptSignHash( user->signing_key, NULL, hash, sizeof( hash ), NULL, 0, &sig_size, 0 )))
    {
        hr = HRESULT_FROM_NT( status );
        goto done;
    }
    if (!(sig = calloc( 1, sig_size )) || !(blob = calloc( 1, sizeof( version ) + sizeof( timestamp ) + sig_size )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if ((status = BCryptSignHash( user->signing_key, NULL, hash, sizeof( hash ), sig, sig_size, &sig_size, 0 )))
    {
        hr = HRESULT_FROM_NT( status );
        goto done;
    }
    memcpy( blob, version, sizeof( version ) );
    memcpy( blob + sizeof( version ), timestamp, sizeof( timestamp ) );
    memcpy( blob + sizeof( version ) + sizeof( timestamp ), sig, sig_size );
    blob_size = sizeof( version ) + sizeof( timestamp ) + sig_size;

    if (!CryptBinaryToStringA( blob, blob_size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_size ))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto done;
    }
    if (!(*signature = calloc( base64_size, sizeof( CHAR ) )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (!CryptBinaryToStringA( blob, blob_size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *signature, &base64_size ))
    {
        free( *signature );
        *signature = NULL;
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto done;
    }
    hr = S_OK;

done:
    free( path_and_query );
    free( method_upper );
    free( message );
    free( sig );
    free( blob );
    return hr;
}

static HRESULT utf8_to_wide( LPCSTR str, LPWSTR *wide )
{
    int len;

    *wide = NULL;
    if (!(len = MultiByteToWideChar( CP_UTF8, 0, str, -1, NULL, 0 )))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!(*wide = calloc( len, sizeof( WCHAR ) ))) return E_OUTOFMEMORY;
    if (!MultiByteToWideChar( CP_UTF8, 0, str, -1, *wide, len ))
    {
        free( *wide );
        *wide = NULL;
        return HRESULT_FROM_WIN32( GetLastError() );
    }
    return S_OK;
}

static HRESULT wide_to_utf8( LPCWSTR wide, LPSTR *str )
{
    int len;

    *str = NULL;
    if (!(len = WideCharToMultiByte( CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL )))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!(*str = calloc( len, sizeof( CHAR ) ))) return E_OUTOFMEMORY;
    if (!WideCharToMultiByte( CP_UTF8, 0, wide, -1, *str, len, NULL, NULL ))
    {
        free( *str );
        *str = NULL;
        return HRESULT_FROM_WIN32( GetLastError() );
    }
    return S_OK;
}

static HRESULT token_context_prepare_result( struct XUserGetTokenAndSignatureContext *context )
{
    struct x_user *user = context->user;
    LPWSTR url_w = NULL;
    LPSTR method = NULL;
    HRESULT hr;

    if (FAILED( hr = refresh_user_tokens( user, context->options & XUserGetTokenAndSignatureOptions_ForceRefresh ) ))
        return hr;

    if (!(context->token = strdup( user->authorization ? user->authorization : "" ))) return E_OUTOFMEMORY;

    if (context->utf16)
    {
        if (FAILED( hr = wide_to_utf8( context->method_utf16, &method ) )) return hr;
        url_w = (LPWSTR)context->url_utf16;
    }
    else
    {
        if (!(method = strdup( context->method ))) return E_OUTOFMEMORY;
        if (FAILED( hr = utf8_to_wide( context->url, &url_w ) ))
        {
            free( method );
            return hr;
        }
    }

    hr = sign_request( user, method, url_w, context->buffer, context->size, &context->signature );
    free( method );
    if (!context->utf16) free( url_w );
    if (FAILED( hr )) return hr;

    if (context->utf16)
    {
        int token_len = MultiByteToWideChar( CP_UTF8, 0, context->token, -1, NULL, 0 );
        int sig_len = context->signature ? MultiByteToWideChar( CP_UTF8, 0, context->signature, -1, NULL, 0 ) : 0;
        if (!token_len || (context->signature && !sig_len)) return HRESULT_FROM_WIN32( GetLastError() );
        if (!(context->token_utf16 = calloc( token_len, sizeof( WCHAR ) ))) return E_OUTOFMEMORY;
        if (!MultiByteToWideChar( CP_UTF8, 0, context->token, -1, context->token_utf16, token_len ))
            return HRESULT_FROM_WIN32( GetLastError() );
        if (context->signature)
        {
            if (!(context->signature_utf16 = calloc( sig_len, sizeof( WCHAR ) ))) return E_OUTOFMEMORY;
            if (!MultiByteToWideChar( CP_UTF8, 0, context->signature, -1, context->signature_utf16, sig_len ))
                return HRESULT_FROM_WIN32( GetLastError() );
        }
        context->result_size = sizeof( XUserGetTokenAndSignatureUtf16Data ) +
            token_len * sizeof( WCHAR ) + (context->signature ? sig_len * sizeof( WCHAR ) : 0);
    }
    else
    {
        context->result_size = sizeof( XUserGetTokenAndSignatureData ) +
            strlen( context->token ) + 1 + (context->signature ? strlen( context->signature ) + 1 : 0);
    }
    return S_OK;
}

static HRESULT token_context_get_result( struct XUserGetTokenAndSignatureContext *context, SIZE_T size, void *buffer, SIZE_T *used )
{
    BYTE *cursor = buffer;

    if (!buffer) return E_POINTER;
    if (size < context->result_size) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );

    if (context->utf16)
    {
        XUserGetTokenAndSignatureUtf16Data *data = buffer;
        SIZE_T token_bytes = (wcslen( context->token_utf16 ) + 1) * sizeof( WCHAR );
        SIZE_T signature_bytes = context->signature_utf16 ? (wcslen( context->signature_utf16 ) + 1) * sizeof( WCHAR ) : 0;

        cursor += sizeof( *data );
        data->token = (LPCWSTR)cursor;
        data->tokenCount = wcslen( context->token_utf16 ) + 1;
        memcpy( cursor, context->token_utf16, token_bytes );
        cursor += token_bytes;
        if (context->signature_utf16)
        {
            data->signature = (LPCWSTR)cursor;
            data->signatureCount = wcslen( context->signature_utf16 ) + 1;
            memcpy( cursor, context->signature_utf16, signature_bytes );
        }
        else
        {
            data->signature = NULL;
            data->signatureCount = 0;
        }
    }
    else
    {
        XUserGetTokenAndSignatureData *data = buffer;
        SIZE_T token_bytes = strlen( context->token ) + 1;
        SIZE_T signature_bytes = context->signature ? strlen( context->signature ) + 1 : 0;

        cursor += sizeof( *data );
        data->token = (LPCSTR)cursor;
        data->tokenSize = token_bytes;
        memcpy( cursor, context->token, token_bytes );
        cursor += token_bytes;
        if (context->signature)
        {
            data->signature = (LPCSTR)cursor;
            data->signatureSize = signature_bytes;
            memcpy( cursor, context->signature, signature_bytes );
        }
        else
        {
            data->signature = NULL;
            data->signatureSize = 0;
        }
    }
    if (used) *used = context->result_size;
    return S_OK;
}

static HRESULT XUserGetTokenAndSignatureProvider( XAsyncOp operation, const XAsyncProviderData *providerData )
{
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "operation %d, providerData %p\n", operation, providerData );

    if (!providerData) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    context = providerData->context;

    switch (operation)
    {
        case Begin:
            return impl->lpVtbl->XAsyncSchedule( impl, providerData->async, 0 );

        case GetResult:
            return token_context_get_result( context, providerData->bufferSize, providerData->buffer, NULL );

        case DoWork:
            hr = token_context_prepare_result( context );
            impl->lpVtbl->XAsyncComplete( impl, providerData->async, hr, SUCCEEDED( hr ) ? context->result_size : 0 );
            break;

        case Cleanup:
            if (context->count)
            {
                if (context->utf16) free( context->headers_utf16 );
                else free( context->headers );
            }
            free( context->token );
            free( context->signature );
            free( context->token_utf16 );
            free( context->signature_utf16 );
            free( context );
            break;

        case Cancel:
            break;
    }

    return S_OK;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureAsync( IXUserImpl *iface, XUserHandle user, XUserGetTokenAndSignatureOptions options, LPCSTR method, LPCSTR url, SIZE_T count, const XUserGetTokenAndSignatureHttpHeader *headers, SIZE_T size, const void *buffer, XAsyncBlock *asyncBlock )
{
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    FIXME( "iface %p, user %p, options %d, method %s, url %s, count %llu, headers %p, size %llu, buffer %p, asyncBlock %p\n", iface, user, options, method, url, count, headers, size, buffer, asyncBlock );

    if (!user || !method || !url || (count && !headers) || (size && !buffer) || !asyncBlock) return E_POINTER;
    for (SIZE_T i = 0; i < count; i++) FIXME( "%s: %s", headers[i].name, headers[i].value );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return hr;
    if (!(context = calloc( 1, sizeof( *context ) )))
    {
        impl->lpVtbl->Release( impl );
        return E_OUTOFMEMORY;
    }

    context->options = options;
    context->buffer = buffer;
    context->method = method;
    context->count = count;
    context->utf16 = FALSE;
    context->size = size;
    context->user = user;
    context->url = url;
    if (count && !(context->headers = calloc( count, sizeof( *headers ) )))
    {
        free( context );
        impl->lpVtbl->Release( impl );
        return E_OUTOFMEMORY;
    }

    for (SIZE_T i = 0; i < count; i++)
        context->headers[i] = headers[i];

    hr = impl->lpVtbl->XAsyncBegin( impl, asyncBlock, context, x_user_XUserGetTokenAndSignatureAsync, "XUserGetTokenAndSignatureAsync", XUserGetTokenAndSignatureProvider );
    impl->lpVtbl->Release( impl );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureResultSize( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *size )
{
    IXThreadingImpl *impl;

    TRACE( "iface %p, asyncBlock %p, size %p\n", iface, asyncBlock, size );
    if (!asyncBlock || !size) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    return impl->lpVtbl->XAsyncGetResultSize( impl, asyncBlock, size );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureResult( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T size, PVOID buffer, XUserGetTokenAndSignatureData **ptr, SIZE_T *used )
{
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, asyncBlock %p, size %llu, buffer %p, ptr %p, used %p\n", iface, asyncBlock, size, buffer, ptr, used );
    if (!asyncBlock || !buffer || !ptr) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    hr = impl->lpVtbl->XAsyncGetResult( impl, asyncBlock, x_user_XUserGetTokenAndSignatureAsync, size, buffer, used );
    if (SUCCEEDED( hr )) *ptr = buffer;
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16Async( IXUserImpl *iface, XUserHandle user, XUserGetTokenAndSignatureOptions options, LPCWSTR method, LPCWSTR url, SIZE_T count, const XUserGetTokenAndSignatureUtf16HttpHeader *headers, SIZE_T size, const void *buffer, XAsyncBlock *asyncBlock )
{
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, user %p, options %d, method %s, url %s, count %llu, headers %p, size %llu, buffer %p, asyncBlock %p\n",
           iface, user, options, debugstr_w( method ), debugstr_w( url ), count, headers, size, buffer, asyncBlock );

    if (!user || !method || !url || (count && !headers) || (size && !buffer) || !asyncBlock) return E_POINTER;
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return hr;
    if (!(context = calloc( 1, sizeof( *context ) )))
    {
        impl->lpVtbl->Release( impl );
        return E_OUTOFMEMORY;
    }

    context->method_utf16 = method;
    context->options = options;
    context->buffer = buffer;
    context->url_utf16 = url;
    context->count = count;
    context->utf16 = TRUE;
    context->size = size;
    context->user = user;
    if (count && !(context->headers_utf16 = calloc( count, sizeof( *headers ) )))
    {
        free( context );
        impl->lpVtbl->Release( impl );
        return E_OUTOFMEMORY;
    }

    for (SIZE_T i = 0; i < count; i++)
        context->headers_utf16[i] = headers[i];

    hr = impl->lpVtbl->XAsyncBegin( impl, asyncBlock, context, x_user_XUserGetTokenAndSignatureUtf16Async, "XUserGetTokenAndSignatureUtf16Async", XUserGetTokenAndSignatureProvider );
    impl->lpVtbl->Release( impl );
    return hr;
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16ResultSize( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *size )
{
    IXThreadingImpl *impl;

    TRACE( "iface %p, asyncBlock %p, size %p\n", iface, asyncBlock, size );
    if (!asyncBlock || !size) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    return impl->lpVtbl->XAsyncGetResultSize( impl, asyncBlock, size );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16Result( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T size, PVOID buffer, XUserGetTokenAndSignatureUtf16Data **ptr, SIZE_T *used )
{
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, asyncBlock %p, size %llu, buffer %p, ptr %p, used %p\n", iface, asyncBlock, size, buffer, ptr, used );
    if (!asyncBlock || !buffer || !ptr) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    hr = impl->lpVtbl->XAsyncGetResult( impl, asyncBlock, x_user_XUserGetTokenAndSignatureUtf16Async, size, buffer, used );
    if (SUCCEEDED( hr )) *ptr = buffer;
    return hr;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiAsync( IXUserImpl *iface, XUserHandle user, LPCSTR url, XAsyncBlock *asyncBlock )
{
    abort();
    FIXME( "iface %p, user %p, url %s, asyncBlock %p stub!\n", iface, user, url, asyncBlock );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiResult( IXUserImpl *iface, XAsyncBlock *asyncBlock )
{
    abort();
    FIXME( "iface %p, asyncBlock %p stub!\n", iface, asyncBlock );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiUtf16Async( IXUserImpl *iface, XUserHandle user, LPCWSTR url, XAsyncBlock *asyncBlock )
{
    abort();
    FIXME( "iface %p, user %p, url %s, asyncBlock %p stub!\n", iface, user, debugstr_w( url ), asyncBlock );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserResolveIssueWithUiUtf16Result( IXUserImpl *iface, XAsyncBlock *asyncBlock )
{
    abort();
    FIXME( "iface %p, asyncBlock %p stub!\n", iface, asyncBlock );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserRegisterForChangeEvent( IXUserImpl *iface, XTaskQueueHandle queue, PVOID context, XUserChangeEventCallback *callback, XTaskQueueRegistrationToken *token )
{
    FIXME( "iface %p, context %p, callback %p, token %p stub!\n", iface, context, callback, token );
    // XUserLocalId id;
    // id.value = 1;
    // (*callback)(context, id, XUserChangeEvent_SignedInAgain);
    return 0;
}

static BOOLEAN WINAPI x_user_XUserUnregisterForChangeEvent( IXUserImpl *iface, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    FIXME( "iface %p, token %p, wait %d stub!\n", iface, &token, wait );
    abort();
    return FALSE;
}

static HRESULT WINAPI x_user_XUserGetSignOutDeferral( IXUserImpl *iface, XUserSignOutDeferralHandle *deferral )
{
    FIXME( "iface %p, deferral %p stub!\n", iface, deferral );
    abort();
    return E_GAMEUSER_DEFERRAL_NOT_AVAILABLE;
}

static void WINAPI x_user_XUserCloseSignOutDeferralHandle( IXUserImpl *iface, XUserSignOutDeferralHandle deferral )
{
    FIXME( "iface %p, deferral %p stub!\n", iface, deferral );
    abort();
}

static HRESULT WINAPI x_user_XUserAddByIdWithUiAsync( IXUserImpl *iface, UINT64 userId, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, userId %llu, asyncBlock %p stub!\n", iface, userId, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserAddByIdWithUiResult( IXUserImpl *iface, XAsyncBlock *asyncBlock, XUserHandle *user )
{
    FIXME( "iface %p, asyncBlock %p, user %p stub!\n", iface, asyncBlock, user );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetMsaTokenSilentlyAsync( IXUserImpl *iface, XUserHandle user, XUserGetMsaTokenSilentlyOptions options, LPCSTR scope, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, options %u, scope %s, asyncBlock %p stub!\n", iface, options, scope, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetMsaTokenSilentlyResult( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T size, LPSTR token, SIZE_T *used )
{
    FIXME( "iface %p, size %llu, token %p, used %p stub!\n", iface, size, token, used );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserGetMsaTokenSilentlyResultSize( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *size )
{
    FIXME( "iface %p, asyncBlock %p stub!\n", iface, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_user_XUserIsStoreUser( IXUserImpl *iface, XUserHandle user )
{
    FIXME( "iface %p, user %p stub!\n", iface, user );
    abort();
    return FALSE;
}

static HRESULT WINAPI x_user_XUserPlatformRemoteConnectSetEventHandlers( IXUserImpl *iface, XTaskQueueHandle queue, XUserPlatformRemoteConnectEventHandlers *handlers )
{
    FIXME( "iface %p, queue %p, handlers %p stub!\n", iface, queue, handlers );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserPlatformRemoteConnectCancelPrompt( IXUserImpl *iface, XUserPlatformOperation operation )
{
    FIXME( "iface %p, operation %p stub!\n", iface, operation );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserPlatformSpopPromptSetEventHandlers( IXUserImpl *iface, XTaskQueueHandle queue, XUserPlatformSpopPromptEventHandler *handler, void *context )
{
    FIXME( "iface %p, queue %p, handler %p, context %p stub!\n", iface, queue, handler, context );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserPlatformSpopPromptComplete( IXUserImpl *iface, XUserPlatformOperation operation, XUserPlatformOperationResult result )
{
    FIXME( "iface %p iface, operation %p, result %d stub!\n", iface, operation, result );
    abort();
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_user_XUserIsSignOutPresent( IXUserImpl *iface )
{
    FIXME( "iface %p stub!\n", iface );
    abort();
    return FALSE;
}

static HRESULT WINAPI x_user_XUserSignOutAsync( IXUserImpl *iface, XUserHandle user, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, user %p, asyncBlock %p stub!\n", iface, user, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static HRESULT WINAPI x_user_XUserSignOutResult( IXUserImpl *iface, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, asyncBlock %p stub!\n", iface, asyncBlock );
    abort();
    return E_NOTIMPL;
}

static const struct IXUserImplVtbl x_user_vtbl =
{
    /* IUnknown methods */
    x_user_QueryInterface,
    x_user_AddRef,
    x_user_Release,
    /* IXUserBase methods */
    x_user_XUserDuplicateHandle,
    x_user_XUserCloseHandle,
    x_user_XUserCompare,
    x_user_XUserGetMaxUsers,
    x_user_XUserAddAsync,
    x_user_XUserAddResult,
    x_user_XUserGetLocalId,
    x_user_XUserFindUserByLocalId,
    x_user_XUserGetId,
    x_user_XUserFindUserById,
    x_user_XUserGetIsGuest,
    x_user_XUserGetState,
    __PADDING__,
    x_user_XUserGetGamerPictureAsync,
    x_user_XUserGetGamerPictureResultSize,
    x_user_XUserGetGamerPictureResult,
    x_user_XUserGetAgeGroup,
    x_user_XUserCheckPrivilege,
    x_user_XUserResolvePrivilegeWithUiAsync,
    x_user_XUserResolvePrivilegeWithUiResult,
    x_user_XUserGetTokenAndSignatureAsync,
    x_user_XUserGetTokenAndSignatureResultSize,
    x_user_XUserGetTokenAndSignatureResult,
    x_user_XUserGetTokenAndSignatureUtf16Async,
    x_user_XUserGetTokenAndSignatureUtf16ResultSize,
    x_user_XUserGetTokenAndSignatureUtf16Result,
    x_user_XUserResolveIssueWithUiAsync,
    x_user_XUserResolveIssueWithUiResult,
    x_user_XUserResolveIssueWithUiUtf16Async,
    x_user_XUserResolveIssueWithUiUtf16Result,
    x_user_XUserRegisterForChangeEvent,
    x_user_XUserUnregisterForChangeEvent,
    x_user_XUserGetSignOutDeferral,
    x_user_XUserCloseSignOutDeferralHandle,
    /* IXUserAddWithUi methods */
    x_user_XUserAddByIdWithUiAsync,
    x_user_XUserAddByIdWithUiResult,
    /* IXUserMsa methods */
    x_user_XUserGetMsaTokenSilentlyAsync,
    x_user_XUserGetMsaTokenSilentlyResult,
    x_user_XUserGetMsaTokenSilentlyResultSize,
    /* IXUserStore methods */
    x_user_XUserIsStoreUser,
    /* IXUserPlatform methods */
    x_user_XUserPlatformRemoteConnectSetEventHandlers,
    x_user_XUserPlatformRemoteConnectCancelPrompt,
    x_user_XUserPlatformSpopPromptSetEventHandlers,
    x_user_XUserPlatformSpopPromptComplete,
    /* IXUserSignOut methods */
    x_user_XUserIsSignOutPresent,
    x_user_XUserSignOutAsync,
    x_user_XUserSignOutResult
};

static inline struct x_user *impl_from_IXUserGamertag( IXUserGamertag *iface )
{
    return CONTAINING_RECORD( iface, struct x_user, IXUserGamertag_iface );
}

static HRESULT WINAPI x_user_gt_QueryInterface( IXUserGamertag *iface, REFIID iid, void **out )
{
    struct x_user *impl = impl_from_IXUserGamertag( iface );

    TRACE( "iface %p, iid %s, out %p\n", iface, debugstr_guid( iid ), out );

    if (!out) return E_POINTER;

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IXUserBase ) ||
        IsEqualGUID( iid, &IID_IXUserAddWithUi ) ||
        IsEqualGUID( iid, &IID_IXUserMsa ) ||
        IsEqualGUID( iid, &IID_IXUserStore ) ||
        IsEqualGUID( iid, &IID_IXUserPlatform ) ||
        IsEqualGUID( iid, &IID_IXUserSignOut ))
    {
        *out = &impl->IXUserImpl_iface;
        IXUserImpl_AddRef( *out );
        return S_OK;
    }

    if (IsEqualGUID( iid, &IID_IXUserGamertag ))
    {
        *out = &impl->IXUserGamertag_iface;
        IXUserGamertag_AddRef( *out );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI x_user_gt_AddRef( IXUserGamertag *iface )
{
    struct x_user *impl = impl_from_IXUserGamertag( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu\n", iface, ref );
    return ref;
}

static ULONG WINAPI x_user_gt_Release( IXUserGamertag *iface )
{
    struct x_user *impl = impl_from_IXUserGamertag( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu\n", iface, ref );
    if (!ref)
    {
        x_user_free_members( impl );
        if (impl->heap_allocated) free( impl );
    }
    return ref;
}

static HRESULT x_user_gt_XUserGetGamertag( IXUserGamertag *iface, XUserHandle user, XUserGamertagComponent component, SIZE_T size, LPSTR gamertag, SIZE_T *used )
{
    struct x_user *impl = user;
    LPSTR tag = NULL;
    UINT32 tag_len;
    HRESULT hr;

    FIXME( "iface %p, user %p, component %d, size %llu, gamertag %p, used %p stub!\n", iface, user, component, size, gamertag, used );

    if (!user || !gamertag || !used) return E_POINTER;
    if (impl->gamertag && SUCCEEDED( hr = HSTRINGToMultiByte( impl->gamertag, &tag, &tag_len ) ))
    {
        if (size < tag_len + 1)
        {
            free( tag );
            return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        }
        memcpy( gamertag, tag, tag_len );
        gamertag[tag_len] = 0;
        *used = tag_len + 1;
        free( tag );
        return S_OK;
    }
    if (size < 1) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
    gamertag[0] = 0;
    *used = 1;
    return S_OK;
}

static const struct IXUserGamertagVtbl x_user_gt_vtbl =
{
    /* IUnknown methods */
    x_user_gt_QueryInterface,
    x_user_gt_AddRef,
    x_user_gt_Release,
    /* IXUserGamertag methods */
    x_user_gt_XUserGetGamertag
};

static struct x_user x_user = {
    {&x_user_vtbl},
    {&x_user_gt_vtbl},
    0,
};

IXUserImpl *x_user_impl = &x_user.IXUserImpl_iface;
