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
#define XUSER_STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)

// #undef TRACE
// #define TRACE FIXME

static HRESULT xuser_log_hr( const char *func, const char *where, HRESULT hr )
{
    FIXME( "%s %s returning %#lx\n", func, where, hr );
    return hr;
}

void WINAPI __debug_check(HRESULT hr) {

}

#define XUSER_RETURN_HR(hr) return xuser_log_hr( __func__, "", (hr) )
#define XUSER_RETURN_HR_WHERE(where, hr) return xuser_log_hr( __func__, (where), (hr) )

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

    if (FAILED( hr = HSTRINGToMultiByte( hstr, str, &len ) )) XUSER_RETURN_HR_WHERE( "HSTRINGToMultiByte", hr );
    if (!(tmp = realloc( *str, len + 1 )))
    {
        free( *str );
        *str = NULL;
        XUSER_RETURN_HR_WHERE( "realloc", E_OUTOFMEMORY );
    }
    *str = tmp;
    (*str)[len] = 0;
    XUSER_RETURN_HR( S_OK );
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

    if (FAILED( hr = HSTRINGToMultiByte( impl->user_hash, &user_hash, &user_hash_len ) )) XUSER_RETURN_HR_WHERE( "user_hash", hr );
    if (FAILED( hr = HSTRINGToMultiByte( impl->xsts_token, &token, &token_len ) ))
    {
        free( user_hash );
        XUSER_RETURN_HR_WHERE( "xsts_token", hr );
    }

    if (!(impl->authorization = calloc( strlen( "XBL3.0 x=;" ) + user_hash_len + token_len + 1, sizeof( CHAR ) )))
    {
        free( user_hash );
        free( token );
        XUSER_RETURN_HR_WHERE( "authorization calloc", E_OUTOFMEMORY );
    }

    strcpy( impl->authorization, "XBL3.0 x=" );
    strncat( impl->authorization, user_hash, user_hash_len );
    strcat( impl->authorization, ";" );
    strncat( impl->authorization, token, token_len );
    free( user_hash );
    free( token );
    XUSER_RETURN_HR( S_OK );
}

static HRESULT create_authorization_string( LPCSTR user_hash, LPCSTR token, BOOLEAN all_users, LPSTR *authorization )
{
    const char *hash = all_users ? "*" : user_hash;
    SIZE_T size;

    *authorization = NULL;
    if (!hash || !token) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    size = strlen( "XBL3.0 x=;" ) + strlen( hash ) + strlen( token ) + 1;
    if (!(*authorization = calloc( size, sizeof( CHAR ) ))) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
    snprintf( *authorization, size, "XBL3.0 x=%s;%s", hash, token );
    XUSER_RETURN_HR( S_OK );
}

static HRESULT create_signing_key( BCRYPT_KEY_HANDLE *key )
{
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status;

    *key = NULL;
    if ((status = BCryptOpenAlgorithmProvider( &alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0 )))
        XUSER_RETURN_HR_WHERE( "BCryptOpenAlgorithmProvider", HRESULT_FROM_NT( status ) );
    if ((status = BCryptGenerateKeyPair( alg, key, 256, 0 )))
    {
        BCryptCloseAlgorithmProvider( alg, 0 );
        XUSER_RETURN_HR_WHERE( "BCryptGenerateKeyPair", HRESULT_FROM_NT( status ) );
    }
    status = BCryptFinalizeKeyPair( *key, 0 );
    BCryptCloseAlgorithmProvider( alg, 0 );
    if (status)
    {
        BCryptDestroyKey( *key );
        *key = NULL;
        XUSER_RETURN_HR_WHERE( "BCryptFinalizeKeyPair", HRESULT_FROM_NT( status ) );
    }
    XUSER_RETURN_HR( S_OK );
}

static HRESULT base64url_encode( const BYTE *buffer, DWORD size, LPSTR *encoded )
{
    DWORD base64_size;

    *encoded = NULL;
    if (!CryptBinaryToStringA( buffer, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64_size ))
        XUSER_RETURN_HR_WHERE( "CryptBinaryToStringA size", HRESULT_FROM_WIN32( GetLastError() ) );
    if (!(*encoded = calloc( base64_size + 1, sizeof( CHAR ) ))) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
    if (!CryptBinaryToStringA( buffer, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *encoded, &base64_size ))
    {
        free( *encoded );
        *encoded = NULL;
        XUSER_RETURN_HR_WHERE( "CryptBinaryToStringA", HRESULT_FROM_WIN32( GetLastError() ) );
    }

    for (DWORD i = 0; i < base64_size; ++i)
    {
        if ((*encoded)[i] == '+') (*encoded)[i] = '-';
        else if ((*encoded)[i] == '/') (*encoded)[i] = '_';
        else if ((*encoded)[i] == '=')
        {
            (*encoded)[i] = 0;
            break;
        }
    }

    XUSER_RETURN_HR( S_OK );
}

static HRESULT export_proof_key_jwk( BCRYPT_KEY_HANDLE key, LPSTR *proof_key_json )
{
    BCRYPT_ECCKEY_BLOB *blob;
    DWORD blob_size = 0;
    BYTE *buffer = NULL;
    LPSTR x = NULL, y = NULL;
    HRESULT hr = S_OK;
    size_t json_size;
    NTSTATUS status;

    *proof_key_json = NULL;
    status = BCryptExportKey( key, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &blob_size, 0 );
    if (status)
        XUSER_RETURN_HR_WHERE( "BCryptExportKey size", E_FAIL );
    if (!(buffer = calloc( blob_size, sizeof( BYTE ) ))) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
    status = BCryptExportKey( key, NULL, BCRYPT_ECCPUBLIC_BLOB, buffer, blob_size, &blob_size, 0 );
    if (status)
    {
        free( buffer );
        XUSER_RETURN_HR_WHERE( "BCryptExportKey", E_FAIL );
    }

    blob = (BCRYPT_ECCKEY_BLOB *)buffer;
    if (blob->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC)
    {
        free( buffer );
        XUSER_RETURN_HR_WHERE( "dwMagic", E_FAIL );
    }
    if (FAILED( hr = base64url_encode( buffer + sizeof( *blob ), blob->cbKey, &x ) )) goto done;
    if (FAILED( hr = base64url_encode( buffer + sizeof( *blob ) + blob->cbKey, blob->cbKey, &y ) )) goto done;

    json_size = snprintf( NULL, 0,
                          "{\"alg\":\"ES256\",\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}",
                          x, y ) + 1;
    if (!(*proof_key_json = calloc( json_size, sizeof( CHAR ) )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    snprintf( *proof_key_json, json_size,
              "{\"alg\":\"ES256\",\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}",
              x, y );

done:
    free( x );
    free( y );
    free( buffer );
    XUSER_RETURN_HR( hr );
}

static HRESULT refresh_user_tokens( struct x_user *impl, BOOL force )
{
    HSTRING refresh_token = NULL, oauth_token = NULL, user_token = NULL, xsts_token = NULL, user_hash = NULL, gamertag = NULL;
    LPSTR client_id = NULL, old_refresh = NULL;
    time_t expiry, now;
    HRESULT hr;

    now = time( NULL );
    if (!force && impl->authorization && impl->oauth_token_expiry > now + 300) XUSER_RETURN_HR_WHERE( "cached", S_OK );

    if (FAILED( hr = hstring_to_nul_string( impl->client_id, &client_id ) )) XUSER_RETURN_HR_WHERE( "client_id", hr );
    if (FAILED( hr = hstring_to_nul_string( impl->refresh_token, &old_refresh ) ))
    {
        free( client_id );
        XUSER_RETURN_HR_WHERE( "refresh_token", hr );
    }

    hr = RefreshOAuth( client_id, old_refresh, &expiry, &refresh_token, &oauth_token );
    free( client_id );
    free( old_refresh );
    if (FAILED( hr )) XUSER_RETURN_HR_WHERE( "RefreshOAuth", E_GAMEUSER_FAILED_TO_GET_TOKEN );

    if (FAILED( hr = RequestUserToken( oauth_token, &user_token, &impl->local_id ) ))
    {
        FIXME( "%s RequestUserToken returned %#lx\n", __func__, hr );
        goto failed;
    }
    if (FAILED( hr = RequestXstsTokenWithUserHash( user_token, &xsts_token, &user_hash, &gamertag, &impl->xuid, &impl->age_group ) ))
    {
        FIXME( "%s RequestXstsTokenWithUserHash returned %#lx\n", __func__, hr );
        goto failed;
    }

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

    if (FAILED( hr = SaveTokenStoreRefreshToken( impl->client_id, impl->refresh_token ) )) XUSER_RETURN_HR_WHERE( "SaveTokenStoreRefreshToken", hr );
    hr = create_authorization_header( impl );
    XUSER_RETURN_HR_WHERE( "create_authorization_header", hr );

failed:
    if (refresh_token) WindowsDeleteString( refresh_token );
    if (oauth_token) WindowsDeleteString( oauth_token );
    if (user_token) WindowsDeleteString( user_token );
    if (xsts_token) WindowsDeleteString( xsts_token );
    if (user_hash) WindowsDeleteString( user_hash );
    if (gamertag) WindowsDeleteString( gamertag );
    XUSER_RETURN_HR_WHERE( "failed", E_GAMEUSER_FAILED_TO_GET_TOKEN );
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
    if (FAILED( hr )) XUSER_RETURN_HR_WHERE( "load token/client", hr );

    if (!(impl = calloc( 1, sizeof( *impl ) )))
    {
        WindowsDeleteString( client_id );
        WindowsDeleteString( refresh_token );
        XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
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
        XUSER_RETURN_HR_WHERE( "init user", hr );
    }

    *out = impl;
    XUSER_RETURN_HR( S_OK );
}

static HRESULT LoadDefaultUser( XUserHandle *user, XUserAddOptions options )
{
    HRESULT hr = S_OK;

    if (!user) XUSER_RETURN_HR_WHERE( "user pointer", E_POINTER );
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
    XUSER_RETURN_HR( hr );
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

    if (!providerData) XUSER_RETURN_HR_WHERE( "providerData", E_POINTER );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", E_FAIL );
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
    LPSTR method;
    LPWSTR method_utf16;
    LPSTR url;
    LPWSTR url_utf16;
    SIZE_T count;
    XUserGetTokenAndSignatureHttpHeader *headers;
    XUserGetTokenAndSignatureUtf16HttpHeader *headers_utf16;
    SIZE_T size;
    void *buffer;
    LPSTR authorization;
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

    if (!WinHttpCrackUrl( url, 0, 0, &components )) {
        FIXME( "url %s\n", debugstr_w( url ) );
        return HRESULT_FROM_WIN32( GetLastError() );
    }
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

static HRESULT sign_request( struct x_user *user, LPCSTR authorization, LPCSTR method, LPCWSTR url,
                             SIZE_T header_count, const XUserGetTokenAndSignatureHttpHeader *headers,
                             const void *body, SIZE_T body_size, LPSTR *signature )
{
    BYTE version[4] = {0, 0, 0, XUSER_SIGNATURE_POLICY_VERSION};
    BYTE timestamp[8], hash[32], *message = NULL, *ptr, *sig = NULL, *blob = NULL;
    DWORD sig_size = 0, blob_size, base64_size;
    ULARGE_INTEGER filetime_int;
    FILETIME filetime;
    LPSTR path_and_query = NULL, method_upper = NULL;
    SIZE_T method_len, path_len, auth_len, body_hash_size, message_size, i;
    HRESULT hr;
    NTSTATUS status;

    *signature = NULL;
    if (!user->signing_key) XUSER_RETURN_HR_WHERE( "signing_key", E_FAIL );
    if (FAILED( hr = get_path_and_query( url, &path_and_query ) )) XUSER_RETURN_HR_WHERE( "get_path_and_query", hr );

    method_len = strlen( method );
    if (!(method_upper = calloc( method_len + 1, sizeof( CHAR ) )))
    {
        free( path_and_query );
        XUSER_RETURN_HR_WHERE( "method_upper calloc", E_OUTOFMEMORY );
    }
    for (SIZE_T i = 0; i < method_len; i++) method_upper[i] = toupper( method[i] );

    GetSystemTimeAsFileTime( &filetime );
    filetime_int.LowPart = filetime.dwLowDateTime;
    filetime_int.HighPart = filetime.dwHighDateTime;
    for (int i = 0; i < 8; i++) timestamp[i] = (BYTE)(filetime_int.QuadPart >> ((7 - i) * 8));

    path_len = strlen( path_and_query );
    auth_len = authorization ? strlen( authorization ) : 0;
    body_hash_size = body_size < XUSER_SIGNATURE_MAX_BODY_BYTES ? body_size : XUSER_SIGNATURE_MAX_BODY_BYTES;
    message_size = sizeof( version ) + 1 + sizeof( timestamp ) + 1 + method_len + 1 + path_len + 1 + auth_len + 1 + body_hash_size + 1;
    for (i = 0; i < header_count; ++i) message_size += strlen( headers[i].value ? headers[i].value : "" ) + 1;
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
    if (auth_len) append_bytes( &ptr, authorization, auth_len );
    ptr++;
    for (i = 0; i < header_count; ++i)
    {
        SIZE_T header_len = strlen( headers[i].value ? headers[i].value : "" );

        if (header_len) append_bytes( &ptr, headers[i].value, header_len );
        ptr++;
    }
    if (body_hash_size) append_bytes( &ptr, body, body_hash_size );

    if (FAILED( hr = sha256_hash( message, message_size, hash ) )) goto done;
    if ((status = BCryptSignHash( user->signing_key, NULL, hash, sizeof( hash ), NULL, 0, &sig_size, 0 )))
    {
        FIXME( "BCryptSignHash size query failed %#lx, sig_size %lu\n", status, sig_size );
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
        if (status == XUSER_STATUS_BUFFER_TOO_SMALL)
        {
            BYTE *new_sig;

            FIXME( "BCryptSignHash retrying with sig_size %lu\n", sig_size );
            if (!(new_sig = realloc( sig, sig_size )))
            {
                hr = E_OUTOFMEMORY;
                goto done;
            }
            sig = new_sig;
            if (!(blob = realloc( blob, sizeof( version ) + sizeof( timestamp ) + sig_size )))
            {
                hr = E_OUTOFMEMORY;
                goto done;
            }
            if ((status = BCryptSignHash( user->signing_key, NULL, hash, sizeof( hash ), sig, sig_size, &sig_size, 0 )))
            {
                FIXME( "BCryptSignHash retry failed %#lx, sig_size %lu\n", status, sig_size );
                hr = HRESULT_FROM_NT( status );
                goto done;
            }
        }
        else
        {
            FIXME( "BCryptSignHash failed %#lx, sig_size %lu\n", status, sig_size );
            hr = HRESULT_FROM_NT( status );
            goto done;
        }
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
    XUSER_RETURN_HR( hr );
}

static HRESULT utf8_to_wide( LPCSTR str, LPWSTR *wide )
{
    int len;

    *wide = NULL;
    if (!(len = MultiByteToWideChar( CP_UTF8, 0, str, -1, NULL, 0 )))
        XUSER_RETURN_HR_WHERE( "length", HRESULT_FROM_WIN32( GetLastError() ) );
    if (!(*wide = calloc( len, sizeof( WCHAR ) ))) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
    if (!MultiByteToWideChar( CP_UTF8, 0, str, -1, *wide, len ))
    {
        free( *wide );
        *wide = NULL;
        XUSER_RETURN_HR_WHERE( "convert", HRESULT_FROM_WIN32( GetLastError() ) );
    }
    XUSER_RETURN_HR( S_OK );
}

static HRESULT wide_to_utf8( LPCWSTR wide, LPSTR *str )
{
    int len;

    *str = NULL;
    if (!(len = WideCharToMultiByte( CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL )))
        XUSER_RETURN_HR_WHERE( "length", HRESULT_FROM_WIN32( GetLastError() ) );
    if (!(*str = calloc( len, sizeof( CHAR ) ))) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
    if (!WideCharToMultiByte( CP_UTF8, 0, wide, -1, *str, len, NULL, NULL ))
    {
        free( *str );
        *str = NULL;
        XUSER_RETURN_HR_WHERE( "convert", HRESULT_FROM_WIN32( GetLastError() ) );
    }
    XUSER_RETURN_HR( S_OK );
}

static HRESULT wide_strdup( LPCWSTR wide, LPWSTR *copy )
{
    SIZE_T len;

    *copy = NULL;
    if ( !wide ) XUSER_RETURN_HR_WHERE( "wide", E_POINTER );
    len = wcslen( wide ) + 1;
    if ( !(*copy = calloc( len, sizeof( WCHAR ) )) ) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );
    memcpy( *copy, wide, len * sizeof( WCHAR ) );
    XUSER_RETURN_HR( S_OK );
}

static void free_ansi_headers( XUserGetTokenAndSignatureHttpHeader *headers, SIZE_T count )
{
    SIZE_T i;

    if (!headers) return;
    for (i = 0; i < count; ++i)
    {
        free( (void *)headers[i].name );
        free( (void *)headers[i].value );
    }
    free( headers );
}

static void free_utf16_headers( XUserGetTokenAndSignatureUtf16HttpHeader *headers, SIZE_T count )
{
    SIZE_T i;

    if (!headers) return;
    for (i = 0; i < count; ++i)
    {
        free( (void *)headers[i].name );
        free( (void *)headers[i].value );
    }
    free( headers );
}

static HRESULT copy_ansi_headers( struct XUserGetTokenAndSignatureContext *context,
                                  const XUserGetTokenAndSignatureHttpHeader *headers )
{
    SIZE_T i;

    if (!context->count) return S_OK;
    if (!(context->headers = calloc( context->count, sizeof( *context->headers ) )))
        XUSER_RETURN_HR_WHERE( "headers calloc", E_OUTOFMEMORY );

    for (i = 0; i < context->count; ++i)
    {
        if (!(context->headers[i].name = strdup( headers[i].name ? headers[i].name : "" )))
        {
            free_ansi_headers( context->headers, i );
            context->headers = NULL;
            XUSER_RETURN_HR_WHERE( "header name strdup", E_OUTOFMEMORY );
        }
        if (!(context->headers[i].value = strdup( headers[i].value ? headers[i].value : "" )))
        {
            free_ansi_headers( context->headers, i + 1 );
            context->headers = NULL;
            XUSER_RETURN_HR_WHERE( "header value strdup", E_OUTOFMEMORY );
        }
    }

    XUSER_RETURN_HR( S_OK );
}

static HRESULT copy_utf16_headers( struct XUserGetTokenAndSignatureContext *context,
                                   const XUserGetTokenAndSignatureUtf16HttpHeader *headers )
{
    SIZE_T i;
    HRESULT hr;

    if (!context->count) return S_OK;
    if (!(context->headers_utf16 = calloc( context->count, sizeof( *context->headers_utf16 ) )))
        XUSER_RETURN_HR_WHERE( "headers calloc", E_OUTOFMEMORY );

    for (i = 0; i < context->count; ++i)
    {
        if (FAILED( hr = wide_strdup( headers[i].name ? headers[i].name : L"", (LPWSTR *)&context->headers_utf16[i].name ) ))
        {
            free_utf16_headers( context->headers_utf16, i );
            context->headers_utf16 = NULL;
            XUSER_RETURN_HR_WHERE( "header name wide strdup", hr );
        }
        if (FAILED( hr = wide_strdup( headers[i].value ? headers[i].value : L"", (LPWSTR *)&context->headers_utf16[i].value ) ))
        {
            free_utf16_headers( context->headers_utf16, i + 1 );
            context->headers_utf16 = NULL;
            XUSER_RETURN_HR_WHERE( "header value wide strdup", hr );
        }
    }

    XUSER_RETURN_HR( S_OK );
}

static HRESULT copy_request_buffer( struct XUserGetTokenAndSignatureContext *context,
                                    const void *buffer, SIZE_T size )
{
    if (!size)
    {
        context->buffer = NULL;
        XUSER_RETURN_HR( S_OK );
    }

    if (!(context->buffer = malloc( size ))) XUSER_RETURN_HR_WHERE( "buffer malloc", E_OUTOFMEMORY );
    memcpy( context->buffer, buffer, size );
    XUSER_RETURN_HR( S_OK );
}

static HRESULT utf16_headers_to_utf8( const XUserGetTokenAndSignatureUtf16HttpHeader *headers_utf16,
                                      SIZE_T count, XUserGetTokenAndSignatureHttpHeader **headers )
{
    SIZE_T i;
    HRESULT hr;

    *headers = NULL;
    if (!count) return S_OK;
    if (!(*headers = calloc( count, sizeof( **headers ) ))) XUSER_RETURN_HR_WHERE( "calloc", E_OUTOFMEMORY );

    for (i = 0; i < count; ++i)
    {
        if (FAILED( hr = wide_to_utf8( headers_utf16[i].name, (LPSTR *)&(*headers)[i].name ) ) ||
            FAILED( hr = wide_to_utf8( headers_utf16[i].value, (LPSTR *)&(*headers)[i].value ) ))
        {
            for (SIZE_T j = 0; j <= i; ++j)
            {
                free( (void *)(*headers)[j].name );
                free( (void *)(*headers)[j].value );
            }
            free( *headers );
            *headers = NULL;
            XUSER_RETURN_HR_WHERE( "wide_to_utf8", hr );
        }
    }

    XUSER_RETURN_HR( S_OK );
}

static HRESULT token_context_prepare_result( struct XUserGetTokenAndSignatureContext *context )
{
    struct x_user *user = context->user;
    HSTRING request_xsts = NULL, request_user_hash = NULL;
    LPSTR request_xsts_str = NULL, request_user_hash_str = NULL, proof_key_json = NULL;
    XUserGetTokenAndSignatureHttpHeader *utf8_headers = NULL;
    LPWSTR url_w = NULL;
    LPSTR method = NULL;
    HRESULT hr;

    if (FAILED( hr = refresh_user_tokens( user, context->options & XUserGetTokenAndSignatureOptions_ForceRefresh ) ))
    {
        FIXME( "refresh_user_tokens failed %#lx\n", hr );
        XUSER_RETURN_HR_WHERE( "refresh_user_tokens", hr );
    }

    if ((!context->utf16 && !context->url[0]) || (context->utf16 && !context->url_utf16[0]))
    {
        if (FAILED( hr = export_proof_key_jwk( user->signing_key, &proof_key_json ) ))
        {
            FIXME( "export_proof_key_jwk failed %#lx\n", hr );
            XUSER_RETURN_HR_WHERE( "export_proof_key_jwk", hr );
        }
        if (FAILED( hr = RequestXstsTokenForUrlWithProofKey( user->user_token,
                                                             context->utf16 ? context->url_utf16 : L"https://xboxlive.com/",
                                                             proof_key_json, &request_xsts, &request_user_hash ) ))
        {
            free( proof_key_json );
            FIXME( "RequestXstsTokenForUrlWithProofKey failed %#lx\n", hr );
            XUSER_RETURN_HR_WHERE( "RequestXstsTokenForUrlWithProofKey", hr );
        }
        free( proof_key_json );
        if (FAILED( hr = hstring_to_nul_string( request_xsts, &request_xsts_str ) ))
        {
            WindowsDeleteString( request_xsts );
            WindowsDeleteString( request_user_hash );
            XUSER_RETURN_HR_WHERE( "request_xsts_str", hr );
        }
        WindowsDeleteString( request_xsts );
        if (FAILED( hr = hstring_to_nul_string( request_user_hash, &request_user_hash_str ) ))
        {
            free( request_xsts_str );
            WindowsDeleteString( request_user_hash );
            XUSER_RETURN_HR_WHERE( "request_user_hash_str", hr );
        }
        WindowsDeleteString( request_user_hash );
        if (FAILED( hr = create_authorization_string( request_user_hash_str, request_xsts_str,
                                                      !!(context->options & XUserGetTokenAndSignatureOptions_AllUsers),
                                                      &context->authorization ) ))
        {
            free( request_user_hash_str );
            free( request_xsts_str );
            XUSER_RETURN_HR_WHERE( "create_authorization_string", hr );
        }
        free( request_user_hash_str );
        free( request_xsts_str );
        if (!(context->token = strdup( context->authorization ? context->authorization : "" )))
        {
            FIXME( "token strdup failed\n" );
            XUSER_RETURN_HR_WHERE( "token strdup", E_OUTOFMEMORY );
        }
        FIXME( "token-only request, utf16 %u\n", context->utf16 );
        if (!(context->signature = strdup( "" )))
        {
            FIXME( "empty signature strdup failed\n" );
            XUSER_RETURN_HR_WHERE( "empty signature strdup", E_OUTOFMEMORY );
        }
        if (context->utf16)
        {
            int token_len = MultiByteToWideChar( CP_UTF8, 0, context->token, -1, NULL, 0 );
            int sig_len = MultiByteToWideChar( CP_UTF8, 0, context->signature, -1, NULL, 0 );
            if (!token_len || !sig_len)
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                FIXME( "token-only utf16 length conversion failed %#lx\n", hr );
                XUSER_RETURN_HR_WHERE( "token-only length conversion", hr );
            }
            if (!(context->token_utf16 = calloc( token_len, sizeof( WCHAR ) ))) XUSER_RETURN_HR_WHERE( "token_utf16 calloc", E_OUTOFMEMORY );
            if (!MultiByteToWideChar( CP_UTF8, 0, context->token, -1, context->token_utf16, token_len ))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                FIXME( "token-only token utf16 conversion failed %#lx\n", hr );
                XUSER_RETURN_HR_WHERE( "token-only token conversion", hr );
            }
            if (!(context->signature_utf16 = calloc( sig_len, sizeof( WCHAR ) ))) XUSER_RETURN_HR_WHERE( "signature_utf16 calloc", E_OUTOFMEMORY );
            if (!MultiByteToWideChar( CP_UTF8, 0, context->signature, -1, context->signature_utf16, sig_len ))
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                FIXME( "token-only signature utf16 conversion failed %#lx\n", hr );
                XUSER_RETURN_HR_WHERE( "token-only signature conversion", hr );
            }
            context->result_size = sizeof( XUserGetTokenAndSignatureUtf16Data ) + token_len * sizeof( WCHAR ) + sig_len * sizeof( WCHAR );
        }
        else
        {
            context->result_size = sizeof( XUserGetTokenAndSignatureData ) + strlen( context->token ) + 1 + 1;
        }
        XUSER_RETURN_HR_WHERE( "token-only", S_OK );
    }

    if (context->utf16)
    {
        if (FAILED( hr = wide_to_utf8( context->method_utf16, &method ) ))
        {
            FIXME( "method utf16 conversion failed %#lx\n", hr );
            XUSER_RETURN_HR_WHERE( "method utf16 conversion", hr );
        }
        url_w = (LPWSTR)context->url_utf16;
    }
    else
    {
        if (!(method = strdup( context->method )))
        {
            FIXME( "method strdup failed\n" );
            XUSER_RETURN_HR_WHERE( "method strdup", E_OUTOFMEMORY );
        }
        if (FAILED( hr = utf8_to_wide( context->url, &url_w ) ))
        {
            free( method );
            FIXME( "url utf8 conversion failed %#lx, url %s\n", hr, debugstr_a( context->url ) );
            XUSER_RETURN_HR_WHERE( "url utf8 conversion", hr );
        }
    }

    if (FAILED( hr = export_proof_key_jwk( user->signing_key, &proof_key_json ) ))
    {
        free( method );
        if (!context->utf16) free( url_w );
        FIXME( "export_proof_key_jwk failed %#lx\n", hr );
        XUSER_RETURN_HR_WHERE( "export_proof_key_jwk", hr );
    }
    if (FAILED( hr = RequestXstsTokenForUrlWithProofKey( user->user_token,
                                                         context->utf16 ? context->url_utf16 : url_w,
                                                         proof_key_json, &request_xsts, &request_user_hash ) ))
    {
        free( proof_key_json );
        free( method );
        if (!context->utf16) free( url_w );
        FIXME( "RequestXstsTokenForUrlWithProofKey failed %#lx\n", hr );
        XUSER_RETURN_HR_WHERE( "RequestXstsTokenForUrlWithProofKey", hr );
    }
    free( proof_key_json );
    if (FAILED( hr = hstring_to_nul_string( request_xsts, &request_xsts_str ) ))
    {
        WindowsDeleteString( request_xsts );
        WindowsDeleteString( request_user_hash );
        free( method );
        if (!context->utf16) free( url_w );
        XUSER_RETURN_HR_WHERE( "request_xsts_str", hr );
    }
    WindowsDeleteString( request_xsts );
    if (FAILED( hr = hstring_to_nul_string( request_user_hash, &request_user_hash_str ) ))
    {
        free( request_xsts_str );
        WindowsDeleteString( request_user_hash );
        free( method );
        if (!context->utf16) free( url_w );
        XUSER_RETURN_HR_WHERE( "request_user_hash_str", hr );
    }
    WindowsDeleteString( request_user_hash );
    if (FAILED( hr = create_authorization_string( request_user_hash_str, request_xsts_str,
                                                  !!(context->options & XUserGetTokenAndSignatureOptions_AllUsers),
                                                  &context->authorization ) ))
    {
        free( request_user_hash_str );
        free( request_xsts_str );
        free( method );
        if (!context->utf16) free( url_w );
        XUSER_RETURN_HR_WHERE( "create_authorization_string", hr );
    }
    free( request_user_hash_str );
    free( request_xsts_str );

    if (!(context->token = strdup( context->authorization ? context->authorization : "" )))
    {
        free( method );
        if (!context->utf16) free( url_w );
        FIXME( "token strdup failed\n" );
        XUSER_RETURN_HR_WHERE( "token strdup", E_OUTOFMEMORY );
    }

    if (context->utf16)
    {
        if (FAILED( hr = utf16_headers_to_utf8( context->headers_utf16, context->count, &utf8_headers ) ))
        {
            free( method );
            XUSER_RETURN_HR_WHERE( "utf16_headers_to_utf8", hr );
        }
        hr = sign_request( user, context->authorization, method, url_w, context->count, utf8_headers,
                           context->buffer, context->size, &context->signature );
        for (SIZE_T i = 0; i < context->count; ++i)
        {
            free( (void *)utf8_headers[i].name );
            free( (void *)utf8_headers[i].value );
        }
        free( utf8_headers );
    }
    else
    {
        hr = sign_request( user, context->authorization, method, url_w, context->count, context->headers,
                           context->buffer, context->size, &context->signature );
    }
    free( method );
    if (!context->utf16) free( url_w );
    if (FAILED( hr ))
    {
        FIXME( "sign_request failed %#lx\n", hr );
        XUSER_RETURN_HR_WHERE( "sign_request", hr );
    }

    if (context->utf16)
    {
        int token_len = MultiByteToWideChar( CP_UTF8, 0, context->token, -1, NULL, 0 );
        int sig_len = context->signature ? MultiByteToWideChar( CP_UTF8, 0, context->signature, -1, NULL, 0 ) : 0;
        if (!token_len || (context->signature && !sig_len)) XUSER_RETURN_HR_WHERE( "utf16 result length", HRESULT_FROM_WIN32( GetLastError() ) );
        if (!(context->token_utf16 = calloc( token_len, sizeof( WCHAR ) ))) XUSER_RETURN_HR_WHERE( "token_utf16 calloc", E_OUTOFMEMORY );
        if (!MultiByteToWideChar( CP_UTF8, 0, context->token, -1, context->token_utf16, token_len ))
            XUSER_RETURN_HR_WHERE( "token utf16 conversion", HRESULT_FROM_WIN32( GetLastError() ) );
        if (context->signature)
        {
            if (!(context->signature_utf16 = calloc( sig_len, sizeof( WCHAR ) ))) XUSER_RETURN_HR_WHERE( "signature_utf16 calloc", E_OUTOFMEMORY );
            if (!MultiByteToWideChar( CP_UTF8, 0, context->signature, -1, context->signature_utf16, sig_len ))
                XUSER_RETURN_HR_WHERE( "signature utf16 conversion", HRESULT_FROM_WIN32( GetLastError() ) );
        }
        context->result_size = sizeof( XUserGetTokenAndSignatureUtf16Data ) +
            token_len * sizeof( WCHAR ) + (context->signature ? sig_len * sizeof( WCHAR ) : 0);
    }
    else
    {
        context->result_size = sizeof( XUserGetTokenAndSignatureData ) +
            strlen( context->token ) + 1 + (context->signature ? strlen( context->signature ) + 1 : 0);
    }
    XUSER_RETURN_HR( S_OK );
}

static HRESULT token_context_get_result( struct XUserGetTokenAndSignatureContext *context, SIZE_T size, void *buffer, SIZE_T *used )
{
    BYTE *cursor = buffer;

    if (!buffer) XUSER_RETURN_HR_WHERE( "buffer", E_POINTER );
    if (size < context->result_size) XUSER_RETURN_HR_WHERE( "buffer too small", HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) );

    if (context->utf16)
    {
        XUserGetTokenAndSignatureUtf16Data *data = buffer;
        SIZE_T token_bytes = (wcslen( context->token_utf16 ) + 1) * sizeof( WCHAR );
        SIZE_T signature_bytes = context->signature_utf16 ? (wcslen( context->signature_utf16 ) + 1) * sizeof( WCHAR ) : 0;

        cursor += sizeof( *data );
        data->token = (LPCWSTR)cursor;
        data->tokenCount = wcslen( context->token_utf16 );
        memcpy( cursor, context->token_utf16, token_bytes );
        cursor += token_bytes;
        if (context->signature_utf16)
        {
            data->signature = (LPCWSTR)cursor;
            data->signatureCount = wcslen( context->signature_utf16 );
            memcpy( cursor, context->signature_utf16, signature_bytes );
        }
        else
        {
            __debug_check(1);
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
        data->tokenSize = token_bytes - 1;
        memcpy( cursor, context->token, token_bytes );
        cursor += token_bytes;
        if (context->signature)
        {
            data->signature = (LPCSTR)cursor;
            data->signatureSize = signature_bytes - 1;
            memcpy( cursor, context->signature, signature_bytes );
        }
        else
        {
            __debug_check(1);
            data->signature = NULL;
            data->signatureSize = 0;
        }
    }
    if (used) *used = context->result_size;
    XUSER_RETURN_HR( S_OK );
}

static HRESULT XUserGetTokenAndSignatureProvider( XAsyncOp operation, const XAsyncProviderData *providerData )
{
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    FIXME( "operation %d, providerData %p\n", operation, providerData );

    if (!providerData) return E_POINTER;
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) return E_FAIL;
    context = providerData->context;

    switch (operation)
    {
        case Begin:
            hr = impl->lpVtbl->XAsyncSchedule( impl, providerData->async, 0 );
            XUSER_RETURN_HR_WHERE( "XAsyncSchedule", hr );

        case GetResult:
            hr = token_context_get_result( context, providerData->bufferSize, providerData->buffer, NULL );
            XUSER_RETURN_HR_WHERE( "token_context_get_result", hr );

        case DoWork:
            hr = token_context_prepare_result( context );
            if (FAILED( hr )) FIXME( "token_context_prepare_result %#lx\n", hr );
            else FIXME( "token_context_prepare_result completed result_size %Iu\n", context->result_size );
            impl->lpVtbl->XAsyncComplete( impl, providerData->async, hr, SUCCEEDED( hr ) ? context->result_size : 0 );
            break;

        case Cleanup:
            if (context->count)
            {
                if (context->utf16) free_utf16_headers( context->headers_utf16, context->count );
                else free_ansi_headers( context->headers, context->count );
            }
            free( context->buffer );
            free( context->authorization );
            free( context->method );
            free( context->method_utf16 );
            free( context->token );
            free( context->signature );
            free( context->token_utf16 );
            free( context->url );
            free( context->url_utf16 );
            free( context->signature_utf16 );
            free( context );
            break;

        case Cancel:
            break;
    }

    XUSER_RETURN_HR( S_OK );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureAsync( IXUserImpl *iface, XUserHandle user, XUserGetTokenAndSignatureOptions options, LPCSTR method, LPCSTR url, SIZE_T count, const XUserGetTokenAndSignatureHttpHeader *headers, SIZE_T size, const void *buffer, XAsyncBlock *asyncBlock )
{
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    FIXME( "iface %p, user %p, options %d, method %s, url %s, count %llu, headers %p, size %llu, buffer %p, asyncBlock %p\n", iface, user, options, method, url, count, headers, size, buffer, asyncBlock );

    if (!user || !method || !url || (count && !headers) || (size && !buffer) || !asyncBlock) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    for (SIZE_T i = 0; i < count; i++) FIXME( "%s: %s", headers[i].name, headers[i].value );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", hr );
    if (!(context = calloc( 1, sizeof( *context ) )))
    {
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "context calloc", E_OUTOFMEMORY );
    }

    context->options = options;
    context->count = count;
    context->utf16 = FALSE;
    context->size = size;
    context->user = user;
    if (!(context->method = strdup( method )))
    {
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "method strdup", E_OUTOFMEMORY );
    }
    if (!(context->url = strdup( url )))
    {
        free( context->method );
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "url strdup", E_OUTOFMEMORY );
    }
    if (FAILED( hr = copy_ansi_headers( context, headers ) ))
    {
        free( context->url );
        free( context->method );
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "copy_ansi_headers", hr );
    }
    if (FAILED( hr = copy_request_buffer( context, buffer, size ) ))
    {
        free_ansi_headers( context->headers, context->count );
        free( context->url );
        free( context->method );
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "copy_request_buffer", hr );
    }

    FIXME( "iface %p, user %p, options %d, method %s, url %s, count %llu, headers %p, size %llu, buffer %p, asyncBlock %p\n", iface, user, options, method, url, count, headers, size, buffer, asyncBlock );
    hr = impl->lpVtbl->XAsyncBegin( impl, asyncBlock, context, x_user_XUserGetTokenAndSignatureAsync, "XUserGetTokenAndSignatureAsync", XUserGetTokenAndSignatureProvider );
    impl->lpVtbl->Release( impl );
    XUSER_RETURN_HR_WHERE( "XAsyncBegin", hr );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureResultSize( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *size )
{
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, asyncBlock %p, size %p\n", iface, asyncBlock, size );
    if (!asyncBlock || !size) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", E_FAIL );
    hr = impl->lpVtbl->XAsyncGetResultSize( impl, asyncBlock, size );
    FIXME( "XAsyncGetResultSize returned %#lx, size %Iu\n", hr, *size );
    if(FAILED(hr)) __debug_check(hr);
    XUSER_RETURN_HR_WHERE( "XAsyncGetResultSize", hr );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureResult( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T size, PVOID buffer, XUserGetTokenAndSignatureData **ptr, SIZE_T *used )
{
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, asyncBlock %p, size %llu, buffer %p, ptr %p, used %p\n", iface, asyncBlock, size, buffer, ptr, used );
    if (!asyncBlock || !buffer || !ptr) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", E_FAIL );
    FIXME( "XUserGetTokenAndSignatureResult buffer size %Iu\n", size );
    hr = impl->lpVtbl->XAsyncGetResult( impl, asyncBlock, x_user_XUserGetTokenAndSignatureAsync, size, buffer, used );
    if (SUCCEEDED( hr )) {
        *ptr = buffer;
        __debug_check(1);
        //FIXME("TOKEN %s | SIG %s", (*ptr)->token, (*ptr)->signature);
        FIXME("OK\n");
    } else {
        FIXME("FAILED");
    }
    XUSER_RETURN_HR_WHERE( "XAsyncGetResult", hr );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16Async( IXUserImpl *iface, XUserHandle user, XUserGetTokenAndSignatureOptions options, LPCWSTR method, LPCWSTR url, SIZE_T count, const XUserGetTokenAndSignatureUtf16HttpHeader *headers, SIZE_T size, const void *buffer, XAsyncBlock *asyncBlock )
{
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, user %p, options %d, method %s, url %s, count %llu, headers %p, size %llu, buffer %p, asyncBlock %p\n",
           iface, user, options, debugstr_w( method ), debugstr_w( url ), count, headers, size, buffer, asyncBlock );

    if (!user || !method || !url || (count && !headers) || (size && !buffer) || !asyncBlock) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", hr );
    if (!(context = calloc( 1, sizeof( *context ) )))
    {
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "context calloc", E_OUTOFMEMORY );
    }

    context->options = options;
    context->count = count;
    context->utf16 = TRUE;
    context->size = size;
    context->user = user;
    if (FAILED( hr = wide_strdup( method, &context->method_utf16 ) ))
    {
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "method wide strdup", hr );
    }
    if (FAILED( hr = wide_strdup( url, &context->url_utf16 ) ))
    {
        free( context->method_utf16 );
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "url wide strdup", hr );
    }
    if (FAILED( hr = copy_utf16_headers( context, headers ) ))
    {
        free( context->url_utf16 );
        free( context->method_utf16 );
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "copy_utf16_headers", hr );
    }
    if (FAILED( hr = copy_request_buffer( context, buffer, size ) ))
    {
        free_utf16_headers( context->headers_utf16, context->count );
        free( context->url_utf16 );
        free( context->method_utf16 );
        free( context );
        impl->lpVtbl->Release( impl );
        XUSER_RETURN_HR_WHERE( "copy_request_buffer", hr );
    }

    hr = impl->lpVtbl->XAsyncBegin( impl, asyncBlock, context, x_user_XUserGetTokenAndSignatureUtf16Async, "XUserGetTokenAndSignatureUtf16Async", XUserGetTokenAndSignatureProvider );
    impl->lpVtbl->Release( impl );
    XUSER_RETURN_HR_WHERE( "XAsyncBegin", hr );
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16ResultSize( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *size )
{
    IXThreadingImpl *impl;

    TRACE( "iface %p, asyncBlock %p, size %p\n", iface, asyncBlock, size );
    if (!asyncBlock || !size) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    if (FAILED( QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", E_FAIL );
    {
        HRESULT hr = impl->lpVtbl->XAsyncGetResultSize( impl, asyncBlock, size );
        XUSER_RETURN_HR_WHERE( "XAsyncGetResultSize", hr );
    }
}

static HRESULT WINAPI x_user_XUserGetTokenAndSignatureUtf16Result( IXUserImpl *iface, XAsyncBlock *asyncBlock, SIZE_T size, PVOID buffer, XUserGetTokenAndSignatureUtf16Data **ptr, SIZE_T *used )
{
    IXThreadingImpl *impl;
    HRESULT hr;

    TRACE( "iface %p, asyncBlock %p, size %llu, buffer %p, ptr %p, used %p\n", iface, asyncBlock, size, buffer, ptr, used );
    if (!asyncBlock || !buffer || !ptr) XUSER_RETURN_HR_WHERE( "args", E_POINTER );
    if (FAILED( hr = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void**)&impl ) )) XUSER_RETURN_HR_WHERE( "QueryApiImpl", E_FAIL );
    FIXME( "XUserGetTokenAndSignatureUtf16Result buffer size %Iu\n", size );
    hr = impl->lpVtbl->XAsyncGetResult( impl, asyncBlock, x_user_XUserGetTokenAndSignatureUtf16Async, size, buffer, used );
    if (SUCCEEDED( hr )) *ptr = buffer;
    XUSER_RETURN_HR_WHERE( "XAsyncGetResult", hr );
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
