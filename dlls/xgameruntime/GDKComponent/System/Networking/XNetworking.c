/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XSystem
 * 
 * Written by Weather
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

#include "XNetworking.h"

WINE_DEFAULT_DEBUG_CHANNEL(gdkc);

static HRESULT utf8_to_wide( LPCSTR str, LPWSTR *wide )
{
    int len;

    if ( !str || !wide ) return E_POINTER;

    if ( !(len = MultiByteToWideChar( CP_UTF8, 0, str, -1, NULL, 0 )) )
        return HRESULT_FROM_WIN32( GetLastError() );
    if ( !(*wide = calloc( len, sizeof( **wide ) )) )
        return E_OUTOFMEMORY;
    if ( !MultiByteToWideChar( CP_UTF8, 0, str, -1, *wide, len ) )
    {
        free( *wide );
        *wide = NULL;
        return HRESULT_FROM_WIN32( GetLastError() );
    }

    return S_OK;
}

static void x_networking_fixup_security_information_buffer( BYTE *buffer, SIZE_T buffer_size,
                                                            XNetworkingSecurityInformation **security_information )
{
    XNetworkingSecurityInformation *information;
    XNetworkingThumbprint *thumbprints;
    BYTE *thumbprint_buffer;
    SIZE_T i;

    (void)buffer_size;

    if ( !buffer || buffer_size < sizeof( *information ) ) return;

    information = (XNetworkingSecurityInformation *)buffer;
    thumbprints = (XNetworkingThumbprint *)(buffer + sizeof( *information ));
    thumbprint_buffer = (BYTE *)(thumbprints + information->thumbprintCount);

    if ( information->thumbprintCount )
    {
        information->thumbprints = thumbprints;
        for ( i = 0; i < information->thumbprintCount; ++i )
        {
            if ( thumbprints[i].thumbprintBufferByteCount )
            {
                thumbprints[i].thumbprintBuffer = thumbprint_buffer;
                thumbprint_buffer += thumbprints[i].thumbprintBufferByteCount;
            }
            else
            {
                thumbprints[i].thumbprintBuffer = NULL;
            }
        }
    }
    else
    {
        information->thumbprints = NULL;
    }

    if ( security_information ) *security_information = information;
}

static HRESULT CALLBACK HTTPClientProvider( XAsyncOp operation, const XAsyncProviderData *data )
{
    HRESULT status;
    IXThreadingImpl *threadingImpl;

    struct UrlSecurityInfoContext *context = (struct UrlSecurityInfoContext *)data->context;

    // Threading module may be obtained from another binary.
    TRACE( "operation %d, data %p\n", operation, data );

    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    switch ( operation )
    {
        case Begin:
            status = IXThreadingImpl_XAsyncSchedule( threadingImpl, data->async, 100 );
            break;

        case DoWork:
            status = httpclient_ObtainSecurityInformationForUrl( context->url,
                                                                 &context->securityInformationBuffer,
                                                                 &context->securityInformationBufferCount,
                                                                 NULL );
            IXThreadingImpl_XAsyncComplete( threadingImpl, data->async, status, context->securityInformationBufferCount );
            break;

        case GetResult:
            if ( data->buffer && data->bufferSize >= context->securityInformationBufferCount )
            {
                memcpy( data->buffer, context->securityInformationBuffer, context->securityInformationBufferCount );
                status = S_OK;
            }
            else status = HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
            break;

        case Cancel:
            IXThreadingImpl_XAsyncComplete( threadingImpl, data->async, E_ABORT, 0 );
            status = S_OK;
            break;

        case Cleanup:
            free( context->securityInformationBuffer );
            if ( context->owns_url ) free( context->url );
            free( context );
            status = S_OK;
            break;

        default:
            status = E_NOTIMPL;
            break;
    }

    IXThreadingImpl_Release( threadingImpl );
    return status;
}

static inline struct x_networking *impl_from_IXNetworkingImpl( IXNetworkingImpl *iface )
{
    return CONTAINING_RECORD( iface, struct x_networking, IXNetworkingImpl_iface );
}

static HRESULT WINAPI x_networking_QueryInterface( IXNetworkingImpl *iface, REFIID iid, void **out )
{
    struct x_networking *impl = impl_from_IXNetworkingImpl( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) ||
        IsEqualGUID( iid, &IID_IXNetworkingImpl ) ||
        //  For some strange, unexplainable reason, the xgameruntime.lib library shipped with
        // PlayFabMultiplayerGDK has the GUID of IXNetworkingImpl of the class Id of XNetworking.
        // This is for compatibility reasons only.
        IsEqualGUID( iid, &CLSID_XNetworkingImpl ))
    {
        *out = &impl->IXNetworkingImpl_iface;
        impl->IXNetworkingImpl_iface.lpVtbl->AddRef( *out );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI x_networking_AddRef( IXNetworkingImpl *iface )
{
    struct x_networking *impl = impl_from_IXNetworkingImpl( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p increasing refcount to %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI x_networking_Release( IXNetworkingImpl *iface )
{
    struct x_networking *impl = impl_from_IXNetworkingImpl( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p decreasing refcount to %lu.\n", iface, ref );
    return ref;
}

static HRESULT WINAPI x_networking_XNetworkingQueryPreferredLocalUdpMultiplayerPort( IXNetworkingImpl *iface, UINT16 *preferredLocalUdpMultiplayerPort )
{
    FIXME( "iface %p, preferredLocalUdpMultiplayerPort %p stub!\n", iface, preferredLocalUdpMultiplayerPort );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_networking_XNetworkingQueryPreferredLocalUdpMultiplayerPortAsync( IXNetworkingImpl *iface, XAsyncBlock *asyncBlock )
{
    FIXME( "iface %p, asyncBlock %p stub!\n", iface, asyncBlock );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_networking_XNetworkingQueryPreferredLocalUdpMultiplayerPortAsyncResult( IXNetworkingImpl *iface, XAsyncBlock *asyncBlock, UINT16 *preferredLocalUdpMultiplayerPort )
{
    FIXME( "iface %p, asyncBlock %p, preferredLocalUdpMultiplayerPort %p stub!\n", iface, asyncBlock, preferredLocalUdpMultiplayerPort );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_networking_XNetworkingRegisterPreferredLocalUdpMultiplayerPortChanged( IXNetworkingImpl *iface, XTaskQueueHandle queue, PVOID context, XNetworkingPreferredLocalUdpMultiplayerPortChangedCallback *callback, XTaskQueueRegistrationToken *token )
{
    FIXME( "iface %p, queue %p, context %p, callback %p, token %p stub!\n", iface, queue, context, callback, token );
    return E_NOTIMPL;
}

static BOOLEAN WINAPI x_networking_XNetworkingUnregisterPreferredLocalUdpMultiplayerPortChanged( IXNetworkingImpl *iface, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    FIXME( "iface %p, token %p, wait %d stub!\n", iface, &token, wait );
    return FALSE;
}

static HRESULT WINAPI x_networking_XNetworkingQuerySecurityInformationForUrlAsync( IXNetworkingImpl *iface, LPCSTR url, XAsyncBlock *asyncBlock )
{
    struct UrlSecurityInfoContext *context;
    IXThreadingImpl *threadingImpl;
    HRESULT status;

    TRACE( "iface %p, url %s, asyncBlock %p.\n", iface, debugstr_a( url ), asyncBlock );

    if ( !url || !asyncBlock ) return E_POINTER;

    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    context = calloc( 1, sizeof( *context ) );
    if ( !context )
    {
        IXThreadingImpl_Release( threadingImpl );
        return E_OUTOFMEMORY;
    }

    status = utf8_to_wide( url, &context->url );
    if ( FAILED( status ) )
    {
        free( context );
        IXThreadingImpl_Release( threadingImpl );
        return status;
    }

    context->owns_url = TRUE;
    status = IXThreadingImpl_XAsyncBegin( threadingImpl, asyncBlock, context,
                                          x_networking_XNetworkingQuerySecurityInformationForUrlAsync,
                                          "XNetworkingQuerySecurityInformationForUrlAsync", HTTPClientProvider );
    IXThreadingImpl_Release( threadingImpl );

    if ( FAILED( status ) )
    {
        free( context->url );
        free( context );
    }

    return status;
}

static HRESULT WINAPI x_networking_XNetworkingQuerySecurityInformationForUrlAsyncResultSize( IXNetworkingImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *securityInformationBufferByteCount )
{
    IXThreadingImpl *threadingImpl;
    HRESULT status;

    TRACE( "iface %p, asyncBlock %p, securityInformationBufferByteCount %p.\n",
           iface, asyncBlock, securityInformationBufferByteCount );

    if ( !asyncBlock || !securityInformationBufferByteCount ) return E_POINTER;

    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    status = IXThreadingImpl_XAsyncGetResultSize( threadingImpl, asyncBlock, securityInformationBufferByteCount );
    IXThreadingImpl_Release( threadingImpl );
    return status;
}

static HRESULT WINAPI x_networking_XNetworkingQuerySecurityInformationForUrlAsyncResult( IXNetworkingImpl *iface, XAsyncBlock *asyncBlock, SIZE_T securityInformationBufferByteCount, SIZE_T *securityInformationBufferByteCountUsed, UINT8 *securityInformationBuffer, XNetworkingSecurityInformation **securityInformation )
{
    IXThreadingImpl *threadingImpl;
    HRESULT status;

    TRACE( "iface %p, asyncBlock %p, securityInformationBufferByteCount %Iu, securityInformationBufferByteCountUsed %p, securityInformationBuffer %p, securityInformation %p.\n",
           iface, asyncBlock, securityInformationBufferByteCount, securityInformationBufferByteCountUsed,
           securityInformationBuffer, securityInformation );

    if ( !asyncBlock || !securityInformationBuffer || !securityInformation ) return E_POINTER;

    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    status = IXThreadingImpl_XAsyncGetResult( threadingImpl, asyncBlock,
                                              x_networking_XNetworkingQuerySecurityInformationForUrlAsync,
                                              securityInformationBufferByteCount, securityInformationBuffer,
                                              securityInformationBufferByteCountUsed );
    IXThreadingImpl_Release( threadingImpl );
    if ( FAILED( status ) ) return status;

    x_networking_fixup_security_information_buffer( securityInformationBuffer, securityInformationBufferByteCount,
                                                    securityInformation );
    return S_OK;
}

static HRESULT WINAPI x_networking_XNetworkingQuerySecurityInformationForUrlUtf16Async( IXNetworkingImpl *iface, LPCWSTR url, XAsyncBlock *asyncBlock )
{
    struct UrlSecurityInfoContext *context;
    HRESULT status;
    IXThreadingImpl *threadingImpl;

    TRACE( "iface %p, url %p, asyncBlock %p.\n", iface, url, asyncBlock );

    // Threading module may be obtained from another binary.
    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    context = calloc( 1, sizeof( *context ) );
    if ( !context )
    {
        IXThreadingImpl_Release( threadingImpl );
        return E_OUTOFMEMORY;
    }

    context->url = (LPWSTR)url;

    status = IXThreadingImpl_XAsyncBegin( threadingImpl, asyncBlock, context,
                                          x_networking_XNetworkingQuerySecurityInformationForUrlUtf16Async,
                                          "XNetworkingQuerySecurityInformationForUrlUtf16Async", HTTPClientProvider );
    IXThreadingImpl_Release( threadingImpl );

    if ( FAILED( status ) )
    {
        free( context );
    }

    return status;
}

static HRESULT WINAPI x_networking_XNetworkingQuerySecurityInformationForUrlUtf16AsyncResultSize( IXNetworkingImpl *iface, XAsyncBlock *asyncBlock, SIZE_T *securityInformationBufferByteCount )
{
    HRESULT status;
    IXThreadingImpl *threadingImpl;

    TRACE( "iface %p, asyncBlock %p, securityInformationBufferByteCount %p.\n", iface, asyncBlock, securityInformationBufferByteCount );

    // Threading module may be obtained from another binary.
    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    status = IXThreadingImpl_XAsyncGetResultSize( threadingImpl, asyncBlock, securityInformationBufferByteCount );
    IXThreadingImpl_Release( threadingImpl );
    return status;
}

static HRESULT WINAPI x_networking_XNetworkingQuerySecurityInformationForUrlUtf16AsyncResult( IXNetworkingImpl *iface, XAsyncBlock *asyncBlock, SIZE_T securityInformationBufferByteCount, SIZE_T *securityInformationBufferByteCountUsed, UINT8 *securityInformationBuffer, XNetworkingSecurityInformation **securityInformation )
{
    HRESULT status;
    IXThreadingImpl *threadingImpl;

    TRACE( "iface %p, asyncBlock %p, securityInformationBufferByteCount %Iu, securityInformationBufferByteCountUsed %p, securityInformationBuffer %p, securityInformation %p.\n",
           iface, asyncBlock, securityInformationBufferByteCount, securityInformationBufferByteCountUsed,
           securityInformationBuffer, securityInformation );
    
    // Threading module may be obtained from another binary.
    status = QueryApiImpl( &CLSID_XThreadingImpl, &IID_IXThreadingImpl, (void **)&threadingImpl );
    if ( FAILED( status ) ) return status;

    status = IXThreadingImpl_XAsyncGetResult( threadingImpl, asyncBlock,
                                              x_networking_XNetworkingQuerySecurityInformationForUrlUtf16Async,
                                              securityInformationBufferByteCount, securityInformationBuffer,
                                              securityInformationBufferByteCountUsed );
    IXThreadingImpl_Release( threadingImpl );
    if ( FAILED( status ) ) return status;

    x_networking_fixup_security_information_buffer( securityInformationBuffer, securityInformationBufferByteCount,
                                                    securityInformation );
    return S_OK;
}

static HRESULT WINAPI x_networking_XNetworkingVerifyServerCertificate( IXNetworkingImpl *iface, PVOID requestHandle, const XNetworkingSecurityInformation *securityInformation )
{
    FIXME( "iface %p, requestHandle %p, securityInformation %p stub!\n", iface, requestHandle, securityInformation );
    return S_OK;
}

static HRESULT WINAPI x_networking_XNetworkingGetConnectivityHint( IXNetworkingImpl *iface, XNetworkingConnectivityHint *connectivityHint )
{
    XNetworkingConnectivityHint hint;

    TRACE( "iface %p, connectivityHint %p\n", iface, connectivityHint );

    hint.ianaInterfaceType = 0; // There's no direct way to get NDIS interface type in userspace.
    hint.roaming = FALSE;
    hint.overDataLimit = FALSE;
    hint.networkInitialized = TRUE;
    hint.approachingDataLimit = FALSE;
    hint.connectivityLevel = ConnectivityLevelHintInternetAccess;
    hint.connectivityCost = ConnectivityCostHintUnrestricted;

    *connectivityHint = hint;

    return S_OK;
}

static HRESULT WINAPI x_networking_XNetworkingRegisterConnectivityHintChanged( IXNetworkingImpl *iface, XTaskQueueHandle queue, PVOID context, XNetworkingConnectivityHintChangedCallback *callback, XTaskQueueRegistrationToken *token )
{
    XNetworkingConnectivityHint hint;
    FIXME( "iface %p, queue %p, context %p, callback %p, token %p stub!\n", iface, queue, context, callback, token );
    x_networking_XNetworkingGetConnectivityHint( iface, &hint );
    callback( context, &hint );
    return S_OK;
}

static BOOLEAN WINAPI x_networking_XNetworkingUnregisterConnectivityHintChanged( IXNetworkingImpl *iface, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    FIXME( "iface %p, token %p, wait %d stub!\n", iface, &token, wait );
    return FALSE;
}

static HRESULT WINAPI x_networking_XNetworkingQueryConfigurationSetting( IXNetworkingImpl *iface, XNetworkingConfigurationSetting configurationSetting, UINT64 *value )
{
    FIXME( "iface %p, configurationSetting %d, value %p stub!\n", iface, configurationSetting, value );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_networking_XNetworkingSetConfigurationSetting( IXNetworkingImpl *iface, XNetworkingConfigurationSetting configurationParameter, UINT64 value )
{
    FIXME( "iface %p, configurationParameter %d, value %llu stub!\n", iface, configurationParameter, value );
    return E_NOTIMPL;
}

static HRESULT WINAPI x_networking_XNetworkingQueryStatistics( IXNetworkingImpl *iface, XNetworkingStatisticsBuffer *statisticsBuffer )
{
    FIXME( "iface %p, statisticsBuffer %p stub!\n", iface, statisticsBuffer );
    return E_NOTIMPL;
}

static const struct IXNetworkingImplVtbl x_networking_vtbl =
{
    x_networking_QueryInterface,
    x_networking_AddRef,
    x_networking_Release, 
    /* IXNetworkingImpl methods */
    x_networking_XNetworkingQueryPreferredLocalUdpMultiplayerPort,
    x_networking_XNetworkingQueryPreferredLocalUdpMultiplayerPortAsync,
    x_networking_XNetworkingQueryPreferredLocalUdpMultiplayerPortAsyncResult,
    x_networking_XNetworkingRegisterPreferredLocalUdpMultiplayerPortChanged,
    x_networking_XNetworkingUnregisterPreferredLocalUdpMultiplayerPortChanged,
    x_networking_XNetworkingQuerySecurityInformationForUrlAsync,
    x_networking_XNetworkingQuerySecurityInformationForUrlAsyncResultSize,
    x_networking_XNetworkingQuerySecurityInformationForUrlAsyncResult,
    x_networking_XNetworkingQuerySecurityInformationForUrlUtf16Async,
    x_networking_XNetworkingQuerySecurityInformationForUrlUtf16AsyncResultSize,
    x_networking_XNetworkingQuerySecurityInformationForUrlUtf16AsyncResult,
    x_networking_XNetworkingVerifyServerCertificate,
    x_networking_XNetworkingGetConnectivityHint,
    x_networking_XNetworkingRegisterConnectivityHintChanged,
    x_networking_XNetworkingUnregisterConnectivityHintChanged,
    x_networking_XNetworkingQueryConfigurationSetting,
    x_networking_XNetworkingSetConfigurationSetting,
    x_networking_XNetworkingQueryStatistics,
};

static struct x_networking x_networking =
{
    {&x_networking_vtbl},
    0,
};

IXNetworkingImpl *x_networking_impl = &x_networking.IXNetworkingImpl_iface;
