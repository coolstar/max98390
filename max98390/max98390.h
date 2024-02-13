#if !defined(_MAX98390_H_)
#define _MAX98390_H_

#pragma warning(disable:4200)  // suppress nameless struct/union warning
#pragma warning(disable:4201)  // suppress nameless struct/union warning
#pragma warning(disable:4214)  // suppress bit field types other than int warning
#include <initguid.h>
#include <wdm.h>

#pragma warning(default:4200)
#pragma warning(default:4201)
#pragma warning(default:4214)
#include <wdf.h>

#include <portcls.h>

#include <acpiioct.h>
#include <ntstrsafe.h>

#include <stdint.h>

#include "spb.h"

//
// String definitions
//

#define DRIVERNAME                 "max98390.sys: "

#define MAX98390_POOL_TAG            (ULONG) '3XAM'

#define true 1
#define false 0

typedef enum {
	CSAudioEndpointTypeDSP,
	CSAudioEndpointTypeSpeaker,
	CSAudioEndpointTypeHeadphone,
	CSAudioEndpointTypeMicArray,
	CSAudioEndpointTypeMicJack
} CSAudioEndpointType;

typedef enum {
	CSAudioEndpointRegister,
	CSAudioEndpointStart,
	CSAudioEndpointStop,
	CSAudioEndpointOverrideFormat
} CSAudioEndpointRequest;

typedef struct CSAUDIOFORMATOVERRIDE {
	UINT16 channels;
	UINT16 frequency;
	UINT16 bitsPerSample;
	UINT16 validBitsPerSample;
	BOOL force32BitOutputContainer;
} CsAudioFormatOverride;

typedef struct CSAUDIOARG {
	UINT32 argSz;
	CSAudioEndpointType endpointType;
	CSAudioEndpointRequest endpointRequest;
	union {
		CsAudioFormatOverride formatOverride;
	};
} CsAudioArg, * PCsAudioArg;

typedef struct _MAX98390_CONTEXT
{

	WDFDEVICE FxDevice;

	WDFQUEUE ReportQueue;

	SPB_CONTEXT I2CContext;

	BOOLEAN SetUID;
	INT32 UID;

	BOOLEAN DevicePoweredOn;
	BOOLEAN DidSwResetOnce;

	PCALLBACK_OBJECT CSAudioAPICallback;
	PVOID CSAudioAPICallbackObj;

	BOOL CSAudioManaged;
	BOOLEAN CSAudioRequestsOn;

} MAX98390_CONTEXT, *PMAX98390_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(MAX98390_CONTEXT, GetDeviceContext)

//
// Function definitions
//

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_UNLOAD Max98390DriverUnload;

EVT_WDF_DRIVER_DEVICE_ADD Max98390EvtDeviceAdd;

EVT_WDFDEVICE_WDM_IRP_PREPROCESS Max98390EvtWdmPreprocessMnQueryId;

EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL Max98390EvtInternalDeviceControl;

//
// Helper macros
//

#define DEBUG_LEVEL_ERROR   1
#define DEBUG_LEVEL_INFO    2
#define DEBUG_LEVEL_VERBOSE 3

#define DBG_INIT  1
#define DBG_PNP   2
#define DBG_IOCTL 4

#if 0
#define Max98390Print(dbglevel, dbgcatagory, fmt, ...) {          \
    if (Max98390DebugLevel >= dbglevel &&                         \
        (Max98390DebugCatagories && dbgcatagory))                 \
	    {                                                           \
        DbgPrint(DRIVERNAME);                                   \
        DbgPrint(fmt, __VA_ARGS__);                             \
	    }                                                           \
}
#else
#define Max98390Print(dbglevel, fmt, ...) {                       \
}
#endif

#endif