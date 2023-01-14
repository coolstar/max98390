#include "max98390.h"
#include "registers.h"
#include "firmware.h"

#define bool int

static ULONG Max98390DebugLevel = 100;
static ULONG Max98390DebugCatagories = DBG_INIT || DBG_PNP || DBG_IOCTL;

NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT  DriverObject,
	__in PUNICODE_STRING RegistryPath
)
{
	NTSTATUS               status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG      config;
	WDF_OBJECT_ATTRIBUTES  attributes;

	Max98390Print(DEBUG_LEVEL_INFO, DBG_INIT,
		"Driver Entry\n");

	WDF_DRIVER_CONFIG_INIT(&config, Max98390EvtDeviceAdd);

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

	//
	// Create a framework driver object to represent our driver.
	//

	status = WdfDriverCreate(DriverObject,
		RegistryPath,
		&attributes,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status))
	{
		Max98390Print(DEBUG_LEVEL_ERROR, DBG_INIT,
			"WdfDriverCreate failed with status 0x%x\n", status);
	}

	return status;
}

NTSTATUS max98390_reg_read(
	_In_ PMAX98390_CONTEXT pDevice,
	uint16_t reg,
	uint8_t* data
) {
	uint8_t buf[2];
	buf[0] = (reg >> 8) & 0xff;
	buf[1] = reg & 0xff;

	uint8_t raw_data = 0;
	NTSTATUS status = SpbXferDataSynchronously(&pDevice->I2CContext, buf, sizeof(buf), &raw_data, sizeof(uint8_t));
	*data = raw_data;
	return status;
}

NTSTATUS max98390_reg_write(
	_In_ PMAX98390_CONTEXT pDevice,
	uint16_t reg,
	uint8_t data
) {
	uint8_t buf[3];
	buf[0] = (reg >> 8) & 0xff;
	buf[1] = reg & 0xff;
	buf[2] = data;
	return SpbWriteDataSynchronously(&pDevice->I2CContext, buf, sizeof(buf));
}

NTSTATUS max98390_reg_update(
	_In_ PMAX98390_CONTEXT pDevice,
	uint16_t reg,
	uint8_t mask,
	uint8_t val
) {
	uint8_t tmp = 0, orig = 0;

	NTSTATUS status = max98390_reg_read(pDevice, reg, &orig);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	tmp = orig & ~mask;
	tmp |= val & mask;

	if (tmp != orig) {
		status = max98390_reg_write(pDevice, reg, tmp);
	}
	return status;
}

NTSTATUS
GetDeviceUID(
	_In_ WDFDEVICE FxDevice,
	_In_ PINT32 PUID
)
{
	NTSTATUS status = STATUS_ACPI_NOT_INITIALIZED;
	ACPI_EVAL_INPUT_BUFFER_EX inputBuffer;
	RtlZeroMemory(&inputBuffer, sizeof(inputBuffer));

	inputBuffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE_EX;
	status = RtlStringCchPrintfA(
		inputBuffer.MethodName,
		sizeof(inputBuffer.MethodName),
		"_UID"
	);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	WDFMEMORY outputMemory;
	PACPI_EVAL_OUTPUT_BUFFER outputBuffer;
	size_t outputArgumentBufferSize = 32;
	size_t outputBufferSize = FIELD_OFFSET(ACPI_EVAL_OUTPUT_BUFFER, Argument) + outputArgumentBufferSize;

	WDF_OBJECT_ATTRIBUTES attributes;
	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.ParentObject = FxDevice;

	status = WdfMemoryCreate(&attributes,
		NonPagedPoolNx,
		0,
		outputBufferSize,
		&outputMemory,
		(PVOID*)&outputBuffer);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlZeroMemory(outputBuffer, outputBufferSize);

	WDF_MEMORY_DESCRIPTOR inputMemDesc;
	WDF_MEMORY_DESCRIPTOR outputMemDesc;
	WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&inputMemDesc, &inputBuffer, (ULONG)sizeof(inputBuffer));
	WDF_MEMORY_DESCRIPTOR_INIT_HANDLE(&outputMemDesc, outputMemory, NULL);

	status = WdfIoTargetSendInternalIoctlSynchronously(
		WdfDeviceGetIoTarget(FxDevice),
		NULL,
		IOCTL_ACPI_EVAL_METHOD_EX,
		&inputMemDesc,
		&outputMemDesc,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	if (outputBuffer->Signature != ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE) {
		goto Exit;
	}

	if (outputBuffer->Count < 1) {
		goto Exit;
	}

	uint32_t uid;
	if (outputBuffer->Argument[0].DataLength >= 4) {
		uid = *(uint32_t*)outputBuffer->Argument->Data;
	}
	else if (outputBuffer->Argument[0].DataLength >= 2) {
		uid = *(uint16_t*)outputBuffer->Argument->Data;
	}
	else {
		uid = *(uint8_t*)outputBuffer->Argument->Data;
	}
	if (PUID) {
		*PUID = uid;
	}
	else {
		status = STATUS_ACPI_INVALID_ARGUMENT;
	}
Exit:
	if (outputMemory != WDF_NO_HANDLE) {
		WdfObjectDelete(outputMemory);
	}
	return status;
}

int CsAudioArg2 = 1;

static NTSTATUS GetIntegerProperty(
	_In_ WDFDEVICE FxDevice,
	char* propertyStr,
	UINT16* property
) {
	PMAX98390_CONTEXT pDevice = GetDeviceContext(FxDevice);
	WDFMEMORY outputMemory = WDF_NO_HANDLE;

	NTSTATUS status = STATUS_ACPI_NOT_INITIALIZED;

	size_t inputBufferLen = sizeof(ACPI_GET_DEVICE_SPECIFIC_DATA) + strlen(propertyStr) + 1;
	ACPI_GET_DEVICE_SPECIFIC_DATA* inputBuffer = ExAllocatePoolWithTag(NonPagedPool, inputBufferLen, MAX98390_POOL_TAG);
	if (!inputBuffer) {
		goto Exit;
	}
	RtlZeroMemory(inputBuffer, inputBufferLen);

	inputBuffer->Signature = IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA_SIGNATURE;

	unsigned char uuidend[] = { 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01 };

	inputBuffer->Section.Data1 = 0xdaffd814;
	inputBuffer->Section.Data2 = 0x6eba;
	inputBuffer->Section.Data3 = 0x4d8c;
	memcpy(inputBuffer->Section.Data4, uuidend, sizeof(uuidend)); //Avoid Windows defender false positive

	strcpy(inputBuffer->PropertyName, propertyStr);
	inputBuffer->PropertyNameLength = strlen(propertyStr) + 1;

	PACPI_EVAL_OUTPUT_BUFFER outputBuffer;
	size_t outputArgumentBufferSize = 8;
	size_t outputBufferSize = FIELD_OFFSET(ACPI_EVAL_OUTPUT_BUFFER, Argument) + sizeof(ACPI_METHOD_ARGUMENT_V1) + outputArgumentBufferSize;

	WDF_OBJECT_ATTRIBUTES attributes;
	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.ParentObject = FxDevice;
	status = WdfMemoryCreate(&attributes,
		NonPagedPoolNx,
		0,
		outputBufferSize,
		&outputMemory,
		&outputBuffer);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	WDF_MEMORY_DESCRIPTOR inputMemDesc;
	WDF_MEMORY_DESCRIPTOR outputMemDesc;
	WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&inputMemDesc, inputBuffer, (ULONG)inputBufferLen);
	WDF_MEMORY_DESCRIPTOR_INIT_HANDLE(&outputMemDesc, outputMemory, NULL);

	status = WdfIoTargetSendInternalIoctlSynchronously(
		WdfDeviceGetIoTarget(FxDevice),
		NULL,
		IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA,
		&inputMemDesc,
		&outputMemDesc,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		Max98390Print(
			DEBUG_LEVEL_ERROR,
			DBG_IOCTL,
			"Error getting device data - 0x%x\n",
			status);
		goto Exit;
	}

	if (outputBuffer->Signature != ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE_V1 &&
		outputBuffer->Count < 1 &&
		outputBuffer->Argument->Type != ACPI_METHOD_ARGUMENT_INTEGER &&
		outputBuffer->Argument->DataLength < 1) {
		status = STATUS_ACPI_INVALID_ARGUMENT;
		goto Exit;
	}

	if (property) {
		*property = outputBuffer->Argument->Data[0] & 0xF;
	}

Exit:
	if (inputBuffer) {
		ExFreePoolWithTag(inputBuffer, MAX98390_POOL_TAG);
	}
	if (outputMemory != WDF_NO_HANDLE) {
		WdfObjectDelete(outputMemory);
	}
	return status;
}

#define MAX_DEVICE_REG_VAL_LENGTH 0x100
NTSTATUS GetSmbiosName(WCHAR systemProductName[MAX_DEVICE_REG_VAL_LENGTH]) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE parentKey = NULL;
	UNICODE_STRING ParentKeyName;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	RtlInitUnicodeString(&ParentKeyName, L"\\Registry\\Machine\\Hardware\\DESCRIPTION\\System\\BIOS");

	InitializeObjectAttributes(&ObjectAttributes,
		&ParentKeyName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,    // handle
		NULL);

	status = ZwOpenKey(&parentKey, KEY_READ, &ObjectAttributes);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	ULONG ResultLength;
	PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolZero(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_DEVICE_REG_VAL_LENGTH, MAX98390_POOL_TAG);
	if (!KeyValueInfo) {
		status = STATUS_NO_MEMORY;
		goto exit;
	}

	UNICODE_STRING SystemProductNameValue;
	RtlInitUnicodeString(&SystemProductNameValue, L"SystemProductName");
	status = ZwQueryValueKey(parentKey, &SystemProductNameValue, KeyValuePartialInformation, KeyValueInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_DEVICE_REG_VAL_LENGTH, &ResultLength);
	if (!NT_SUCCESS(status)) {
		goto exit;
	}

	if (KeyValueInfo->DataLength > MAX_DEVICE_REG_VAL_LENGTH) {
		status = STATUS_BUFFER_OVERFLOW;
		goto exit;
	}

	RtlZeroMemory(systemProductName, sizeof(systemProductName));
	RtlCopyMemory(systemProductName, &KeyValueInfo->Data, KeyValueInfo->DataLength);

exit:
	if (KeyValueInfo) {
		ExFreePoolWithTag(KeyValueInfo, MAX98390_POOL_TAG);
	}
	return status;
}

void max98390_init_regs(PMAX98390_CONTEXT pDevice, UINT8 vmon_slot_no, UINT8 imon_slot_no) {
	max98390_reg_write(pDevice, MAX98390_CLK_MON, 0x6f);
	max98390_reg_write(pDevice, MAX98390_DAT_MON, 0x00);
	max98390_reg_write(pDevice, MAX98390_PWR_GATE_CTL, 0x00);
	max98390_reg_write(pDevice, MAX98390_PCM_RX_EN_A, 0x03);
	max98390_reg_write(pDevice, MAX98390_ENV_TRACK_VOUT_HEADROOM, 0x0e);
	max98390_reg_write(pDevice, MAX98390_BOOST_BYPASS1, 0x46);
	max98390_reg_write(pDevice, MAX98390_FET_SCALING3, 0x03);

	/* voltage, current slot configuration */
	max98390_reg_write(pDevice, MAX98390_PCM_CH_SRC_2,
		(imon_slot_no << 4 |
			vmon_slot_no) & 0xFF);

	if (vmon_slot_no < 8) {
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_HIZ_CTRL_A,
			1 << vmon_slot_no, 0);
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_EN_A,
			1 << vmon_slot_no,
			1 << vmon_slot_no);
	}
	else {
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_HIZ_CTRL_B,
			1 << (vmon_slot_no - 8), 0);
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_EN_B,
			1 << (vmon_slot_no - 8),
			1 << (vmon_slot_no - 8));
	}

	if (imon_slot_no < 8) {
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_HIZ_CTRL_A,
			1 << imon_slot_no, 0);
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_EN_A,
			1 << imon_slot_no,
			1 << imon_slot_no);
	}
	else {
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_HIZ_CTRL_B,
			1 << (imon_slot_no - 8), 0);
		max98390_reg_update(pDevice,
			MAX98390_PCM_TX_EN_B,
			1 << (imon_slot_no - 8),
			1 << (imon_slot_no - 8));
	}
}

void uploadDSMBin(PMAX98390_CONTEXT pDevice) {
	NTSTATUS status;

	WCHAR SystemProductName[MAX_DEVICE_REG_VAL_LENGTH];
	status = GetSmbiosName(SystemProductName);
	if (!NT_SUCCESS(status)) {
		return;
	}

	struct firmware *fw = NULL;
	status = STATUS_NOT_FOUND;
	if (wcscmp(SystemProductName, L"Nightfury") == 0) {
		status = request_firmware(&fw, L"\\SystemRoot\\system32\\DRIVERS\\dsm_param_Google_Nightfury.bin");
	}
	if (!NT_SUCCESS(status) || !fw) {
		DbgPrint("Warning: No DSM found for MAX98390!!!\n");
		return;
	}

	char* dsm_param = (char*)fw->data;
	UINT16 param_size;
	UINT16 param_start_addr;
	param_start_addr = (dsm_param[0] & 0xff) | (dsm_param[1] & 0xff) << 8;
	param_size = (dsm_param[2] & 0xff) | (dsm_param[3] & 0xff) << 8;

	if (param_size > MAX98390_DSM_PARAM_MAX_SIZE ||
		param_start_addr < MAX98390_IRQ_CTRL ||
		fw->size < param_size + MAX98390_DSM_PAYLOAD_OFFSET) {
		DbgPrint("DSM param fw is invalid.\n");
		goto dealloc;
	}


	max98390_reg_write(pDevice, MAX98390_R203A_AMP_EN, 0x80);
	dsm_param += MAX98390_DSM_PAYLOAD_OFFSET;

	for (UINT16 i = 0; i < param_size; i++) {
		max98390_reg_write(pDevice, param_start_addr + i, dsm_param[i]);
	}

	max98390_reg_write(pDevice, MAX98390_R23E1_DSP_GLOBAL_EN, 0x01);

dealloc:
	free_firmware(fw);
}

NTSTATUS
StartCodec(
	PMAX98390_CONTEXT pDevice
) {
	NTSTATUS status = STATUS_SUCCESS;
	if (!pDevice->SetUID) {
		status = STATUS_INVALID_DEVICE_STATE;
		return status;
	}

	UINT8 reg;
	status = max98390_reg_read(pDevice, MAX98390_R24FF_REV_ID, &reg);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	UINT16 vmon_slot_no, imon_slot_no;
	status = GetIntegerProperty(pDevice->FxDevice, "maxim,vmon-slot-no", &vmon_slot_no);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = GetIntegerProperty(pDevice->FxDevice, "maxim,imon-slot-no", &imon_slot_no);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	vmon_slot_no = vmon_slot_no & 0xF;
	imon_slot_no = imon_slot_no & 0xF;

	UINT16 ref_rdc_value = 0, ambient_temp_value = 0;
	GetIntegerProperty(pDevice->FxDevice, "maxim,r0_calib", &ref_rdc_value);
	GetIntegerProperty(pDevice->FxDevice, "maxim,temperature_calib", &ambient_temp_value);

	status = max98390_reg_write(pDevice, MAX98390_SOFTWARE_RESET, 0x01);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	LARGE_INTEGER Interval;
	Interval.QuadPart = -10 * 1000 * 20;
	KeDelayExecutionThread(KernelMode, false, &Interval);

	/* Amp init setting */
	max98390_init_regs(pDevice, vmon_slot_no, imon_slot_no);
	/* Update dsm bin param */
	uploadDSMBin(pDevice);

	/* Dsm Setting */
	if (ref_rdc_value) {
		max98390_reg_write(pDevice, DSM_TPROT_RECIP_RDC_ROOM_BYTE0,
			ref_rdc_value & 0x000000ff);
		max98390_reg_write(pDevice, DSM_TPROT_RECIP_RDC_ROOM_BYTE1,
			(ref_rdc_value >> 8) & 0x000000ff);
		max98390_reg_write(pDevice, DSM_TPROT_RECIP_RDC_ROOM_BYTE2,
			(ref_rdc_value >> 16) & 0x000000ff);
	}
	if (ambient_temp_value) {
		max98390_reg_write(pDevice, DSM_TPROT_ROOM_TEMPERATURE_BYTE1,
			(ambient_temp_value >> 8) & 0x000000ff);
		max98390_reg_write(pDevice, DSM_TPROT_ROOM_TEMPERATURE_BYTE0,
			(ambient_temp_value) & 0x000000ff);
	}

	max98390_reg_write(pDevice, DSM_VOL_CTRL, 0x8a);
	max98390_reg_update(pDevice,
		MAX98390_R203A_AMP_EN,
		MAX98390_AMP_EN_MASK, 1);
	max98390_reg_write(pDevice, MAX98390_R23FF_GLOBAL_EN, 0x01);

	pDevice->DevicePoweredOn = TRUE;
	return status;
}

NTSTATUS
StopCodec(
	PMAX98390_CONTEXT pDevice
) {
	NTSTATUS status;

	status = max98390_reg_write(pDevice, MAX98390_SOFTWARE_RESET, 0x01);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	pDevice->DevicePoweredOn = FALSE;
	return status;
}

VOID
CSAudioRegisterEndpoint(
	PMAX98390_CONTEXT pDevice
) {
	CsAudioArg arg;
	RtlZeroMemory(&arg, sizeof(CsAudioArg));
	arg.argSz = sizeof(CsAudioArg);
	arg.endpointType = CSAudioEndpointTypeSpeaker;
	arg.endpointRequest = CSAudioEndpointRegister;
	ExNotifyCallback(pDevice->CSAudioAPICallback, &arg, &CsAudioArg2);
}

VOID
CsAudioCallbackFunction(
	IN PMAX98390_CONTEXT  pDevice,
	CsAudioArg* arg,
	PVOID Argument2
) {
	if (!pDevice) {
		return;
	}

	if (Argument2 == &CsAudioArg2) {
		return;
	}

	pDevice->CSAudioManaged = TRUE;

	CsAudioArg localArg;
	RtlZeroMemory(&localArg, sizeof(CsAudioArg));
	RtlCopyMemory(&localArg, arg, min(arg->argSz, sizeof(CsAudioArg)));

	if (localArg.endpointType == CSAudioEndpointTypeDSP && localArg.endpointRequest == CSAudioEndpointRegister) {
		CSAudioRegisterEndpoint(pDevice);
	}
	else if (localArg.endpointType != CSAudioEndpointTypeSpeaker) {
		return;
	}

	if (localArg.endpointRequest == CSAudioEndpointStop) {
		StopCodec(pDevice);
	}
	if (localArg.endpointRequest == CSAudioEndpointStart) {
		StartCodec(pDevice);
	}
}

NTSTATUS
OnPrepareHardware(
	_In_  WDFDEVICE     FxDevice,
	_In_  WDFCMRESLIST  FxResourcesRaw,
	_In_  WDFCMRESLIST  FxResourcesTranslated
)
/*++

Routine Description:

This routine caches the SPB resource connection ID.

Arguments:

FxDevice - a handle to the framework device object
FxResourcesRaw - list of translated hardware resources that
the PnP manager has assigned to the device
FxResourcesTranslated - list of raw hardware resources that
the PnP manager has assigned to the device

Return Value:

Status

--*/
{
	PMAX98390_CONTEXT pDevice = GetDeviceContext(FxDevice);
	BOOLEAN fSpbResourceFound = FALSE;
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	UNREFERENCED_PARAMETER(FxResourcesRaw);

	//
	// Parse the peripheral's resources.
	//

	ULONG resourceCount = WdfCmResourceListGetCount(FxResourcesTranslated);

	for (ULONG i = 0; i < resourceCount; i++)
	{
		PCM_PARTIAL_RESOURCE_DESCRIPTOR pDescriptor;
		UCHAR Class;
		UCHAR Type;

		pDescriptor = WdfCmResourceListGetDescriptor(
			FxResourcesTranslated, i);

		switch (pDescriptor->Type)
		{
		case CmResourceTypeConnection:
			//
			// Look for I2C or SPI resource and save connection ID.
			//
			Class = pDescriptor->u.Connection.Class;
			Type = pDescriptor->u.Connection.Type;
			if (Class == CM_RESOURCE_CONNECTION_CLASS_SERIAL &&
				Type == CM_RESOURCE_CONNECTION_TYPE_SERIAL_I2C)
			{
				if (fSpbResourceFound == FALSE)
				{
					status = STATUS_SUCCESS;
					pDevice->I2CContext.I2cResHubId.LowPart = pDescriptor->u.Connection.IdLowPart;
					pDevice->I2CContext.I2cResHubId.HighPart = pDescriptor->u.Connection.IdHighPart;
					fSpbResourceFound = TRUE;
				}
				else
				{
				}
			}
			break;
		default:
			//
			// Ignoring all other resource types.
			//
			break;
		}
	}

	//
	// An SPB resource is required.
	//

	if (fSpbResourceFound == FALSE)
	{
		status = STATUS_NOT_FOUND;
	}

	status = SpbTargetInitialize(FxDevice, &pDevice->I2CContext);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = GetDeviceUID(FxDevice, &pDevice->UID);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	pDevice->SetUID = TRUE;

	return status;
}

NTSTATUS
OnReleaseHardware(
	_In_  WDFDEVICE     FxDevice,
	_In_  WDFCMRESLIST  FxResourcesTranslated
)
/*++

Routine Description:

Arguments:

FxDevice - a handle to the framework device object
FxResourcesTranslated - list of raw hardware resources that
the PnP manager has assigned to the device

Return Value:

Status

--*/
{
	PMAX98390_CONTEXT pDevice = GetDeviceContext(FxDevice);
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(FxResourcesTranslated);

	SpbTargetDeinitialize(FxDevice, &pDevice->I2CContext);

	if (pDevice->CSAudioAPICallbackObj) {
		ExUnregisterCallback(pDevice->CSAudioAPICallbackObj);
		pDevice->CSAudioAPICallbackObj = NULL;
	}

	if (pDevice->CSAudioAPICallback) {
		ObfDereferenceObject(pDevice->CSAudioAPICallback);
		pDevice->CSAudioAPICallback = NULL;
	}

	return status;
}

NTSTATUS
OnSelfManagedIoInit(
	_In_
	WDFDEVICE FxDevice
) {
	PMAX98390_CONTEXT pDevice = GetDeviceContext(FxDevice);
	NTSTATUS status = STATUS_SUCCESS;

	if (!pDevice->SetUID) {
		status = STATUS_INVALID_DEVICE_STATE;
		return status;
	}

	// CS Audio Callback

	UNICODE_STRING CSAudioCallbackAPI;
	RtlInitUnicodeString(&CSAudioCallbackAPI, L"\\CallBack\\CsAudioCallbackAPI");


	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(&attributes,
		&CSAudioCallbackAPI,
		OBJ_KERNEL_HANDLE | OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
		NULL,
		NULL
	);
	status = ExCreateCallback(&pDevice->CSAudioAPICallback, &attributes, TRUE, TRUE);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	pDevice->CSAudioAPICallbackObj = ExRegisterCallback(pDevice->CSAudioAPICallback,
		CsAudioCallbackFunction,
		pDevice
	);
	if (!pDevice->CSAudioAPICallbackObj) {

		return STATUS_NO_CALLBACK_ACTIVE;
	}

	CSAudioRegisterEndpoint(pDevice);

	return status;
}

NTSTATUS
OnD0Entry(
	_In_  WDFDEVICE               FxDevice,
	_In_  WDF_POWER_DEVICE_STATE  FxPreviousState
)
/*++

Routine Description:

This routine allocates objects needed by the driver.

Arguments:

FxDevice - a handle to the framework device object
FxPreviousState - previous power state

Return Value:

Status

--*/
{
	UNREFERENCED_PARAMETER(FxPreviousState);

	PMAX98390_CONTEXT pDevice = GetDeviceContext(FxDevice);
	NTSTATUS status = STATUS_SUCCESS;

	if (!pDevice->CSAudioManaged) {
		status = StartCodec(pDevice);
	}

	return status;
}

NTSTATUS
OnD0Exit(
	_In_  WDFDEVICE               FxDevice,
	_In_  WDF_POWER_DEVICE_STATE  FxPreviousState
)
/*++

Routine Description:

This routine destroys objects needed by the driver.

Arguments:

FxDevice - a handle to the framework device object
FxPreviousState - previous power state

Return Value:

Status

--*/
{
	UNREFERENCED_PARAMETER(FxPreviousState);

	PMAX98390_CONTEXT pDevice = GetDeviceContext(FxDevice);
	NTSTATUS status = STATUS_SUCCESS;

	status = StopCodec(pDevice);

	return STATUS_SUCCESS;
}

NTSTATUS
Max98390EvtDeviceAdd(
	IN WDFDRIVER       Driver,
	IN PWDFDEVICE_INIT DeviceInit
)
{
	NTSTATUS                      status = STATUS_SUCCESS;
	WDF_IO_QUEUE_CONFIG           queueConfig;
	WDF_OBJECT_ATTRIBUTES         attributes;
	WDFDEVICE                     device;
	WDFQUEUE                      queue;
	PMAX98390_CONTEXT               devContext;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	Max98390Print(DEBUG_LEVEL_INFO, DBG_PNP,
		"Max98390EvtDeviceAdd called\n");

	{
		WDF_PNPPOWER_EVENT_CALLBACKS pnpCallbacks;
		WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpCallbacks);

		pnpCallbacks.EvtDevicePrepareHardware = OnPrepareHardware;
		pnpCallbacks.EvtDeviceReleaseHardware = OnReleaseHardware;
		pnpCallbacks.EvtDeviceSelfManagedIoInit = OnSelfManagedIoInit;
		pnpCallbacks.EvtDeviceD0Entry = OnD0Entry;
		pnpCallbacks.EvtDeviceD0Exit = OnD0Exit;

		WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpCallbacks);
	}

	//
	// Setup the device context
	//

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, MAX98390_CONTEXT);

	//
	// Create a framework device object.This call will in turn create
	// a WDM device object, attach to the lower stack, and set the
	// appropriate flags and attributes.
	//

	status = WdfDeviceCreate(&DeviceInit, &attributes, &device);

	if (!NT_SUCCESS(status))
	{
		Max98390Print(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfDeviceCreate failed with status code 0x%x\n", status);

		return status;
	}

	{
		WDF_DEVICE_STATE deviceState;
		WDF_DEVICE_STATE_INIT(&deviceState);

		deviceState.NotDisableable = WdfFalse;
		WdfDeviceSetDeviceState(device, &deviceState);
	}

	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);

	queueConfig.EvtIoInternalDeviceControl = Max98390EvtInternalDeviceControl;

	status = WdfIoQueueCreate(device,
		&queueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		&queue
	);

	if (!NT_SUCCESS(status))
	{
		Max98390Print(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfIoQueueCreate failed 0x%x\n", status);

		return status;
	}

	//
	// Create manual I/O queue to take care of hid report read requests
	//

	devContext = GetDeviceContext(device);

	devContext->FxDevice = device;
	devContext->CSAudioManaged = FALSE;

	WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);

	queueConfig.PowerManaged = WdfFalse;

	status = WdfIoQueueCreate(device,
		&queueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		&devContext->ReportQueue
	);

	if (!NT_SUCCESS(status))
	{
		Max98390Print(DEBUG_LEVEL_ERROR, DBG_PNP,
			"WdfIoQueueCreate failed 0x%x\n", status);

		return status;
	}

	return status;
}

VOID
Max98390EvtInternalDeviceControl(
	IN WDFQUEUE     Queue,
	IN WDFREQUEST   Request,
	IN size_t       OutputBufferLength,
	IN size_t       InputBufferLength,
	IN ULONG        IoControlCode
)
{
	NTSTATUS            status = STATUS_SUCCESS;
	WDFDEVICE           device;
	PMAX98390_CONTEXT     devContext;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);

	device = WdfIoQueueGetDevice(Queue);
	devContext = GetDeviceContext(device);

	switch (IoControlCode)
	{
	default:
		status = STATUS_NOT_SUPPORTED;
		break;
	}

	WdfRequestComplete(Request, status);

	return;
}