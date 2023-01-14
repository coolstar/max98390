#pragma once
#include <wdm.h>

struct firmware {
    UINT8* data;
    size_t size;
};

NTSTATUS request_firmware(struct firmware** img, PCWSTR path);
void free_firmware(struct firmware* fw);