/*
 * EFI Boot Guard, WDAT additions
 *
 * Copyright (c) Siemens AG, 2017
 *
 * Authors:
 *  Claudius Heine <ch@denx.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier:     GPL-2.0
 */

#ifndef __H_EFI_WDAT__
#define __H_EFI_WDAT__

#include <efi.h>
#include <efilib.h>
#include "acpi.h"

#define EFI_ACPI_WDAT_SIGNATURE EFI_SIGNATURE_32('W', 'D', 'A', 'T')

/*
 * Watchdog Flag Definitions
 */
//
// Indicates whether the watchdog hardware is in an enabled state when the BIOS
// transfers control to the operating system boot code. If set, the watchdog
// hardware could be enabled\running or enabled\stopped. If not set, the
// watchdog hardware is disabled and can not be enabled by the OS.
//
#define EFI_ACPI_WDAT_ENABLED 0x1
//
// Indicates whether the watchdog hardware countdown is stopped in sleep states
// S1 through S5.  If the watchdog countdown is not stopped in all sleep states
// S1 through S5, this flag must not be set. The
// EFI_ACPI_WDAT_STOPPED_IN_SLEEP_STATE flag can be used by the Microsoft
// Hardware Watchdog Timer driver when going into a sleep state to decide
// whether the watchdog timer should be stopped.
//
#define EFI_ACPI_WDAT_STOPPED_IN_SLEEP_STATE 0x80


/*
 * Watchdog Actions Definitions
 */
//
// Restarts the watchdog timer’s countdown.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_RESET 0x1
//
// Returns the current countdown value of the watchdog hardware (in count
// intervals).
//
#define EFI_ACPI_WDAT_ACTION_QUERY_CURRENT_COUNTDOWN_PERIOD 0x4
//
// Returns the countdown value the watchdog hardware is configured to use when
// reset (in count intervals).
//
#define EFI_ACPI_WDAT_ACTION_QUERY_COUNTDOWN_PERIOD 0x5
//
// Sets the countdown value (in count intervals) to be used when the watchdog
// timer is reset.  This action is required if EFI_ACPI_WDAT_ACTION_RESET does
// not explicitly write a new countdown value to a register during a reset.
// Otherwise, this action is optional.
//
#define EFI_ACPI_WDAT_ACTION_SET_COUNTDOWN_PERIOD 0x6
//
// Determines if the watchdog hardware is currently in enabled\running state.
// The same result must occur when performed from both from enabled\stopped
// state and enabled\running state.  If the watchdog hardware is disabled,
// results are indeterminate.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_QUERY_RUNNING_STATE 0x8
//
// Starts the watchdog, if not already in running state.  If the watchdog
// hardware is disabled, results are indeterminate.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_SET_RUNNING_STATE 0x9
//
// Determines if the watchdog hardware is currently in enabled\stopped state.
// The sameresult must occur when performed from both the enabled\stopped state
// and enabled\running state.  If the watchdog hardware is disabled, results are
// indeterminate.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_QUERY_STOPPED_STATE 0xA
//
// Stops the watchdog, if not already in stopped state.  If the watchdog
// hardware is disabled, results are indeterminate.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_SET_STOPPED_STATE 0xB
//
// Determines if the watchdog hardware is configured to perform a reboot when
// the watchdog is fired.
//
#define EFI_ACPI_WDAT_ACTION_QUERY_ REBOOT 0x10
//
// Configures the watchdog hardware to perform a reboot  when it is fired.
//
#define EFI_ACPI_WDAT_ACTION_SET_REBOOT 0x11
//
// Determines if the watchdog hardware is configured to perform a system
// shutdown when fired.
//
#define EFI_ACPI_WDAT_ACTION_QUERY_SHUTDOWN 0x12
//
// Configures the watchdog hardware to perform a system shutdown when fired. 
//
#define EFI_ACPI_WDAT_ACTION_SET_SHUTDOWN 0x13
//
// Determines if the current boot was caused by the watchdog firing.  The boot
// status is required to be set if the watchdog fired and caused a reboot.  It
// is recommended that the Watchdog Status be set if the watchdog fired and
// causeda shutdown.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_QUERY_WATCHDOG_STATUS 0x20
//
// Sets the watchdog’s boot status to the default value.
// This action is required.
//
#define EFI_ACPI_WDAT_ACTION_SET_WATCHDOG_STATUS 0x21


/*
 * Watchdog Instruction Definitions
 */
#define EFI_ACPI_WDAT_INSTRUCTION_READ_VALUE 0x0

#define EFI_ACPI_WDAT_INSTRUCTION_READ_COUNTDOWN 0x1

#define EFI_ACPI_WDAT_INSTRUCTION_WRITE_VALUE 0x2

#define EFI_ACPI_WDAT_INSTRUCTION_WRITE_COUNTDOWN 0x3

#define EFI_ACPI_WDAT_INSTRUCTION_PRESERVE_REGISTER 0x80

typedef struct _EFI_ACPI_WDAT_INSTRUCTION {
	UINT8				Action;
	UINT8				Flags;
	UINT8				reserved[2];
	EFI_ACPI_GAS			RegisterRegion;
	UINT32				Value;
	UINT32				Mask;

} __attribute__((__packed__)) EFI_ACPI_WDAT_INSTRUCTION;

void wdat_instruction_print(const EFI_ACPI_WDAT_INSTRUCTION * wdi) {
	Print(L"Action 0x%x ", (UINTN)wdi->Action);
	Print(L"Flags 0x%x ", (UINTN)wdi->Flags);
	Print(L"reserved[2] 0x%x ", (UINTN)wdi->reserved);
	Print(L"AddressSpaceId 0x%x ", (UINTN)wdi->RegisterRegion.AddressSpaceId);
        Print(L"RegisterBitWidth 0x%x", (UINTN)wdi->RegisterRegion.RegisterBitWidth);
        Print(L"RegisterBitOffset 0x%x\n", (UINTN)wdi->RegisterRegion.RegisterBitOffset);
        Print(L"AccessSize 0x%x ", (UINTN)wdi->RegisterRegion.AccessSize);
        Print(L"Address 0x%x ", (UINTN)wdi->RegisterRegion.Address);
	Print(L"Value 0x%x ", (UINTN)wdi->Value);
	Print(L"Mask 0x%x\n", (UINTN)wdi->Mask);
}


static EFI_STATUS wdat_read(const EFI_ACPI_GAS *gas, UINT32 *value) {
	if (gas->AddressSpaceId != EFI_ACPI_GAS_ASID_SYSMEM &&
			gas->AddressSpaceId != EFI_ACPI_GAS_ASID_SYSMIO) {
		return EFI_UNSUPPORTED;
	}

	switch (gas->AccessSize) {
	case 1:
		*value = *((volatile const UINT8*)(gas->Address));
		break;
	case 2:
		*value = *((volatile const UINT16*)(gas->Address));
		break;
	case 3:
		*value = *((volatile const UINT32*)(gas->Address));
		break;
	default:
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}


static EFI_STATUS wdat_write(const EFI_ACPI_GAS *gas, const UINT32 value) {
	if (gas->AddressSpaceId != EFI_ACPI_GAS_ASID_SYSMEM &&
			gas->AddressSpaceId != EFI_ACPI_GAS_ASID_SYSMIO) {
		return EFI_UNSUPPORTED;
	}

	switch (gas->AccessSize) {
	case 1:
		*((volatile UINT8*)(gas->Address)) = (UINT8)value;
		break;
	case 2:
		*((volatile UINT16*)(gas->Address)) = (UINT16)value;
		break;
	case 3:
		*((volatile UINT32*)(gas->Address)) = (UINT32)value;
		break;
	default:
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}


typedef struct _EFI_ACPI_WDAT_HEADER {

	EFI_ACPI_SDT_HEADER		SDTHeader;

	UINT32				WDATHeaderLength;
	UINT16				PCISegment;
	UINT8				PCIBusNumber;
	UINT8				PCIDeviceNumber;
	UINT8				PCIFunctionNumber;
	UINT8				reserved1[3];
	UINT32				TimerPeriod;
	UINT32				MaximumCount;
	UINT32				MinimumCount;
	UINT8				WatchdogFlags;
	UINT8				reserved2[3];
	UINT32				NumberWDInstructionEntries;
	EFI_ACPI_WDAT_INSTRUCTION	ActionTable[0];
} __attribute__((__packed__)) EFI_ACPI_WDAT_HEADER;

void wdat_print(const EFI_ACPI_WDAT_HEADER *wdat) {
	const EFI_ACPI_WDAT_INSTRUCTION *wdi = wdat->ActionTable;
	const UINTN instructionEntries = (wdat->SDTHeader.Length -
			sizeof(EFI_ACPI_WDAT_HEADER)) /
		sizeof(EFI_ACPI_WDAT_INSTRUCTION);

	acpi_sdt_print(&(wdat->SDTHeader));
	Print(L"WDATHeaderLength 0x%x ", (UINTN)wdat->WDATHeaderLength);
	Print(L"PCISegment 0x%x ", (UINTN)wdat->PCISegment);
	Print(L"PCIBusNumber 0x%x ", (UINTN)wdat->PCIBusNumber);
	Print(L"PCIDeviceNumber 0x%x ", (UINTN)wdat->PCIDeviceNumber);
	Print(L"PCIFunctionNumber 0x%x ", (UINTN)wdat->PCIFunctionNumber);
	Print(L"reserved1[3] 0x%x\n", (UINTN)wdat->reserved1);
	Print(L"TimerPeriod 0x%x ", (UINTN)wdat->TimerPeriod);
	Print(L"MaximumCount 0x%x ", (UINTN)wdat->MaximumCount);
	Print(L"MinimumCount 0x%x ", (UINTN)wdat->MinimumCount);
	Print(L"WatchdogFlags 0x%x ", (UINTN)wdat->WatchdogFlags);
	Print(L"reserved2[3] 0x%x\n", (UINTN)wdat->reserved2);
	Print(L"NumberWDInstructionEntries 0x%x\n", (UINTN)wdat->NumberWDInstructionEntries);

	for (UINT32 i = 0; i < instructionEntries; i++, wdi++) {
		wdat_instruction_print(wdi);
	}
}


EFI_STATUS wdat_run_action(const EFI_ACPI_WDAT_HEADER *wdat,
		const UINT8 action, const UINT32 param, UINT32 *retval) {

	const EFI_ACPI_WDAT_INSTRUCTION *wdi = wdat->ActionTable;

	/* 
	 * TODO:
	 * Investigate why wdat->NumberWDInstructionEntries == 8 but
	 * there is only space in the table for 5 entries.
	 * (The entries >5 look fishy, so using the calculated 5 entries.)
	 */
	const UINTN instructionEntries = (wdat->SDTHeader.Length -
			sizeof(EFI_ACPI_WDAT_HEADER)) /
		sizeof(EFI_ACPI_WDAT_INSTRUCTION);
	for (UINT32 i = 0; i < instructionEntries; i++, wdi++) {
		const EFI_ACPI_GAS * const gas = &(wdi->RegisterRegion);
		UINT32 flags, value, mask, x, y;
		BOOLEAN preserve;
		EFI_STATUS ret;
		
		// Skip instructions not belonging to the choosen action:
		if (wdi->Action != action) {
			continue;
		}

		preserve = wdi->Flags &
			EFI_ACPI_WDAT_INSTRUCTION_PRESERVE_REGISTER;
		flags = wdi->Flags &
			~EFI_ACPI_WDAT_INSTRUCTION_PRESERVE_REGISTER;
		value = wdi->Value;
		mask = wdi->Mask;

		switch (flags) {
		case EFI_ACPI_WDAT_INSTRUCTION_READ_VALUE:
			ret = wdat_read(gas, &x);
			if (ret) {
				return ret;
			}
			x >>= gas->RegisterBitOffset;
			x &= mask;
			if (retval)
				*retval = (x == value);
			break;

		case EFI_ACPI_WDAT_INSTRUCTION_READ_COUNTDOWN:
			ret = wdat_read(gas, &x);
			if (ret) {
				return ret;
			}
			x >>= gas->RegisterBitOffset;
			x &= mask;
			if (retval)
				*retval = x;
			break;

		case EFI_ACPI_WDAT_INSTRUCTION_WRITE_VALUE:
			x = value & mask;
			x <<= gas->RegisterBitOffset;
			if (preserve) {
				ret = wdat_read(gas, &y);
				if (ret) {
					return ret;
				}
				y = y & ~(mask << gas->RegisterBitOffset);
				x |= y;
			}
			ret = wdat_write(gas, x);
			if (ret) {
				return ret;
			}
			break;

		case EFI_ACPI_WDAT_INSTRUCTION_WRITE_COUNTDOWN:
			x = param;
			x &= mask;
			x <<= gas->RegisterBitOffset;
			if (preserve) {
				ret = wdat_read(gas, &y);
				if (ret) {
					return ret;
				}
				y = y & ~(mask << gas->RegisterBitOffset);
				x |= y;
			}
			ret = wdat_write(gas, x);
			if (ret) {
				return ret;
			}
			break;

		default:
			Print(L"WDAT instruction unsupported\n");
			wdat_instruction_print(wdi);
			return EFI_UNSUPPORTED;
		}
	}

	return EFI_SUCCESS;
}


EFI_STATUS wdat_find(const EFI_ACPI_WDAT_HEADER **wdat) {
	const EFI_ACPI_RSDP_1_TABLE *rsdp_table = NULL;
	const EFI_ACPI_RSDT_HEADER *rsdt = NULL;
	const EFI_ACPI_XSDT_HEADER *xsdt = NULL;

	EFI_STATUS status;

	status = acpi_rsdp_find(&rsdp_table);
	if (status != EFI_SUCCESS) {
		return status;
	}

	status = acpi_rsdp_get_rsdt_xsdt(rsdp_table, &rsdt, &xsdt);
	if (status != EFI_SUCCESS) {
		return status;
	}

	if (xsdt != NULL) {
		status = acpi_xsdt_sdt_find(xsdt,
			(const EFI_ACPI_SDT_HEADER**)(wdat),
			NULL, EFI_ACPI_WDAT_SIGNATURE);

		if (status != EFI_SUCCESS) {
			return status;
		}


		if (wdat != NULL) {
			return EFI_SUCCESS;
		}
	}

	if (rsdt != NULL) {
		status = acpi_rsdt_sdt_find(rsdt,
			(const EFI_ACPI_SDT_HEADER**)(wdat),
			NULL, EFI_ACPI_WDAT_SIGNATURE);

		if (status != EFI_SUCCESS) {
			return status;
		}

		if (wdat != NULL) {
			return EFI_SUCCESS;
		}
	}

	return EFI_SUCCESS;
}

#endif // __H_EFI_WDAT__
