/*
 * EFI Boot Guard, WDAT watchdog support
 *
 * Copyright (c) Siemens AG, 2017
 *
 * Authors:
 *  Claudius Heine <ch@denx.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier:	GPL-2.0
 */

#include <efi.h>
#include <efilib.h>
#include <efiapi.h>
#include <pci/header.h>
#include <efi/acpi.h>
#include <efi/wdat.h>


static EFI_STATUS __attribute__((constructor))
init(__attribute__((unused)) EFI_PCI_IO *_unused0,
     __attribute__((unused)) UINT16 _unused1,
     __attribute__((unused)) UINT16 _unused2,
     UINTN timeout)
{
	EFI_STATUS status = 0;
	const EFI_ACPI_WDAT_HEADER *wdat;

	Print(L"WDAT init started\n");

	status = wdat_find(&wdat);
	if (EFI_ERROR(status)) {
		Print(L"WDAT entry not found\n");
		while (1);
		return status;
	}

	Print(L"WDAT set reboot action\n");
	status = wdat_run_action(wdat,
			EFI_ACPI_WDAT_ACTION_SET_REBOOT,
			0, NULL);
	if (EFI_ERROR(status)) {
		Print(L"WDAT could not set reboot action\n");
		while (1);
		return status;
	}

	Print(L"WDAT set countdown period\n");
	status = wdat_run_action(wdat,
			EFI_ACPI_WDAT_ACTION_SET_COUNTDOWN_PERIOD,
			timeout, NULL);
	if (EFI_ERROR(status)) {
		Print(L"WDAT could not set countdown period\n");
		while (1);
		return status;
	}

	Print(L"WDAT set running state\n");
	status = wdat_run_action(wdat,
			EFI_ACPI_WDAT_ACTION_SET_RUNNING_STATE,
			0, NULL);
	if (EFI_ERROR(status)) {
		Print(L"WDAT could not set running state\n");
		while (1);
		return status;
	}

	Print(L"WDAT reset\n");
	status = wdat_run_action(wdat,
			EFI_ACPI_WDAT_ACTION_RESET,
			0, NULL);
	if (EFI_ERROR(status)) {
		Print(L"WDAT could not reset\n");
		while (1);
		return status;
	}

	Print(L"WDT should be initialized, enter busyloop\n");
	while (1);

	return status;
}
