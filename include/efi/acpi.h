/*
 * EFI Boot Guard, ACPI additions
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

#ifndef __H_EFI_ACPI__
#define __H_EFI_ACPI__

#include <efi.h>
#include <efilib.h>

void hexDump (CHAR16 *desc, const void *addr, UINTN len) {
    UINTN i;
    CHAR16 buff[17];
    const CHAR8 *pc = (const CHAR8*)addr;

    // Output description if given.
    if (desc != NULL)
        Print(L"%s:\n", desc);

    if (len == 0) {
        Print(L"  ZERO LENGTH\n");
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                Print(L"  %s\n", buff);

            // Output the offset.
            Print(L"  %04x ", i);
        }

        // Now the hex code for the specific character.
        Print(L" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        Print(L"   ");
        i++;
    }

    // And print the final ASCII bit.
    Print(L"  %s\n", buff);
}


#define EFI_ACPI_RSDP_SIGNATURE EFI_SIGNATURE_64('R', 'S', 'D', ' ', \
						 'P', 'T', 'R', ' ')
#define EFI_ACPI_RSDT_SIGNATURE EFI_SIGNATURE_32('R', 'S', 'D', 'T')
#define EFI_ACPI_XSDT_SIGNATURE EFI_SIGNATURE_32('X', 'S', 'D', 'T')

typedef struct _EFI_ACPI_SDT_HEADER {
        UINT32                          Signature;
        UINT32                          Length;
        UINT8                           Revision;
        UINT8                           Checksum;
        UINT8                           OEMID[6];
        UINT8                           OEMTableID[8];
        UINT32                          OEMRevision;
        UINT32                          CreatorID;
        UINT32                          CreatorRevision;
} __attribute__((__packed__)) EFI_ACPI_SDT_HEADER;

void acpi_sdt_print(const EFI_ACPI_SDT_HEADER *sdt) {
        Print(L"Signature 0x%x ", (UINTN)sdt->Signature);
        Print(L"Length %u ", (UINTN)sdt->Length);
        Print(L"Revision 0x%x ", (UINTN)sdt->Revision);
        Print(L"Checksum 0x%x\n", (UINTN)sdt->Checksum);
        Print(L"OEMID[6] 0x%x ", (UINTN)sdt->OEMID);
        Print(L"OEMTableID[8] 0x%x ", (UINTN)sdt->OEMTableID);
        Print(L"OEMRevision 0x%x ", (UINTN)sdt->OEMRevision);
        Print(L"CreatorID 0x%x ", (UINTN)sdt->CreatorID);
        Print(L"CreatorRevision 0x%x\n", (UINTN)sdt->CreatorRevision);
}

typedef struct _EFI_ACPI_RSDT_HEADER {
        EFI_ACPI_SDT_HEADER             SDTHeader;

        // Number of entries:
        //      (SDTHeader.Length - sizeof(SDTHeader)) / 4
        UINT32                          entry[0];
} __attribute__((__packed__)) EFI_ACPI_RSDT_HEADER;

typedef struct _EFI_ACPI_XSDT_HEADER {
        EFI_ACPI_SDT_HEADER             SDTHeader;

        // Number of entries:
        //      (SDTHeader.Length - sizeof(SDTHeader)) / 8
        UINT64                          entry[0];
} __attribute__((__packed__)) EFI_ACPI_XSDT_HEADER;


typedef struct _EFI_ACPI_RSDP_1_TABLE {
        UINT64                          Signature;
        UINT8                           Checksum;
        UINT8                           OEMID[6];
        UINT8                           Revision;
        UINT32                          RsdtAddress;
} __attribute__((__packed__)) EFI_ACPI_RSDP_1_TABLE;

typedef struct _EFI_ACPI_RSDP_2_TABLE {
        EFI_ACPI_RSDP_1_TABLE           RSDP1Table;

        UINT32                          Length;
        UINT64                          XsdtAddress;
        UINT8                           ExtendedChecksum;
        UINT8                           reserved[3];
} __attribute__((__packed__)) EFI_ACPI_RSDP_2_TABLE;


EFI_STATUS acpi_rsdp_find(const EFI_ACPI_RSDP_1_TABLE **rsdp_table) {
	/*
	 * Per specification, search for ACPI 2.0 table first and then, if that
	 * was unsuccessful, search for ACPI 1.0 table. (ACPI 6.3: 5.2.5.2)
	 */
	static const EFI_GUID acpi_table_guid[] = {
		ACPI_20_TABLE_GUID,
		ACPI_TABLE_GUID,
	};
	const EFI_GUID *acpi_guid;

	acpi_guid = acpi_table_guid;
	for (UINTN j = 0; j < 2; j++, acpi_guid++) {
		const EFI_CONFIGURATION_TABLE *ect;

		ect = gST->ConfigurationTable;
		for (UINTN i = 0;
			i < gST->NumberOfTableEntries;
			i++, ect++) {

			const EFI_ACPI_RSDP_1_TABLE *found;

			if (CompareGuid(&(ect->VendorGuid), acpi_guid) != 0) {
				continue;
			}

			found = (EFI_ACPI_RSDP_1_TABLE*)(ect->VendorTable);
			if (found->Signature != EFI_ACPI_RSDP_SIGNATURE) {
				Print(L"ACPI RSDP found but invalid signature:\n");
				continue;
			}

			(*rsdp_table) = found;
			Print(L"ACPI RSDP found\n");
			return EFI_SUCCESS;
		}
	}

	return EFI_NOT_FOUND;
}

static inline EFI_STATUS _verify(const UINT8 *ptr, const UINTN length) {
	UINT8 cksum = 0;

	for (UINTN i = 0; i < length; i++, ptr++) {
		cksum += *ptr;
	}

	return cksum == 0 ? EFI_SUCCESS : EFI_CRC_ERROR;
}

EFI_STATUS acpi_rsdp_verify(const EFI_ACPI_RSDP_1_TABLE *rsdp_table) {
	const UINT8 revision = rsdp_table->Revision;
	const UINT8 *ptr = (const UINT8*)(rsdp_table);

	UINTN length = sizeof(EFI_ACPI_RSDP_2_TABLE);

	if (revision < 2) {
		length = sizeof(EFI_ACPI_RSDP_1_TABLE);
	}

	return _verify(ptr, length);
}

EFI_STATUS acpi_sdt_verify(const EFI_ACPI_SDT_HEADER *sdt) {
	const UINT8 *ptr = (const UINT8*)(sdt);
	const UINTN length = sdt->Length;

	return _verify(ptr, length);
}

#define define_acpi_sdt_find(func_name, base_std_type,				\
			     entry_size, log_name)				\
	EFI_STATUS func_name (const base_std_type *sdt,				\
			      const EFI_ACPI_SDT_HEADER **sdt_header,		\
			      UINTN *entry_index,				\
			      const UINT32 signature) {				\
	const UINTN entry_count = (sdt->SDTHeader.Length -			\
				   sizeof(EFI_ACPI_SDT_HEADER)) / entry_size;	\
	const UINTN start_index = (entry_index == NULL) ? 0 : (*entry_index);	\
										\
	Print(log_name L": searching for 0x%x\n", signature);			\
										\
	for (UINTN i = start_index; i < entry_count; i++) {			\
		const EFI_ACPI_SDT_HEADER *inner_sdt =				\
			(EFI_ACPI_SDT_HEADER *)((UINTN)(sdt->entry[i]));	\
		EFI_STATUS status;						\
										\
		if (inner_sdt->Signature != signature) {			\
			continue;						\
		}								\
										\
		status = acpi_sdt_verify(inner_sdt);				\
		if (status != EFI_SUCCESS) {					\
			Print(log_name L": found but crc failed\n");		\
			acpi_sdt_print(inner_sdt);                              \
			return status;						\
		}								\
										\
		if (entry_index != NULL) {					\
			(*entry_index) = i;					\
		}								\
										\
		(*sdt_header) = inner_sdt;					\
		return EFI_SUCCESS;						\
	}									\
	return EFI_SUCCESS;							\
}										\

define_acpi_sdt_find(acpi_xsdt_sdt_find, EFI_ACPI_XSDT_HEADER,
		     8, L"ACPI XSDT SDT find")
define_acpi_sdt_find(acpi_rsdt_sdt_find, EFI_ACPI_RSDT_HEADER,
		     4, L"ACPI RSDT SDT find")

EFI_STATUS acpi_rsdp_get_rsdt_xsdt(const EFI_ACPI_RSDP_1_TABLE *rsdp_table,
				   const EFI_ACPI_RSDT_HEADER **rsdt,
				   const EFI_ACPI_XSDT_HEADER **xsdt) {
	const UINT8 revision = rsdp_table->Revision;
	EFI_STATUS status;

	*rsdt = (EFI_ACPI_RSDT_HEADER *)((UINTN)(rsdp_table->RsdtAddress));

	status = acpi_sdt_verify(&((*rsdt)->SDTHeader));
	if (status != EFI_SUCCESS) {
		Print(L"ACPI RSDT: crc failed\n");
		return status;
	}

	if (revision > 2) {
		const EFI_ACPI_RSDP_2_TABLE *xsdp_table;
		xsdp_table = (EFI_ACPI_RSDP_2_TABLE*)(rsdp_table);
		*xsdt = (EFI_ACPI_XSDT_HEADER *)
			((UINTN)(xsdp_table->XsdtAddress));

		status = acpi_sdt_verify(&((*xsdt)->SDTHeader));
		if (status != EFI_SUCCESS) {
			Print(L"ACPI XSDT: crc failed\n");
			return status;
		}
	}

	return EFI_SUCCESS;
}

// AddressSpaceId flags for Generic Address Structure (GAS)
#define EFI_ACPI_GAS_ASID_SYSMEM		0x00
#define EFI_ACPI_GAS_ASID_SYSMIO		0x01
#define EFI_ACPI_GAS_ASID_PCICFG		0x02
#define EFI_ACPI_GAS_ASID_EC			0x03
#define EFI_ACPI_GAS_ASID_SMBUS			0x04
#define EFI_ACPI_GAS_ASID_SYSCMOS		0x05
#define EFI_ACPI_GAS_ASID_PCIBAR		0x06
#define EFI_ACPI_GAS_ASID_IPMI			0x07
#define EFI_ACPI_GAS_ASID_GPIO			0x08
#define EFI_ACPI_GAS_ASID_GSB			0x09
#define EFI_ACPI_GAS_ASID_PCC			0x0a
#define EFI_ACPI_GAS_ASID_FFH			0x7f

// AddressSize flags for Generic Address Structure (GAS)
#define EFI_ACPI_GAS_ASIZE_BYTE			0x01
#define EFI_ACPI_GAS_ASIZE_WORD			0x02
#define EFI_ACPI_GAS_ASIZE_DWORD		0x03
#define EFI_ACPI_GAS_ASIZE_QWORD		0x04

typedef struct _EFI_ACPI_GAS {
        UINT8                           AddressSpaceId;
        UINT8                           RegisterBitWidth;
        UINT8                           RegisterBitOffset;
        UINT8                           AccessSize;
        UINT64                          Address;
} __attribute__((__packed__)) EFI_ACPI_GAS;

#endif // __H_EFI_ACPI__
