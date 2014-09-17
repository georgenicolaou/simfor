/*
SIMFor - SIM Card Forensics
Copyright (C) 2014  George Nicolaou (george({at})silsensec({dot})com)

This file is part of SIMFor.

SIMFor is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

SIMFor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with SIMFor.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef SIM_KNOWN_FILE_H_
#define SIM_KNOWN_FILE_H_
#include "sim_filesystem.h"
#include "sim_wrap.h"

known_file known[] = {
	{
		{ F_MASTER_FILE, F_EF_DIR, PATH_END },
		"EFdir",
		"Contains Information about Applications present on this card.",
		NULL
	},
	{
		{ F_MASTER_FILE, F_EF_ARR, PATH_END },
		"EFarr",
		"Access Rule Referencing for files and/or records located under the MF",
		NULL
	},
	{
		{ F_MASTER_FILE, F_EF_ICCID, PATH_END },
		"EFiccid",
		"Contains the unique integrated circuit identifier of this card.",
		&decode_bcd
	},
	{
		{ F_MASTER_FILE, F_EF_ELP, PATH_END },
		"EFelp",
		"Contains the Language Preferences of this card.",
		NULL
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, PATH_END },
		"EFfp-cts",
		"Fixed-Part Cordless Telephony System",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_IFPSI, PATH_END },
		"EFifpsi",
		"Contains the International Fixed Part Subscriber Identity",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_CTS_INFO, PATH_END },
		"EFcts-info",
		"Indicates the FP-SIM phase as well as the CTS services table",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_CTS_SNDN, PATH_END },
		"EFcts-sndn",
		"Contains the CTS Service Node Dialing Number",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_CTS_CCP, PATH_END },
		"EFcts-ccp",
		"Contains parameters of required network and bearer capabilities.",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_CTS_EXT, PATH_END },
		"EFctx-ext",
		"Contains extension data of a Service Number.",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_PPLMN, PATH_END },
		"EFpplmn",
		"Contains the supervising security mode for the CTS enrolment procedure"
		" as well as the coding for Permitted PLMNs",
	},
	{
		{ F_MASTER_FILE, F_DF_FP_CTS, F_EF_AD, PATH_END },
		"EFad",
		"Contains Administrative Data used for mode of operation, type approval,"
		" cell testing, etc",
	},
	{
		{ F_MASTER_FILE, F_DF_GSM, F_EF_IMSI, PATH_END },
		"EFimsi",
		"Contains the International Mobile Subscriber Identity for the GSM"
		" application of this card.",
		decode_bcd
	},
	{
		{ F_MASTER_FILE, F_DF_GSM, F_EF_KC, PATH_END },
		"EFkc",
		"Contains the Ciphering Key and Ciphering Key sequence number.",
		NULL
	},
	{
		{ F_MASTER_FILE, F_DF_GSM, F_EF_SPN, PATH_END },
		"EFspn",
		"Contains the Service Provider Name and display requirements.",
		NULL
	},
	{
		{ F_MASTER_FILE, F_DF_GSM, F_EF_LOCI, PATH_END },
		"EFloci",
		"Contains the last Location Information",
		NULL
	},
	{
		{ F_MASTER_FILE, F_DF_TELECOM, F_EF_SMS, PATH_END },
		"EFsms",
		"Contains short messages and associated parameters",
		NULL
	},
	{
		{ F_MASTER_FILE, F_DF_TELECOM, F_EF_LND, PATH_END },
		"EFlnd",
		"Contains the list of Last Numbers (or supplementary services) Dialed",
		NULL
	}
};



#endif /* SIM_KNOWN_FILE_H_ */
