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
#ifndef SIM_FILESYSTEM_H_
#define SIM_FILESYSTEM_H_
#include "include.h"

#define F_MASTER_FILE 0x3F00
/*
 * F_MASTER_FILE Children--------------------------
 */
#define F_EF_DIR	0x2F00
#define F_EF_ELP	0x2F05 //Extended language pref
#define F_EF_ARR	0x2F06
#define F_EF_ICCID	0x2FE2
#define F_DF_IS_41	0x7F22
#define F_DF_FP_CTS	0x7F23
/*
 * F_DF_FP-CTS Contents -------------------------------------------------------
 */
#define F_EF_IFPSI		0x6F07
#define F_EF_CTS_INFO	0x6F38
#define F_EF_CTS_SNDN	0x6F41
#define F_EF_CTS_CCP	0x6F3D
#define F_EF_CTS_EXT	0x6F4A
#define F_EF_PPLMN		0x6F7B
#define F_EF_AD			0x6FAD
//#define F_EF_ARPK 	0x4F42
#define F_DF_TELECOM 0x7F10
/*
 * F_DF_TELECOM Children ---------------
 */
#define F_EF_ARR_1		0x6F06
#define F_EF_ADN		0x6F3A
#define F_EF_FDN		0x6F3B
#define F_EF_SMS		0x6F3C
#define F_EF_ECCP		0x6F4F
#define F_EF_MSISDN		0x6F40
#define F_EF_SMSP		0x6F42
#define F_EF_SMSS		0x6F43
#define F_EF_LND		0x6F44
#define F_EF_SMSR		0x6F47
#define F_EF_SDN		0x6F49
#define F_EF_EXT1		0x6F4A
#define F_EF_EXT2		0x6F4B
#define F_EF_EXT3		0x6F4C
#define F_EF_BDN		0x6F4D
#define F_EF_EXT4		0x6F4E
#define F_EF_SUME		0x6F54
#define F_DF_GRAPHICS	0x5F50
/*
 * F_DF_GRAPHICS CHILDREN -------------
 */
#define F_EF_IMG		0x4F20
/*
 * F_DF_GRAPHICS CHILDREN END ---------
 */
#define F_DF_PHONEBOOK	0x5F3A
/*
 * F_DF_PHONEBOOK CHILDREN
 */
#define F_EF_PBR		0x4F30
//#define F_EF_IAP		0x4F??
//#define F_EF_ADN		0x4F??

/*
 * F_DF_TELECOM Children END -----------------
 */
#define F_DF_GSM 0x7F20
/*
 * F_DF_GSM Children ----------------------------------------------------------
 */
#define F_EF_LP 0x6F05
#define F_EF_IMSI 0x6F07
#define F_EF_KC	0x6F20
#define F_EF_SPN 0x6F46
#define F_EF_LOCI 0x6F7E
/*
 * F_DF_GSM Children End ------------------------------------------------------
 */

/*
typedef enum {
	DONT = 0,
	CODING_RAW,
	CODING_BCD, //Byte Coded Decimal
	CODING_FIXEDRECORD,
	CODING_ATE, //Application Template Entry
	CODING_IMSI, // Similar to BCD but with 1st byte denoting length
	CODING_CIPHERING,
	CODING_SPN,
	CODING_LOCI,
	CODING_SMS,
	CODING_LND
} file_coding;
*/

#define MAX_PATH 10
#define PATH_END 0xFFFF
typedef struct _known_file {
	uint16_t path[MAX_PATH];
	char * name;
	char * descr;
	char * (*coding)( struct _known_file *, uint8_t *, int );
	union {
		int record_len;
	} coding_info;
} known_file;
#endif /* SIM_FILESYSTEM_H_ */
