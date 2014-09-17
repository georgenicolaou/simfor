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
#ifndef APDU_PROTO_H_
#define APDU_PROTO_H_

#include <stdint.h>
/*
 * The following definitions were based on STMicroelectronics simcard.h file
 * ----------------------------------------------------------------------------
 */



/* Exported constants --------------------------------------------------------*/
#define T0_PROTOCOL        0x00  /* T0 protocol */
#define DIRECT             0x3B  /* Direct bit convention */
#define INDIRECT           0x3F  /* Indirect bit convention */
#define SETUP_LENGTH       20
#define HIST_LENGTH        20
#define LC_MAX             20
#define SC_RECEIVE_TIMEOUT 0x8000  /* Direction to reader */

/* SC Tree Structure -----------------------------------------------------------
                              MasterFile
                           ________|___________
                          |        |           |
                        System   UserData     Note
------------------------------------------------------------------------------*/

/* SC APDU Command: Operation Code -------------------------------------------*/
#define SC_CLA_GSM11       0xA0

/*------------------------ Data Area Management Commands ---------------------*/
#define SC_SELECT_FILE     0xA4
#define SC_GET_RESPONCE    0xC0
#define SC_STATUS          0xF2
#define SC_UPDATE_BINARY   0xD6
#define SC_READ_BINARY     0xB0
#define SC_WRITE_BINARY    0xD0
#define SC_UPDATE_RECORD   0xDC
#define SC_READ_RECORD     0xB2

/*-------------------------- Administrative Commands -------------------------*/
#define SC_CREATE_FILE     0xE0

/*-------------------------- Safety Management Commands ----------------------*/
#define SC_VERIFY          0x20
#define SC_CHANGE          0x24
#define SC_DISABLE         0x26
#define SC_ENABLE          0x28
#define SC_UNBLOCK         0x2C
#define SC_EXTERNAL_AUTH   0x82
#define SC_GET_CHALLENGE   0x84

/*-------------------------- Answer to reset Commands ------------------------*/
#define SC_GET_A2R         0x00

/* SC STATUS: Status Code ----------------------------------------------------*/
#define SC_EF_SELECTED     0x9F
#define SC_DF_SELECTED     0x9F
#define SC_OP_TERMINATED   0x9000
#define SC_RESET			0x00 //RESET reply
#define SC_ACK_NULL			0x60
#define SC_ACK_OK			0x90

/* Smartcard Voltage */
#define SC_VOLTAGE_5V      0
#define SC_VOLTAGE_3V      1

/* Exported types ------------------------------------------------------------*/
typedef enum
{
  SC_POWER_ON = 0x00,
  SC_RESET_LOW = 0x01,
  SC_RESET_HIGH = 0x02,
  SC_ACTIVE = 0x03,
  SC_ACTIVE_ON_T0 = 0x04,
  SC_POWER_OFF = 0x05
} SC_State;

/* ATR structure - Answer To Reset -------------------------------------------*/
typedef struct
{
  uint8_t TS;               /* Bit Convention */
  uint8_t T0;               /* High nibble = Number of setup byte; low nibble = Number of historical byte */
  uint8_t T[SETUP_LENGTH];  /* Setup array */
  uint8_t H[HIST_LENGTH];   /* Historical array */
  uint8_t Tlength;          /* Setup array dimension */
  uint8_t Hlength;          /* Historical array dimension */
} SC_ATR;

/* APDU-Header command structure ---------------------------------------------*/
typedef struct
{
  uint8_t CLA;  /* Command class */
  uint8_t INS;  /* Operation code */
  uint8_t P1;   /* Selection Mode */
  uint8_t P2;   /* Selection Option */
} SC_Header;

/* APDU-Body command structure -----------------------------------------------*/
typedef struct
{
  uint8_t LC;           /* Data field length */
  uint8_t Data[LC_MAX];  /* Command parameters */
  uint8_t LE;           /* Expected length of data to be returned */
} SC_Body;

/* APDU Command structure ----------------------------------------------------*/
typedef struct
{
  SC_Header Header;
  SC_Body Body;
} SC_APDU_Commands;

/* SC response structure -----------------------------------------------------*/
typedef struct
{
  uint8_t * Data;  /* Data returned from the card, standard says 20 chars max*/
  uint8_t SW1;          /* Command Processing status */
  uint8_t SW2;          /* Command Processing qualification */
} SC_APDU_Response;

uint8_t DefaultData[LC_MAX];
#define RESP_DEFAULT( resp ) resp.Data = (uint8_t *)&DefaultData;
#define RESP_PTR_DEFAULT( resp ) resp->Data = (uint8_t *)&DefaultData;
/* Exported macro ------------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
/* APPLICATION LAYER ---------------------------------------------------------*/
/*
void SC_Handler(SC_State *SCState, SC_APDU_Commands *SC_APDU, SC_APDU_Responce *SC_Response);
void SC_PowerCmd(FunctionalState NewState);
void SC_Reset(BitAction ResetState);
void SC_IOConfig(void);
void SC_ParityErrorHandler(void);
void SC_PTSConfig(void);
*/


//Response parameter locations for MF or DF: (see ETS 300 977)
/*
 * Response parameter locations for MF or DF when executing the SELECT or
 * STATUS command (see ETS 300 977).
 * Note that the endianess of mem_free and file_id needs to be swaped
 */
typedef struct {
	uint8_t RFU[2];
	uint16_t mem_free;
	uint16_t file_id;
	uint8_t type;
	uint8_t RFU1[5];
	uint8_t data_length;
	uint8_t characteristics;
	uint8_t ndirs;//number of DF directories directly under this DF
	uint8_t nfiles; //number of EF files directly under this DF
	uint8_t ncodes; //number of CHVs, unblock CHVs and admin codes
	uint8_t RFU2;
	uint8_t chv1_status;
	uint8_t uchv1_status; //unblock
	uint8_t chv2_status;
	uint8_t uchv2_status;
	uint8_t RFU3;
	uint8_t administrative[11]; //Reserved for the administrative management
} DF_GSM_Response;

#define SWAP_ENDIANESS_16( val ) ( ( (val & 0xFF00) >> 8 ) | \
									( val & 0x00FF ) << 8 )
//Checking highest bit (bit8) if its set or not
#define CHV1_DISABLED( characteristics ) ( ( characteristics & 0x80 ) >> 7 )

//Get lowest 4 bits
#define GET_CHV_REMAINING( chv_status ) (  chv_status & 0x0F )
//Get highest bit (bit8) which: 1 - secret code initialized, 0 - not initialized
#define GET_CHV_INITIALIZED( chv_status ) ( ( chv_status & 0x80 ) >> 7 )


/* For running the auth algoirthm, or the ENVELOPE command for SIM Data Download,
 * a frequency is required of at least 13/8 MHz if b2 = 0 and 13/4 MHz if b2=1
 */
#define AUTH_FREQ( characteristics ) ( ( characteristics & 0x02 ) >> 1 )

//Get conditions for stopping the clock and the results
#define CLOCK_STOP( characteristics ) ( ( characteristics & 0x0D ) )
#define ALLOWED_NOPREF 		0x01
#define ALLOWED_HIGHPREF 	0x05
#define ALLOWED_LOWPREF 	0x09
#define NOT_ALLOWED 		0x00
#define ONLY_HIGH 			0x04
#define ONLY_LOW 			0x08

typedef struct {
	uint8_t RFU[2];
	uint16_t file_size;
	uint16_t file_id;
	uint8_t type;
	/*
	 * For transparent and linear fixed EFs this byte is RFU.
	 * For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that the
	 * INCREASE command is allowed on the selected cyclic file.
	 */
	uint8_t increase_allowed;
	/*
	 * Each byte is split into two 4bit values that range from 0-14 or 1-15
	 * authorization levels. 0 = PIN1, 1 = PIN2, 3-14 = ADM/Telecom, 15 = Never.
	 * High = high 4 bits
	 * Low = low 4 bits
	 * access[0] - High = READ and SEEK, Low = UPDATE
	 * access[1] - High = INCREASE, Low = Reserved
	 * access[2] - High = REHABILITATE, Low = INVALIDATE
	 */
	uint8_t access[3];
	uint8_t status;
	uint8_t data_length; //length of what is following
	uint8_t ef_structure; //transparent, linear or cyclic?
	uint8_t length_of_record;
	uint8_t reserved[];
} EF_GSM_Response;

//Used to get access levels
#define GET_HIGH4( val ) ( ( val & 0xF0 ) >> 4 )
#define GET_LOW4( val ) ( val & 0x0F )

#define IS_INVALIDATED( status ) ( ( status & 0x1 ) == 0 )
#define READABLE_IF_INVALIDATED( status ) ( status & 0x04 )
#define INCREASE_ALLOWED( status ) ( status & 0x40 )
#define EF_TRANSPARENT 0x00
#define EF_LINEAR 0x01
#define EF_CYCLIC 0x03

//File type field (the following apply for DF and EF)
#define T_RFU 0x00
#define T_MF 0x01
#define T_DF 0x02
#define T_EF 0x04


/*
 * SC_READ_RECORD - Parameters -----------------------------------------------
 */

//Mode (P2)
#define GET_NEXT_RECORD 0x02
#define GET_PREV_RECORD 0x03
#define GET_SPECIFIED_RECORD 0x04


/*
 * SIM Specific structures (contents of EF Files) -----------------------------
 */

//Contents of EFdir file
//                         GSM         P I N 2
//EG 61 0F 4F 07 A0000000090001 50 04 50494E32FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
typedef struct {
	uint8_t tag; //Must always be 61 for application template
	uint8_t length; //03-7F
	uint8_t id_tag; //4F
	uint8_t aid_len; //01-10
	uint8_t * aid_val;
} efdir_head;

typedef struct {
	uint8_t label_tag; //50
	uint8_t label_len;
	uint8_t label_value[]; //Operator name usually
} efdir_applabel;

typedef struct {
	efdir_head  * head;
	efdir_applabel * label;
} efdir_tlv_record;

typedef struct {
	uint8_t tag; //Must always be 61 for application template
	uint8_t length; //03-7F
	uint8_t id_tag; //4F
	uint8_t aid_len; //01-10
	uint8_t * aid_val;

} efdir_record;

#endif /* APDU_PROTO_H_*/
