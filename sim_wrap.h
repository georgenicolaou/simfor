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
#ifndef SIM_WRAP_H_
#define SIM_WRAP_H_
#include <stdint.h>
#include "serial_com.h"
#include "apdu_proto.h"
#include "sim_filesystem.h"
#include "node.h"

/*
 * Dummy storage for CHVs, their unlocks and tries left. 0 = pin1 1 = pin2
 * see below for definitions
 */
typedef struct sim_auth {
	uint8_t chv[2]; //1 = initialized, 0 = not initialized
	uint8_t chv_left[2];
	uint8_t uchv[2]; // unlock chv
	uint8_t uchv_left[2]; // unlock chv
	uint8_t chv1_disabled;
	uint8_t session_auth[14]; //14 authentication levels
} SIM_Auth;

//.chv[] and .chv_left[]
#define PIN1 0
#define PIN2 1
//.uchv[] and .uchv_left[]
#define PUK1 0
#define PUK2 1

typedef struct sim_context {
	SIM_Auth auth;
	int ( * write)( SC_APDU_Commands * , SC_APDU_Response * );
} SIM_Context;

/* Return values -------------------------------------------------------------*/
#define SUCCESS 1
#define FAILURE 0
#define BLOCKED 2
#define ERROR -1

/* check_pin Return values ---------------------------------------------------*/
#define PIN_LOCKED 0
#define PIN_UNLOCKED 1

int goto_file( int sim_file );
int check_pin( SIM_Context * ctx );
/*
 * Go through the process of verifying the CHV (PIN)
 * Parameters:
 * 	- ctx, The context structure
 * 	- chv_number, The CHV number, 0 - for PIN1, 1 for PIN2 if you wish to use
 * 				3 which is possibly for admin go ahead but be warned!
 * 	- pin, ASCII representation of the pin number, eg "1234"
 */
int do_chv_verification( SIM_Context * ctx, uint8_t chv_number, char * pin );

void sigtstp_handler( int sg );
node_t * sim_brute( SIM_Context * ctx );
node_t * sim_brute_known( SIM_Context * ctx );
//node_t * sim_get_iccid( SIM_Context * ctx );
//node_t * sim_get_elp( SIM_Context * ctx );
//node_t * sim_get_arpk( SIM_Context * ctx );
//node_t * sim_get_adn( SIM_Context * ctx );
//node_t * sim_get_fdn( SIM_Context * ctx );

char * decode_bcd( known_file * kf, uint8_t * data, int length );
char * decode_pl( uint8_t * data, int data_len, int record_len );
#endif /* SIM_WRAP_H_ */
