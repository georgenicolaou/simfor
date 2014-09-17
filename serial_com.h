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
#ifndef SERIAL_COM_H_
#define SERIAL_COM_H_
#include "apdu_proto.h"

int serial_connect( char * lpsz_device, int n_braud_rate );
void serial_close();
int serial_read( unsigned char * buf, int nlength );
int serial_write( unsigned char * buf, int nlength );
unsigned char get_byte( char * str );
int serial_write_apdu( SC_APDU_Commands * cmd, SC_APDU_Response * resp );
void hex_to_ascii( uint8_t byte, char * str );
int check_flag( uint16_t sw, uint8_t flag );
#endif /* SERIAL_COM_H_ */
