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
#include "include.h"
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/types.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "serial_com.h"
#include "apdu_proto.h"

void flush_input();
void flush_output();
void setRTS( int set );
void setDTR( int set );
int serial_read_sync( unsigned char * buf, int nlength );
int handle_reset();

struct termios t_original_settings;
int fd;

void serial_sigint_handler( int sig )
{
	dprintf("Got CTRL+C, cleaning up...");
	serial_close();
	exit(sig);
}

int check_flag( uint16_t sw, uint8_t flag )
{
	if( ( ( sw & 0xFF00 ) >> 8 ) == flag ) {
		return TRUE;
	}
	return FALSE;
}

int serial_connect( char * lpsz_device, int n_braud_rate )
{
	speed_t t_baud_rate = B9600;
	struct termios t_settings;
	signal( SIGINT, (void *)serial_sigint_handler );
	dprintf( "Opening device %s", lpsz_device );
	if( ( fd = open( lpsz_device, O_RDWR | O_NOCTTY | O_NONBLOCK ) ) == -1 ) {
		perror("open");
		return ERROR_RESULT;
	}

	dprintf( "Device open at descriptor: %d", fd );
	if( tcgetattr( fd, &t_original_settings ) == -1 ) {
		perror("tcgetattr");
		return ERROR_RESULT;
	}
	dprintf( "Got device original attributes" );
	memset( &t_settings, 0, sizeof(t_settings) );

	t_settings.c_cflag = 0x9FD;
	t_settings.c_ispeed = t_baud_rate;
	t_settings.c_ospeed = t_baud_rate;

	dprintf( "Setting Baud rate for I/O" );
	if( cfsetospeed( &t_settings, t_baud_rate ) == -1 ) {
		perror("Bad speed");
		return ERROR_RESULT;
	}
	if( cfsetispeed( &t_settings, t_baud_rate ) == -1 ) {
		perror("Bad speed");
		return ERROR_RESULT;
	}

	if( tcsetattr( fd, TCSANOW, &t_settings ) == -1 ) {
		perror("tcsetattr");
		return ERROR_RESULT;
	}
	dprintf( "Serial port configuration success" );

	dprintf( "Setting RTS/DTR" );
	int rtsdtr; // = TIOCM_DTR | TIOCM_RTS;
	ioctl( fd, TIOCMGET, &rtsdtr );
	rtsdtr &= ~(TIOCM_RTS | TIOCM_DTR);
	ioctl( fd, TIOCMSET, &rtsdtr );
	rtsdtr &= (TIOCM_RTS | TIOCM_DTR );
	ioctl( fd, TIOCMSET, &rtsdtr );
	//Give some time for the modem to reset (ISO7816 specifies max 40 000CLK Cycles)
	sleep( 0.01 );
	if( handle_reset() < 0 ) {
		printf("Error handle_reset()");
	}
	return fd;
}

int handle_reset()
{
	unsigned char r;
	dprintf("Handling serial port reset");

	if( serial_read( &r, 1 ) < 0 ) {
		return ERROR_RESULT;
	}

	//Handle initial convention (just info)
	char * conv;
	switch( r ) {
		case DIRECT:
			conv = "Direct Convention";
			break;
		case INDIRECT:
			conv = "Inverse Convention";
			break;
		case 0x00:
			dprintf("Card Not Inserted or Damaged");
			return ERROR_RESULT;
		default:
			conv = "Unknown";
			break;
	}
	dprintf("Initial Character (TS) = 0x%02X (%s)", r, conv );

	if( r == 0 ) {
		return ERROR_RESULT;
	}

	//T0
	if( serial_read( &r, 1 ) < 0 ) {
		return ERROR_RESULT;
	}
	dprintf( "T0 = 0x%02X", r );
	unsigned char yi = (r & 0xF0) >> 4; //Initial Y1
	unsigned char ki = r & 0x0F;
	unsigned char proto = 0;
	int i,tdi = 0, protocnt = 1;
	char * paramname[] = { "TA", "TB", "TC", "TD" };
	do {
		for( i = 0; i < 4; i++ ) {
			if( yi & ( 0x01 << i ) ) { //Tx follows
				if( serial_read( &r, 1 ) < 0 ) {
					return ERROR_RESULT;
				}
				dprintf( "Param %s%d = 0x%02X", paramname[i], protocnt, r );
				if( i == 0 ) { //Doing TAi (freq and byte adj)
					char * freq, * bitadj;
					switch( (r & 0xF0) >> 4 ) { //XXX this is probably wrong
						case 0: freq = "Internal"; break; //0000
						case 1: freq = "5Mhz"; break; //0001
						case 2: freq = "6Mhz"; break; //0010
						case 3: freq = "8Mhz"; break; //0011
						case 4: freq = "12Mhz"; break; //0100
						case 5: freq = "16Mhz"; break; //0101
						case 6: freq = "20Mhz"; break; //0110
						case 7: freq = "Invalid/Reserved"; break; //0111
						case 8: freq = "Invalid/Reserved"; break; //1000
						case 9: freq = "5Mhz"; break; //1001
						case 10: freq = "7.5Mhz"; break; //1010
						case 11: freq = "10Mhz"; break; //1011
						case 12: freq = "15Mhz"; break; //1100
						case 13: freq = "20Mhz"; break; //1101
						case 14: freq = "Invalid/Reserved"; break; //1110
						case 15: freq = "Invalid/Reserved"; break; //1111
						default:
							freq = "Internal Error";
					}
					switch( r & 0x0F ) {
						case 0: bitadj = "Invalid/Reserved"; break; //0000
						case 1: bitadj = "1"; break; //0001
						case 2: bitadj = "2"; break; //0010
						case 3: bitadj = "4"; break; //0011
						case 4: bitadj = "8"; break; //0100
						case 5: bitadj = "16"; break; //0101
						case 6:
						case 7:
						case 8:
						case 9:
							bitadj = "Invalid/Reserved"; break;
						case 10: bitadj = "1/2"; break; //1010
						case 11: bitadj = "1/4"; break; //1011
						case 12: bitadj = "1/8"; break; //1100
						case 13: bitadj = "1/16"; break; //1101
						case 14: bitadj = "1/32"; break; //1110
						case 15: bitadj = "1/64"; break; //1111
						default:
							bitadj = "Internal Error";
					}
					//XXX do some checking here
					dprintf( "\tFreq: %s, Bit rate adjustment: %s", freq,
							bitadj);
				}
				else if( i == 1 ) {
					dprintf("\tTBi support not implemented");
				}
				else if( i == 2 ) {
					dprintf("\tTCi support not implemented");
				}
				else if( i == 3 ) { //TDi
					yi = (r & 0xF0) >> 4;
					proto = r & 0x0F;
					//XXX Do some checking here too
					switch( proto ) {
						case 0:
							dprintf( "TD%d = Asynchronous half duplex character"
									" transmission protcol", protocnt );
							break;
						case 1:
							dprintf( "TD%d = Asynchronous half duplex block "
									"transmission protocol", protocnt );
							break;
						default:
							dprintf( "TD%d = Reserved value (%d) - Possible "
									"full duplex or enhanced)", protocnt, proto );
							break;
					}
				}
			}
			else if( i == 3 ) {
				dprintf("No TD%d", protocnt );
				tdi = 0;
			}
		}
		protocnt++;
	} while( tdi );

	if( proto == 0 ) {
		dprintf("Continuing with async halfduplex char transmission protocol");
	}
	else {
		dprintf("Unimplemented protocol, crossing fingers and continuing");
	}

	//going through historical bytes
	for( i = 0; i < (int)ki; i++ ) {
		if( serial_read( &r, 1 ) < 0 ) {
			return ERROR_RESULT;
		}
		dprintf( "Historical Byte %d = 0x%02X", i+1, r );
	}

	/*
	 * Some SIM cards don't behave nicely. There should be something in the
	 * standards that I've missed but some SIM cards provide T=0 but still have
	 * the TCK check byte... However, based on the standard, if T=0 and T=15
	 * then TCK is there. The card tested had T=15 on the first historical byte
	 *
	 * Nonetheless, lets just keep reading until the SIM card complains that we
	 * are a good listener but not a good talker...
	 */

	unsigned char r_prev = '\xff';
	while(1) {
		if( serial_read( &r, 1 ) < 0 ) {
			break;
		}
		if( r == r_prev ) break;
		r_prev = r;
		dprintf( "Extra Byte: 0x%02X", r );
	}
	return 1;
}

void flush_input()
{
	dprintf( "Flushing input" );
	tcflush( fd, TCIFLUSH );
}

void flush_output()
{
	dprintf( "Flushing output" );
	tcflush( fd, TCOFLUSH );
}

void setRTS( int set )
{
	if( set )
		ioctl( fd, TIOCMBIS, TIOCM_RTS );
	else
		ioctl( fd, TIOCMBIC, TIOCM_RTS );
}

void setDTR( int set )
{
	if( set )
		ioctl( fd, TIOCMBIS, TIOCM_DTR );
	else
		ioctl( fd, TIOCMBIC, TIOCM_DTR );
}
void serial_close()
{
	dprintf( "Restoring serial configuration and closing" );
	tcsetattr( fd, TCSANOW, &t_original_settings );
	if( close(fd) == -1 ) {
		perror(NULL);
	}
}

unsigned char get_byte( char * str ) {
	unsigned char c = '\0', step;
	int i;
	for( i = 0; i<2; i++ ) {
		c <<= 4;
		step = str[i];
		c |= ( step < '9' ) ? ( step - '0' ) : ( step - 'A' + 10 );
	}
	return c;
}

static const char hexchars[] = "0123456789ABCDEF";
void hex_to_ascii( uint8_t byte, char * str )
{
	*str = hexchars[( byte & 0xF0 ) >> 4];
	*(str+1) = hexchars[byte & 0x0F];
}

int serial_write_apdu( SC_APDU_Commands * cmd, SC_APDU_Response * resp )
{
	int i;
	unsigned char * header = (unsigned char *)(cmd);
	if( cmd->Body.LC > LC_MAX ) { //|| cmd->Body.LE > LC_MAX+2 ) { //+2 coz of SW
		printf("Invalid APDU argument length");
		return ERROR_RESULT;
	}

	//XXX uncomment if you want to debug
	/*
	char arg[LC_MAX+1] = {0}; // 20 + 1
	if( cmd->Body.LC ) {
		for( i = 0; i < cmd->Body.LC; i++ ) {
			hex_to_ascii( cmd->Body.Data[i], arg+i*2);
		}
		dprintf("Transmitting APDU command %02X%02X%02X%02X%02X%s",
				cmd->Header.CLA, cmd->Header.INS, cmd->Header.P1, cmd->Header.P2,
				cmd->Body.LC, arg );
	}
	else if( cmd->Body.LE ) {
		dprintf("Transmitting APDU command %02X%02X%02X%02X%02X",
				cmd->Header.CLA, cmd->Header.INS, cmd->Header.P1, cmd->Header.P2,
				cmd->Body.LE );
	}
	*/

	//Transmit header
	uint8_t r;
	for( i = 0; i<sizeof(SC_Header); i++ ) {
		if( serial_write( header+i, 1 ) != 1 ) {
			perror("write()");
			return ERROR_RESULT;
		}
		dlprintf( 3, "Wrote: 0x%02X", *(header+i) );
		do {
			if( serial_read( &r, 1 ) == -1 ) {
				perror("serial_read()");
				return ERROR_RESULT;
			}
			dlprintf( 3, "Got: 0x%02X", r );
		} while( r == SC_RESET && *(header+i) != SC_RESET );
	}

	//If LE = 0 and LC = 0 it means we are quering for length
	if( cmd->Body.LC || cmd->Body.LE == 0 ) {
		//dprintf("Sending Body Data Length");
		if( serial_write( &cmd->Body.LC, 1 ) != 1 ) {
			perror("write()");
			return ERROR_RESULT;
		}
		dlprintf( 3, "Wrote: 0x%02X", cmd->Body.LC );
	}
	else if( cmd->Body.LE ) {
		if( serial_write( &cmd->Body.LE, 1 ) != 1 ) {
			perror("write()");
			return ERROR_RESULT;
		}
		dlprintf( 3, "Wrote: 0x%02X", cmd->Body.LE );
	}
	//Read length echo
	if( serial_read( &r, 1 ) == ERROR_RESULT ) {
		perror("serial_read()");
		return ERROR_RESULT;
	}

	dlprintf( 3, "Read: 0x%02X", r );
	if( serial_read( &r, 1 ) == ERROR_RESULT ) {
		perror("serial_read()");
		return ERROR_RESULT;
	}
	dlprintf( 3, "Read: 0x%02X", r );

	//XXX might need to loop this for ACK_NULL
	resp->SW1 = 0;
	if( ( (r & 0xF0) == 0x60 ) || ( (r & 0xF0) == 0x90 ) ) {
		resp->SW1 = r;
		if( serial_read( &r, 1 ) == ERROR_RESULT ) {
			perror("serial_read()");
			return ERROR_RESULT;
		}
		resp->SW2 = r;
		dprintf("Received SW1/SW2 = 0x%02X%02X", resp->SW1, resp->SW2 );
	}

	unsigned char s;
	if( resp->SW1 == 0 ) { //We are sending data
		for( i = 0; i < cmd->Body.LC; i++ ) {
			s = cmd->Body.Data[i];
			if( serial_write( &s, 1 ) != 1 ) {
				perror("write()");
				return ERROR_RESULT;
			}
			dlprintf( 3, "Wrote: 0x%02X", s);
			do {
				if( serial_read( &r, 1 ) == -1 ) {
					perror("read()");
					return ERROR_RESULT;
				}
				dlprintf( 3, "Read: 0x%02X", r );
			} while( r == SC_RESET && s != SC_RESET );
		}
	}
	if( cmd->Body.LE ) { //We are expecting data
		for( i = 0; i < cmd->Body.LE; i++ ) {
			if( serial_read( &r, 1 ) == ERROR_RESULT ) {
				perror("serial_read()");
				return ERROR_RESULT;
			}
			resp->Data[i] = r;
		}
	}

	do {
		if( serial_read( &r, 1 ) == ERROR_RESULT ) {
			perror("serial_read()");
			return ERROR_RESULT;
		}
		dlprintf( 3, "Read: 0x%02X", r );
		//sleep(0.01);
	} while( r == SC_ACK_NULL );


	if( ( (r & 0xF0) == 0x60 ) || ( (r & 0xF0) == 0x90 ) ) {
		resp->SW1 = r;
		if( serial_read( &r, 1 ) == ERROR_RESULT ) {
			perror("serial_read()");
			return ERROR_RESULT;
		}
		resp->SW2 = r;
		//XXX Uncomment if you want to debug
		//dprintf("Received SW1/SW2 = 0x%02X%02X", resp->SW1, resp->SW2 );
	}
	return 1;
}

int serial_write( unsigned char * buf, int nlength )
{
	int res;
	struct timeval tv;
	fd_set fdset;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	if( ( res = write( fd, buf, nlength ) ) == -1 ) {
		perror("write()");
		return res;
	}
	select( fd+1, 0, &fdset, 0, &tv );
	return res;
}

int serial_read_sync( unsigned char * buf, int nlength )
{
	int bread;
	struct timeval tv;
	fd_set fdset;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	//dprintf( "Attemptint to read %d byte(s)", nlength );
	select( fd, 0, 0, 0, &tv );
	if( ( bread = read( fd, buf, nlength ) ) == -1 ) {
		perror("read");
		return ERROR_RESULT;
	}
	return bread;
}

int serial_read( unsigned char * buf, int nlength )
{
	int bread;
	struct timeval tv;
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	select( fd+1, &fdset, 0, 0, &tv );
	//dprintf( "Attemptint to read %d byte(s)", nlength );
	if( ( bread = read( fd, buf, nlength ) ) == -1 ) {
		perror("read");
		return ERROR_RESULT;
	}
	return bread;
}
