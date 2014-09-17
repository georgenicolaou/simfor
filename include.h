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
#ifndef INCLUDE_H_
#define INCLUDE_H_
#include <stdio.h>

#define VERSION "0.0.2 RC1"

extern int glob_verbose;
//#define DEBUG_LEVEL 2
#define dprintf( fmt, ... ) { \
	if( glob_verbose  ) { \
		printf( "[1]%s:%u:" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );   \
	} \
}

#define dlprintf( lvl, fmt, ... ) { \
	if( lvl <= glob_verbose ) \
		printf( "[%d]%s:%u:" fmt "\n", lvl, __FUNCTION__, __LINE__, \
			##__VA_ARGS__ );   \
}
#define ERROR_RESULT -1
#define TRUE 1
#define FALSE 0
#endif
