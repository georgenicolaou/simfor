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
#ifndef SIMFOR_H_
#define SIMFOR_H_


typedef enum usage_type { USAGE_TITLE=0, USAGE_OPTION=1 } usage_type_t;

typedef struct usage {
	enum usage_type type;
	char * str;
	int options_ptr;
} usage_t;

#define FULL_DUMP 1
#define PARTIAL_DUMP 2
#endif /* SIMFOR_H_ */
