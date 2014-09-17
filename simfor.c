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
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include "include.h"
#include "serial_com.h"
#include "sim_wrap.h"
#include "node.h"
#include "xml_generator.h"
#include "simfor.h"

int glob_verbose = 0;

static const char * opt_string = "so:p:fav::Vh";
const struct option opts[] = {
	{ "info", 	0, 0, 's' },
	{ "output",	1, 0, 'o' },
	{ "pin1", 	1, 0, 'p' },
	{ "full", 	0, 0, 'f' },
	{ "partial", 0, 0, 'a' },
	{ "verbose", 2, 0, 'v' },
	{ "version", 0, 0, 'V' },
	{ "help", 0, 0, 'h' }
};

static const struct usage usage_options[] = {
	{ USAGE_TITLE, "General Options:" },
	{ USAGE_OPTION, "This help" },
	{ USAGE_OPTION, "Print authentication information about this SIM card", 0 },
	{ USAGE_OPTION, "Output to file (Required)", 1 },
	{ USAGE_OPTION, "Specify SIM card PIN", 2 },
	{ USAGE_OPTION, "Increase verbosity level (more v = more verbose)", 5 },
	{ USAGE_OPTION, "Print version and exit", 6 },
	{ USAGE_TITLE, "Extraction Options:" },
	{ USAGE_OPTION, "Full SIM card dump (takes time)", 3 },
	{ USAGE_OPTION, "Partial SIM card dump", 4 }
};


int usage( char * filename ) {
	int i;
	printf( "SIMFor SIM Card Extraction\nUsage: %s [OPTIONS] serial_device\n",
			filename );
	printf( "Author: George Nicolaou (george[at]silensec[dot]com)\n" );
	for( i = 0; i < sizeof( usage_options ) / sizeof( struct usage ); i++ ) {
		if( usage_options[i].type == USAGE_TITLE ) {
			printf( "%s\n", usage_options[i].str );
		}
		else if( usage_options[i].type == USAGE_OPTION ) {
			if( opts[usage_options[i].options_ptr].val > 10 ) {
				printf( " -%c, --%s\t%s\n",
					opts[usage_options[i].options_ptr].val,
					opts[usage_options[i].options_ptr].name,
					usage_options[i].str );
			}
			else {
				printf( " --%s\t%s\n", opts[usage_options[i].options_ptr].name,
					usage_options[i].str );
			}
		}
	}
	return 1;
}

void print_ctx_auth( SIM_Context * ctx )
{
	printf("Auth Stats:\n"
			"\tPIN1: %s\n"
			"\tPIN1 Tries Left: %d\n"
			"\tPUK1: %s\n"
			"\tPUK1 Tries Left: %d\n"
			"\tPIN2: %s\n"
			"\tPIN2 Tries Left: %d\n"
			"\tPUK2: %s\n"
			"\tPUK2 Tries Left: %d\n",
			( (ctx->auth.chv[PIN1]) ? "INITIALIZED" : "NOT INITIALIZED"),
			ctx->auth.chv_left[PIN1],
			( (ctx->auth.uchv[PUK1]) ? "INITIALIZED" : "NOT INITIALIZED" ),
			ctx->auth.uchv_left[PUK1],
			(( ctx->auth.chv[PIN2] ) ? "INITIALIZED" : "NOT INITIALIZED"),
			ctx->auth.chv_left[PIN2],
			( (ctx->auth.uchv[PUK2]) ? "INITIALIZED" : "NOT INITIALIZED" ),
			ctx->auth.uchv_left[PUK2]
	);
}
int main( int argc, char * argv[] ) {
	SIM_Context ctx; // -Wmissing-braces complains
	int c, i, res, dump_type, print_info = 0;
	char * output_file = NULL, * device = NULL;
	char pin[5] = {0};

	memset( &ctx, 0, sizeof(SIM_Context) );

	if( node_init() == FALSE ) {
		printf( "Error initialising nodes bucket\n");
		return 1;
	}

	while( ( c = getopt_long( argc, argv, opt_string,
			(const struct option *)&opts, &i ) ) != -1 ) {
		switch( c ) {
			case 's': print_info = 1; break;
			case 'o': output_file = (char *)optarg; break;
			case 'p':
				if( strlen( optarg ) > 4 ) {
					printf("PIN too long\n");
					return 1;
				}
				strcpy( pin, optarg );
				break;
			case 'f': dump_type = FULL_DUMP; break;
			case 'a': dump_type = PARTIAL_DUMP; break;
			case 'v':
				glob_verbose = 1;
				if( optarg != NULL ) {
					while( *optarg++ ) glob_verbose++;
				}
				break;
			case 'V':
				printf("SIMFor version %s ( http://www.silensec.com )\n",
					VERSION );
				return 1;
			case 'h':
			case '?':
				return usage(argv[0]);
		}
	}

	if( optind < argc ) {
		device = argv[optind];
	}
	else {
		printf("No device specified\n");

		return usage(argv[0]);
	}

	signal( SIGTSTP, (void *)sigtstp_handler );

	res = serial_connect( device, 9600 );
	if( res == ERROR_RESULT ) {
		return res;
	}

	if( print_info ) {
		check_pin( &ctx );
		print_ctx_auth( &ctx );
		return 1;
	}
	char u; int ret;
	if( check_pin( &ctx ) == PIN_LOCKED ) {
		print_ctx_auth( &ctx );
		if( *pin != '\0' ) {
			ret = do_chv_verification( &ctx, PIN1, pin );
			if( ret == FAILURE ) {
				printf( "Invalid PIN\n" );
				return 1;
			}
			else if( ret == BLOCKED ) {
				printf( "PIN is blocked\n" );
				return 1;
			}
		}
		else {
			printf("Requires PIN\nDo you want to provide PIN? (y/n)? ");
			scanf("%c", &u);
			if( u == 'y' ) {
				printf("Specify 4 digit PIN number: ");
				scanf( "%4s", pin );
				printf("Attempting to send PIN: %s\n", pin );
				ret = do_chv_verification( &ctx, PIN1, pin );
				if( ret == FAILURE ) {
					printf("Failed to do CHV1 Authentication");
				}
				else if( ret == BLOCKED ) {
					printf("PIN is blocked\n");
				}
			}
			else {
				printf("Would you like to proceed without a PIN (y/n)? ");
				do {
					scanf("%c", &u );
				} while( u != 'y' && u != 'n' );
				if( u != 'y' ) return 1;
			}

		}
	}
	else {
		printf("No PIN Required\n");
	}

	if( output_file == NULL ) {
		printf("No output file specified\n");
		return 1;
	}

	setup_file( output_file );
	node_t * root;
	printf( "Extracting files, please wait...\n" );
	if( dump_type == FULL_DUMP ) {
		root = sim_brute( &ctx );
	}
	else {
		root = sim_brute_known( &ctx );
	}
	serial_close();
	printf( "Generating Document...\n" );
	generate_document(root);

	return 0;
}

