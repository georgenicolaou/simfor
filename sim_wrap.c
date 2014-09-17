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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "include.h"
#include "serial_com.h"
#include "apdu_proto.h"
#include "sim_filesystem.h"
#include "sim_wrap.h"
#include "node.h"
#include "sim_known_files.h"
#include <time.h>

node_t mf_root; //This is the root MF node.

uint16_t sim_goto_file( SIM_Context * ctx, uint16_t sim_file );
void swap_endianess( uint8_t * target, uint8_t * val, int size );
int check_pin( SIM_Context * ctx );
void dump_tree( node_t * currdf );

void swap_endianess( uint8_t * target, uint8_t * val, int size )
{
	int i;
	for( i = size-1; i >= 0; i-- ) {
		target[size-i-1] = val[i];
	}
}

int do_chv_verification( SIM_Context * ctx, uint8_t chv_number, char * pin )
{
	SC_APDU_Commands sCmd;
	SC_APDU_Response sResponse;
	memset( &sCmd, 0, sizeof(sCmd) );
	memset( &sResponse, 0, sizeof(sResponse) );
	RESP_DEFAULT( sResponse );
	if( chv_number > 1 ) {
		printf("**WARNING**: CHV Number you specified could damage the card\n");
	}
	dlprintf( 2, "Attempting to authenticate PIN%d with %s", chv_number+1, pin );

	if( chv_number == PIN1 ) {
		if( ctx->auth.chv1_disabled ) {
			dlprintf( 2, "CHV1 is disabled, no authentication required");
			return SUCCESS;
		}
	}

	if( chv_number <= 1 ) {
		if( ctx->auth.chv_left[chv_number] == 0 ) {
			return BLOCKED;
		}
	}

	sCmd.Header.CLA = SC_CLA_GSM11;
	sCmd.Header.INS = SC_VERIFY;
	sCmd.Header.P1 = 0x00;
	sCmd.Header.P2 = (uint8_t)chv_number+1;
	sCmd.Body.LC = 0x08; //Always 8

	//Padding requirements, eg 1234 becomes: 31323334FFFFFFFF
	int i = 0;
	while( *pin ) {
		sCmd.Body.Data[i++] = *pin;
		pin++;
	}
	while( i < 0x08 ) {
		sCmd.Body.Data[i++] = 0xFF;
	}

	serial_write_apdu( &sCmd, &sResponse );
	dlprintf( 2, "Response SW = 0x%02X%02X", sResponse.SW1, sResponse.SW2 );
	if( ( ( sResponse.SW1 << 8 ) | sResponse.SW2 ) == SC_OP_TERMINATED ) {
		ctx->auth.session_auth[chv_number] = TRUE;
		return SUCCESS;
	}
	ctx->auth.session_auth[chv_number] = FALSE;
	return FAILURE;
}

int check_pin( SIM_Context * ctx )
{
	//Check if MF can be selected
	uint16_t sw = sim_goto_file( ctx, F_MASTER_FILE );
	if( check_flag( sw, SC_DF_SELECTED ) ) {
		SC_APDU_Commands sCmd;
		SC_APDU_Response sResponse;
		memset( &sCmd, 0, sizeof(sCmd) );
		memset( &sResponse, 0, sizeof(sResponse) );

		//All ok, we need to check Response. SW2 contains the length (22 bytes)
		sCmd.Header.CLA = SC_CLA_GSM11;
		sCmd.Header.INS = SC_STATUS;
		sCmd.Header.P1 = 0x00;
		sCmd.Header.P2 = 0x00;
		sCmd.Body.LE = (uint8_t)(sw & 0x00FF);
		if( ( sResponse.Data = (uint8_t *)calloc(
				sCmd.Body.LE, sizeof( uint8_t ) ) ) == NULL ) {
			perror("calloc()");
			return ERROR_RESULT;
		}
		serial_write_apdu( &sCmd, &sResponse );
		DF_GSM_Response * status = (DF_GSM_Response *)sResponse.Data;
		dlprintf( 2, "Response Status:\n"
				"\t1-2:\tReserved\n"
				"\t3-4:\tmem_free = 0x%X\n"
				"\t5-6:\tfile_id = 0x%X\n"
				"\t7:\ttype = 0x%02X\n"
				"\t8-12\tReserved\n"
				"\t13:\tdata_length = 0x%02X\n"
				"\t14:\tcharacteristics = 0x%02X\n"
				"\t15:\tndirs = 0x%02X\n"
				"\t16:\tnfiles = 0x%02X\n"
				"\t17:\tncodes = 0x%02X\n"
				"\t18:\tReserved\n"
				"\t19:\tchv1_status = 0x%02X\n"
				"\t20:\tuchv1_status = 0x%02X\n"
				"\t21:\tchv2_status = 0x%02X\n"
				"\t22:\tuchv2_status = 0x%02X\n"
				"\t23:\tReserved\n"
				"\t24-34: Reserved for admin management\t\n",
				SWAP_ENDIANESS_16( status->mem_free ),
				SWAP_ENDIANESS_16( status->file_id ),
				status->type,
				status->data_length,
				status->characteristics,
				status->ndirs,
				status->nfiles,
				status->ncodes,
				status->chv1_status,
				status->uchv1_status,
				status->chv2_status,
				status->uchv2_status
				);

		ctx->auth.chv[PIN1] = GET_CHV_INITIALIZED( status->chv1_status );
		ctx->auth.chv_left[PIN1] = GET_CHV_REMAINING( status->chv1_status );
		ctx->auth.uchv[PUK1] =	GET_CHV_INITIALIZED( status->uchv1_status );
		ctx->auth.uchv_left[PUK1] = GET_CHV_REMAINING( status->uchv1_status );

		ctx->auth.chv[PIN2] = GET_CHV_INITIALIZED( status->chv2_status );
		ctx->auth.chv_left[PIN2] = GET_CHV_REMAINING( status->chv2_status );
		ctx->auth.uchv[PUK2] =	GET_CHV_INITIALIZED( status->uchv2_status );
		ctx->auth.uchv_left[PUK2] = GET_CHV_REMAINING( status->uchv2_status );

		//Check if MF requires CHV1 and return
		if( CHV1_DISABLED( status->characteristics ) ) {
			ctx->auth.chv1_disabled = 1;
			return PIN_UNLOCKED;
		}
		else {
			ctx->auth.chv1_disabled = 0;
			return PIN_LOCKED;
		}
	}
	else {
		printf("Error: Unable to select MF bad SW: 0x%04X\n", sw );
		//Lets issue an authentication, maybe thats the problem
		return PIN_LOCKED;
	}
}

uint16_t sim_goto_path( SIM_Context * ctx, int num_nodes, ...)
{
	va_list args;
	int i;
	uint16_t arg, sw;
	va_start( args, num_nodes );
	for( i = 0; i < num_nodes; i++ ) {
		arg = va_arg( args, int );
		sw = sim_goto_file( ctx, arg );
		//No need for SC_EF_SELECTED since its equal to SC_DF_SELECTED
		if( check_flag( sw, SC_DF_SELECTED ) == FALSE ) {
			dprintf( "Error: 0x%04X when selecting: 0x%04X", sw, arg );
			va_end( args );
			return sw;
		}
	}
	va_end( args );
	return sw;
}

int keepreading = 1;
void sigtstp_handler( int sg )
{
	keepreading = 0;
}

uint16_t sim_goto_file( SIM_Context * ctx, uint16_t sim_file )
{
	SC_APDU_Commands sCmd;
	SC_APDU_Response sResponse;
	memset( &sCmd, 0, sizeof(sCmd) );
	memset( &sResponse, 0, sizeof(sResponse) );

	RESP_DEFAULT( sResponse );
	//A0A4000002[sim_file]
	sCmd.Header.CLA = SC_CLA_GSM11;
	sCmd.Header.INS = SC_SELECT_FILE;
	sCmd.Header.P1 = 0x00;
	sCmd.Header.P2 = 0x00;
	sCmd.Body.LC = 0x02;
	swap_endianess( (uint8_t *)sCmd.Body.Data, (uint8_t *)&sim_file, 2 );
	sCmd.Body.LE = 0;

	serial_write_apdu( &sCmd, &sResponse );
	uint16_t sw = ( sResponse.SW1 << 8 ) | sResponse.SW2;
	return sw;
	/*
	 * XXX ETS 300 977 says that SELECT also outputs file meta-data. However,
	 * in some real life tests SIM cards usually don't do that (or I've missed
	 * something).
	 *
	 * We should have an algorithm here to try and test weather that is true.
	 * This would however increase read() time due to select() if the file has
	 * nothing to give us. We could decrease the timeout of select() tho.
	 */
}

/*
 * Retrieves the response string of the file we've just SELECTed. This function
 * assumes that the SELECT status word was checked for SC_EF_SELECTED and
 * SC_DF_SELECTED accordingly.
 *
 * Note that the resp->Data field is always allocated by this function and
 * needs to be free'd if the resp structure is discarded
 * Parameters:
 * 	- ctx, The SIM Context
 * 	- sw, The status word received from the previous SELECT command
 * 	- resp, An empty SC_APDU_Response so this function wont have to allocate one
 */
int get_file_response( SIM_Context * ctx, uint16_t sw, SC_APDU_Response * resp )
{
	SC_APDU_Commands sCmd;
	memset( &sCmd, 0, sizeof(sCmd) );
	uint8_t num_expected = (uint8_t)( sw & 0xFF ); //Number of expected bytes
	memset( resp, 0, sizeof(SC_APDU_Response) );

	sCmd.Header.CLA = SC_CLA_GSM11;
	sCmd.Header.INS = SC_GET_RESPONCE;
	sCmd.Header.P1 = 0x00;
	sCmd.Header.P2 = 0x00;
	sCmd.Body.LE = num_expected;

	if( ( resp->Data = (uint8_t *)calloc(
			sCmd.Body.LE, sizeof( uint8_t ) ) ) == NULL ) {
		perror("calloc()");
		return ERROR_RESULT;
	}

	serial_write_apdu( &sCmd, resp );
	//dlprintf( 2, "Response SW = 0x%02X%02X", resp->SW1, resp->SW2 );
	return SUCCESS;
}

/*
 * Get the node of a file given the directory path and file ids.
 * Params:
 * 	- path_len, The number of file/folder ids that are passed to this function.
 * 				eg: For the ICCID file use 3F00, 2FE2 with a path_len = 2
 * 	- ..., The actual file ids that make up the path
 *
 * Returns:
 * 	- node_t *, of the node is found.
 * 	- NULL, if the node could not be found.
 */
node_t * sim_getfile_node( int path_len, ... )
{
	va_list args;
	node_t * curr = &mf_root;
	int i;
	uint16_t arg;
	va_start( args, path_len );
	for( i = 0; i < path_len - 1; i++ ) { // -1 since we already know root
		arg = (uint16_t)va_arg( args, int );
		if( ( curr = node_get_child( curr, arg ) ) == NULL ) {
			va_end( args );
			return NULL;
		}
	}
	va_end( args );
	return curr;
}

int sim_getfile_contents( SIM_Context * ctx, EF_GSM_Response * resp,
		SC_APDU_Response * sDataResponse, node_t * node )
{
	int i;

	/*if( data_len < resp->file_size ) {
		dprintf( "Data given is smaller than file size" );
	}*/
	if( resp->type != T_EF ) {
		dprintf("This is not an EF %02X", resp->file_id );
		return ERROR_RESULT;
	}
	//Check if file is not invalidated
	if( IS_INVALIDATED( resp->status ) ) {
		dlprintf( 2, "File is invalidated" );
		if( !READABLE_IF_INVALIDATED( resp->status ) ) {
			dprintf( "File is invalidated and not readable" );
			return ERROR_RESULT;
		}
	}

	//Check if we have READ/SEEK access (access[0] high 4 bits)
	uint8_t read_lvl = GET_HIGH4(resp->access[0]);
	if( read_lvl == 15 ) {
		//dprintf( "File cannot be read by anyone" );
		return ERROR_RESULT;
	}
	if( read_lvl != 0 ) {
		if( read_lvl - 1 == PIN1 && ctx->auth.chv1_disabled ) {
			//dprintf("CHV1 Required but disabled, moving along");
		}
		else {
			if( ctx->auth.session_auth[read_lvl-1] == FALSE ) {
				//dprintf( "You need to authenticate using PIN%d", read_lvl );
				return ERROR_RESULT;
			}
		}

	}
	//else {
		//dlprintf( 2, "File %04X has unrestricted ALW access", resp->file_id );
	//}

	SC_APDU_Commands sCmd;
	memset( &sCmd, 0, sizeof(sCmd) );
	sCmd.Header.CLA = SC_CLA_GSM11;
	//SC_APDU_Response sDataResponse = {0};
	//Ok lets do some reading
	switch( resp->ef_structure ) {
		case EF_TRANSPARENT: //READ BINARY
			sCmd.Header.INS = SC_READ_BINARY;
			sCmd.Header.P1 = 0; //High offset = 0
			sCmd.Header.P2 = 0; //Low offset = 0
			sCmd.Body.LE = resp->file_size;
			/*if( ( sDataResponse.Data = (uint8_t *)calloc(
					resp->file_size, 1 ) ) == NULL ) {
				perror("calloc()");
				return (uint8_t *)ERROR_RESULT;
			}
			*/
			serial_write_apdu( &sCmd, sDataResponse );
			node->spec.ef_type.type = RAW;
			node->spec.ef_type.ef_rawdata = sDataResponse->Data;
			break;
		case EF_LINEAR: //READ RECORD, SEEK
		case EF_CYCLIC: //READ RECORD
			sCmd.Header.INS = SC_READ_RECORD;
			sCmd.Header.P1 = 0;
			sCmd.Header.P2 = GET_NEXT_RECORD;
			sCmd.Body.LE = resp->length_of_record;
			int num_records = resp->file_size / resp->length_of_record;
			uint8_t * data_buf = sDataResponse->Data;
			raw_records * records = node_allocate_records( num_records,
					resp->length_of_record );
			for( i = 0; i < num_records; i++ ) {
				serial_write_apdu( &sCmd, sDataResponse );
				records->records[i] = (char *)sDataResponse->Data;
				sDataResponse->Data += resp->length_of_record;
			}
			sDataResponse->Data = data_buf;
			node->spec.ef_type.type = RECORDS;
			node->spec.ef_type.ef_records = records;
			break;
	}
	return SUCCESS;
}

void swap_byte_nibbles( uint8_t * buf, int len )
{
	int i;
	for( i = 0; i < len; i++ ) {
		*(buf+i) = ( ( *(buf+i) & 0xF0 ) >> 4 ) | ( ( *(buf+i) & 0x0F ) << 4 );
	}
}

void parse_df_node( node_t * node, node_t * parent, DF_GSM_Response * stats )
{
	stats->file_id = SWAP_ENDIANESS_16( stats->file_id );
	stats->mem_free = SWAP_ENDIANESS_16( stats->mem_free );
	node->file_id = stats->file_id;
	node->file_type = stats->type;
	node->parent = parent;
	node->spec.df_type.df_attr = stats;
	if( stats->file_id != F_MASTER_FILE ) {
		node_add_child( parent, node );
	}
	/*
	dlprintf( 2, "Response Status:\n"
			"\tmem_free = 0x%X\n"
			"\tfile_id = 0x%X\n"
			"\ttype = 0x%02X\n"
			"\tdata_length = 0x%02X\n"
			"\tcharacteristics = 0x%02X\n"
			"\tndirs = 0x%02X\n"
			"\tnfiles = 0x%02X\n"
			"\tncodes = 0x%02X\n"
			"\tReserved\n"
			"\tchv1_status = 0x%02X\n"
			"\tuchv1_status = 0x%02X\n"
			"\tchv2_status = 0x%02X\n"
			"\tuchv2_status = 0x%02X\n",
			stats->mem_free,
			stats->file_id,
			stats->type,
			stats->data_length,
			stats->characteristics,
			stats->ndirs,
			stats->nfiles,
			stats->ncodes,
			stats->chv1_status,
			stats->uchv1_status,
			stats->chv2_status,
			stats->uchv2_status
			);
			*/
}

void parse_ef_node( node_t * node, node_t * parent, EF_GSM_Response * stats )
{
	stats->file_id = SWAP_ENDIANESS_16( stats->file_id );
	stats->file_size = SWAP_ENDIANESS_16( stats->file_size );

	node->file_id = stats->file_id;
	node->file_type = stats->type;
	node->parent = parent;
	node->spec.ef_type.ef_attr = stats;
	node_add_child( parent, node );
/*
	dprintf("Stats\n"
			"\tfile_size = 0x%04X\n"
			"\tfile_id = 0x%04X\n"
			"\ttype = 0x%02X\n"
			"\tincrease_allowed = 0x%02X\n"
			"\taccess[0] = 0x%02X\n"
			"\taccess[1] = 0x%02X\n"
			"\taccess[2] = 0x%02X\n"
			"\tstatus = 0x%02X\n"
			"\tdata_length = 0x%02X\n"
			"\tef_structure = 0x%02X\n"
			"\tlength of record = 0x%02X",
			stats->file_size,
			stats->file_id,
			stats->type,
			stats->increase_allowed,
			stats->access[0],
			stats->access[1],
			stats->access[2],
			stats->status,
			stats->data_length,
			stats->ef_structure,
			stats->length_of_record
			);
			*/
}

/*
 * This function generates the node_t information of a given DF or EF. This
 * includes the file attributes/metadata as well as the file's contents.
 * Note that this function does not care about the current location in the
 * filesystem. That should be handled by the caller.
 */
node_t * sim_populate_file( SIM_Context * ctx, node_t * parent,
		uint16_t file_id )
{
	node_t * this_node;
	uint16_t sw;
	//We already have this record
	if( ( this_node = node_get_child( parent, file_id ) ) != NULL ) {
		dprintf("We have it %X", this_node->file_id );
		return this_node;
	}

	sw = sim_goto_file( ctx, file_id );
	if( !check_flag( sw, SC_EF_SELECTED ) ) {
		dprintf("Unable to access/find file");
		return (node_t *)ERROR_RESULT;
	}

	SC_APDU_Response sStatusResp = {0};
	if( get_file_response( ctx, sw, &sStatusResp ) == ERROR_RESULT ) {
		return (node_t *)ERROR_RESULT;
	}

	//Since we dont know what kind of file this is, we just treat it as DF
	DF_GSM_Response * dummy = (DF_GSM_Response *)sStatusResp.Data;

	switch( dummy->type ) {
		case T_RFU:
			dprintf("This is a reserved file, exiting");
			return (node_t *)ERROR_RESULT;
		case T_MF:
		case T_DF:
			this_node = node_new();
			parse_df_node( this_node, parent,
					(DF_GSM_Response *)sStatusResp.Data );
			return this_node;
		case T_EF:
			this_node = node_new();
			parse_ef_node( this_node, parent,
					(EF_GSM_Response *)sStatusResp.Data );

			int file_size = this_node->spec.ef_type.ef_attr->file_size;
			SC_APDU_Response sDataResp = {0};
			//dprintf("Allocated: %d (%X)", file_size, file_size );
			if( ( sDataResp.Data = calloc( file_size, 1 ) ) == NULL ) {
				perror("calloc()");
				return (node_t *)ERROR_RESULT;
			}
			if( sim_getfile_contents( ctx, this_node->spec.ef_type.ef_attr,
					&sDataResp, this_node ) == ERROR_RESULT ) {
				free( sDataResp.Data );
				return (node_t *)ERROR_RESULT;
			}
			return this_node;
	}
	return (node_t *)ERROR_RESULT;
}

void dump_node( node_t * node )
{
	printf( "***Node: 0x%04X\n", node->file_id );
	printf( "\tfile_id = 0x%02X\n", node->file_id );
	if( node->parent != NULL ) {
		printf( "\tparent = ");
		node_t * par_tmp = node->parent;
		while( par_tmp ) {
			printf("0x%02X ", par_tmp->file_id );
			par_tmp = par_tmp->parent;
		}
		printf("\n");
	}
	char * filetypes[] = { "RFU", "MF", "DF", "???", "EF" };
	char * filetype;
	if( node->file_type < 5 ) {
		filetype = filetypes[node->file_type];
	}
	else {
		filetype = "**Type out of bounds**??";
	}

	printf( "\tfile_type = 0x%02X (%s)\n", node->file_type, filetype );
	printf( "\tnum_children = %d\n", node->num_children );
	EF_GSM_Response * efstats;
	DF_GSM_Response * dfstats;
	switch( node->file_type ) {
	case T_MF:
	case T_DF:
		printf("\tnum_dirs = %d\n"
				"\tnum_files = %d\n",
				node->spec.df_type.num_dirs,
				node->spec.df_type.num_files
				);
		dfstats = node->spec.df_type.df_attr;
		printf("\tStats:\n"
				"\tmem_free = 0x%X\n"
				"\tfile_id = 0x%X\n"
				"\ttype = 0x%02X\n"
				"\tdata_length = 0x%02X\n"
				"\tcharacteristics = 0x%02X\n"
				"\tndirs = 0x%02X\n"
				"\tnfiles = 0x%02X\n"
				"\tncodes = 0x%02X\n"
				"\tReserved\n"
				"\tchv1_status = 0x%02X\n"
				"\tuchv1_status = 0x%02X\n"
				"\tchv2_status = 0x%02X\n"
				"\tuchv2_status = 0x%02X\n",
				dfstats->mem_free,
				dfstats->file_id,
				dfstats->type,
				dfstats->data_length,
				dfstats->characteristics,
				dfstats->ndirs,
				dfstats->nfiles,
				dfstats->ncodes,
				dfstats->chv1_status,
				dfstats->uchv1_status,
				dfstats->chv2_status,
				dfstats->uchv2_status
				);
		break;
	case T_EF:
		efstats = node->spec.ef_type.ef_attr;
		printf("\tStats\n"
				"\tfile_size = 0x%04X\n"
				"\tfile_id = 0x%04X\n"
				"\ttype = 0x%02X\n"
				"\tincrease_allowed = 0x%02X\n"
				"\taccess[0] = 0x%02X\n"
				"\taccess[1] = 0x%02X\n"
				"\taccess[2] = 0x%02X\n"
				"\tstatus = 0x%02X\n"
				"\tdata_length = 0x%02X\n"
				"\tef_structure = 0x%02X\n"
				"\tlength of record = 0x%02X\n",
				efstats->file_size,
				efstats->file_id,
				efstats->type,
				efstats->increase_allowed,
				efstats->access[0],
				efstats->access[1],
				efstats->access[2],
				efstats->status,
				efstats->data_length,
				efstats->ef_structure,
				efstats->length_of_record
				);
		int i;
		int j;
		raw_records * rec;
		printf("File Contents:\n");

		switch( node->spec.ef_type.type ) {
			case RAW:
				for( i = 0; i < efstats->file_size; i++ ) {
					printf( "%02X", (uint8_t)node->spec.ef_type.ef_rawdata[i]);
				}
				printf("\n");
				break;
			case RECORDS:
				rec = node->spec.ef_type.ef_records;
				for( i = 0; i < rec->num_records; i++ ) {
					printf("Record[%d]: ", i );
					for( j = 0; j < rec->record_size; j++ ) {
						printf( "%02X", (uint8_t)rec->records[i][j] );
					}
					printf("\n");
				}
				break;
			case EMPTY:
				printf( "\tEmpty/Not Retrieved" );
		}
		break;
		//node->spec.ef_type.type
	}
}

void sim_decode_known( node_t * root )
{
	int i, j, success;
	known_file * kf;
	node_t * currpath, * tmpnode;

	for( i = 0; i < sizeof(known) / sizeof(known_file); i++ ) {
		j = 0;
		currpath = root;
		kf = &known[i];
		success = TRUE;
		while( kf->path[j] != PATH_END ) {
			if( kf->path[j] != F_MASTER_FILE ) {
				tmpnode = node_get_child( currpath, kf->path[j] );
				if( tmpnode == NULL ) {
					success = FALSE;
					break; //Path could not be found, we haven't got this file
				}
				currpath = tmpnode;
			}
			j++;
		}
		if( success == FALSE ) continue;
		currpath->name = kf->name;
		currpath->description = kf->descr;
		/*
		if( kf->coding_decoder != NULL ) {
			switch( currpath->spec.ef_type.type ) {

			}
		}
		*/
		if( kf->coding ) {
			if( currpath->spec.ef_type.type == RAW ) {
				currpath->spec.ef_type.decoded.ef_rawdata =
					(uint8_t *)kf->coding(
						kf, currpath->spec.ef_type.ef_rawdata,
						currpath->spec.ef_type.ef_attr->file_size );
			}
			else if (currpath->spec.ef_type.type == RECORDS ){
				//XXX implement a way to decode record types...
				printf("Record types are not implemented");
			}
		}

		/* XXX this was the old attempt in decoding records, using ptr to func
		 * now.
		switch( kf->coding ) {
			case CODING_BCD:
				currpath->spec.ef_type.decoded.ef_rawdata = decode_bcd(
						currpath->spec.ef_type.ef_rawdata,
						currpath->spec.ef_type.ef_attr->file_size );
				break;
			case CODING_FIXEDRECORD: //XXX should rename this one
				currpath->spec.ef_type.decoded.ef_rawdata = decode_pl(
						currpath->spec.ef_type.ef_rawdata,
						currpath->spec.ef_type.ef_attr->file_size,
						kf->coding_info.record_len );
				break;
		}
		*/
	}
}
node_t * sim_brute_known( SIM_Context * ctx )
{
	int i,j, success;
	uint16_t sw;
	node_t * path_node, * tmp_node;
	known_file * kf;
	node_t * root = sim_populate_file( ctx, (node_t *)NULL, F_MASTER_FILE );
	for( i = 0; i < sizeof(known) / sizeof(known_file); i++ ) {
		kf = &known[i];
		printf("Processing: %s\r", kf->name );
		j = 0;
		success = TRUE;
		path_node = root;
		while( kf->path[j] != PATH_END ) {
			sw = sim_goto_file( ctx, kf->path[j] );
			if( check_flag( sw, SC_DF_SELECTED ) == FALSE ) {
				success = FALSE;
				break;
			}
			if( kf->path[j] != F_MASTER_FILE ) {
				tmp_node = node_get_child( path_node, kf->path[j] );
				if( tmp_node == NULL ) {
					tmp_node = sim_populate_file( ctx, path_node, kf->path[j] );
				}
				path_node = tmp_node;
			}
			j++;
		}
		if( success == FALSE ) continue;
	}
	sim_decode_known( root );
	return root;
}

void sim_brute_curdir( SIM_Context * ctx, node_t * curr )
{
	uint16_t test_file, sw;
	node_t * child, * parentfile;
	node_t * parents[128] = {0};
	int num_parents;
	int i = 0;
	printf("***Testing Directory: %04X\n", curr->file_id );
	//Walk parents backwards then forwards to select current directory
	if( curr->parent != NULL ) {
		parents[i] = curr->parent;
		while( parents[i]->parent ) {
			parents[i+1] = parents[i]->parent;
			i++;
		}
		num_parents = i;
		for( i = num_parents; i >= 0; i-- ) {
			sw = sim_goto_file( ctx, parents[i]->file_id );
			if( check_flag( sw, SC_DF_SELECTED ) == FALSE ) {
				dprintf("Bad Directory Selection");
			}
		}
	}
	sim_goto_file( ctx, curr->file_id );
	if( check_flag( sw, SC_DF_SELECTED ) == FALSE ) {
		dprintf("Bad Directory Selection");
	}
	printf("Testing Files:\n");
	for( test_file = 0; test_file < 0xFFFF; test_file++ ) {
		/*
		 * - the file ID shall be assigned at the time of creation of the file
		 * 	 concerned;
		 * - no two files under the same parent shall have the same ID;
		 * - a child and any parent, either immediate or remote in the
		 * 	 hierarchy, e.g. grandparent, shall never have the same file ID.
		 *
		 *
		 * Also:
		 *
		 * The following files may be selected, by File IDentifier (FID)
		 * referencing, from the last selected file:
		 * - any file which is an immediate child of the Current Directory;
		 * - any DF which is an immediate child of the parent of the current DF;
		 * - the parent of the Current Directory;
		 * - the current DF or ADF;
		 * - the MF
		 */
		printf("%04X\r", test_file );
		fflush(stdout);
		//We need to skip current directory if we come across it (MF currently)
		if( curr->parent != NULL ) {
			if( curr->parent->file_id == test_file ) {
				continue;
			}
			if( ( parentfile = node_get_child( curr->parent, test_file ) )
					!= NULL ) {
				if( parentfile->file_type == T_DF ) {
					continue;
				}
			}
		}
		if( curr->file_id == test_file || test_file == F_MASTER_FILE ) {
			continue;
		}
		child = sim_populate_file( ctx, curr, test_file );
		if( child == (node_t *)ERROR_RESULT ) {
			continue;
		}
		else {
			curr->num_children++;
			if( child->file_type == T_MF || child->file_type == T_DF ) {
				curr->spec.df_type.num_dirs++;
				//Since we slected a dir we need to go back to original
				if( curr->parent ) {
					printf("Resetting path: ");
					for( i = num_parents; i >= 0; i-- ) {
						printf("0x%04X ", parents[i]->file_id );
						sw = sim_goto_file( ctx, parents[i]->file_id );
						if( check_flag( sw, SC_DF_SELECTED ) == FALSE ) {
							dprintf("Bad directory selection");
						}
					}
				}
				else {
					printf("Resetting path: " );
				}
				printf("0x%04X\n", curr->file_id );
				sw = sim_goto_file( ctx, curr->file_id );
				if( check_flag( sw, SC_DF_SELECTED ) == FALSE ) {
					dprintf("Bad directory selection");
				}
			}
			else if( child->file_type == T_EF ){
				curr->spec.df_type.num_files++;
			}
			else {
				dprintf("Unsupported file type: 0x%02X for File: 0x%04X",
						child->file_type, child->file_id );
			}
		}
	}

	printf("\nFinished Brute Forcing: 0x%04X\n", curr->file_id );

	child = curr->first_child;
	while( child ) {
		if( child->file_type == T_MF || child->file_type == T_DF ) {
			printf("\tDir: 0x%04X\n", child->file_id );
		}
		else if( child->file_type == T_EF ) {
			printf("\tFile: 0x%04X\n", child->file_id );
		}
		else {
			printf("\tUnkn: 0x%04X\n", child->file_id );
		}
		child = child->next;
	}

	child = curr->first_child;
	while( child ) {
		if( child->file_type == T_MF || child->file_type == T_DF ) {
			sim_brute_curdir( ctx, child );
		}
		child = child->next;
	}
}

void dump_tree( node_t * currdf )
{
	dump_node( currdf );
	node_t * curr = currdf->first_child;
	while( curr ) {
		if( curr->file_type == T_DF || curr->file_type == T_MF ) {
			dump_tree( curr );
		}
		else {
			dump_node( curr );
		}
		curr = curr->next;
	}
	return;
}
node_t * sim_brute( SIM_Context * ctx )
{
	printf("\n\n");
	node_t * root;
	clock_t begin, end;

	root = sim_populate_file( ctx, (node_t *)NULL, F_MASTER_FILE );
	begin = clock();
	sim_brute_curdir( ctx, root );
	end = clock();
	printf("Time Elapsed: %f\n", (double)(end-begin)/CLOCKS_PER_SEC);
	return root;
}

char * decode_bcd( known_file * kf, uint8_t * data, int length )
{
	uint8_t * bcd;
	if( ( bcd = (uint8_t *)malloc(length) ) == NULL ) {
		perror("malloc()");
		return (char *)ERROR_RESULT;
	}
	memcpy( bcd, data, length );
	swap_byte_nibbles( bcd, length );

	char * bcd_ascii;
	if( ( bcd_ascii = (char *)calloc( length * 2 + 1, 1 ) ) == NULL ) {
		perror("calloc()");
		return (char *)ERROR_RESULT;
	}

	int i;
	for( i = 0; i < length; i++ ) {
		hex_to_ascii( bcd[i], bcd_ascii+(i*2) );
	}
	free(bcd);
	return bcd_ascii;
}

char * decode_pl( uint8_t * data, int data_len, int record_len )
{
	int rec_cnt = 0;
	uint8_t * tmpdata = data;
	while( *tmpdata != 0xFF ) {
		rec_cnt++;
		tmpdata += record_len;
	}

	char * pl_ascii;
	if( ( pl_ascii = calloc( rec_cnt, record_len+1 ) ) == NULL ) {
		perror("calloc()");
		return (char *)ERROR_RESULT;
	}

	int i;
	for( i = 0; i < rec_cnt; i++ ) {
		memcpy( pl_ascii+(record_len+1)*i, data+record_len*i, record_len );
		if( i+1 < rec_cnt ) *(pl_ascii+record_len*i+2) = ',';
	}

	return pl_ascii;
}
/*
 * ----------------------------------------------------------------------------
 * Known/Standard Files and Structures Retrieval Functions
 * ----------------------------------------------------------------------------
 */

/*
 * Retrieves and parses the contents of the unique identification number of this
 * SIM card.
 *
 * Parent: 3F00
 * File ID: 2FE2
 * Structure: Transparent
 * File Size: 10 bytes
 * Update activity: LOW
 *
 * Access Conditions:
 * READ		 	- ALWAYS
 * UPDATE 		- NEVER
 * INVALIDATE	- ADM
 * REHABILITATE	- ADM
 */

/*
node_t * sim_get_iccid( SIM_Context * ctx )
{
	node_t * file_stats;
	uint16_t sw;
	dprintf("Retrieving SIM ICCID");
	//First we check if we actually have this information in our node tree
	if( ( file_stats = sim_getfile_node( 2, F_MASTER_FILE, F_EF_ICCID ) )
			== NULL ) {

		sw = sim_goto_path( ctx, 2, F_MASTER_FILE, F_EF_ICCID );
		if( !check_flag( sw, SC_EF_SELECTED ) ) {
			dlprintf( 2, "Unable to follow path" );
			return (node_t *)ERROR_RESULT;
		}

		SC_APDU_Response sStatusResponse = {0};
		if( get_file_response( ctx, sw, &sStatusResponse ) == ERROR_RESULT ) {
			return (node_t *)ERROR_RESULT;
		}

		file_stats = node_new();
		parse_ef_node( file_stats, &mf_root,
				(EF_GSM_Response *)sStatusResponse.Data );
	}

	int file_size = file_stats->spec.ef_type.ef_attr->file_size;
	SC_APDU_Response sDataResp = {0};
	sDataResp.Data = calloc( file_size, 1 );
	if( sDataResp.Data == NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}
	if( sim_getfile_contents( ctx, file_stats->spec.ef_type.ef_attr,
			&sDataResp ) == ERROR_RESULT ) {
		return (node_t *)ERROR_RESULT;
	}
	uint8_t  * iccid = sDataResp.Data;
	swap_byte_nibbles( iccid, file_size );

	char * iccid_ascii;
	if( ( iccid_ascii = (char *)calloc( file_size * 2 + 1, 1 ) ) == NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}

	int i;
	for( i = 0; i < file_size; i++ ) {
		hex_to_ascii( iccid[i], iccid_ascii+(i*2) );
	}

	file_stats->spec.ef_type.ef_rawdata = iccid_ascii;

	dprintf( "ICCID = %s", iccid_ascii );
	free(iccid);
	return file_stats;
}
*/


/*
 * This function retrieves the Extended Language Preference of this SIM card.
 */
/*
node_t * sim_get_elp( SIM_Context * ctx )
{
	node_t * file_stats;
	uint16_t sw;
	dprintf("Retrieving SIM ELP");
	//First we check if we actually have this information in our node tree
	if( ( file_stats = sim_getfile_node( 2, F_MASTER_FILE, F_EF_ELP ) )
			== NULL ) {

		sw = sim_goto_path( ctx, 2, F_MASTER_FILE, F_EF_ELP );
		if( !check_flag( sw, SC_EF_SELECTED ) ) {
			dlprintf( 2, "Unable to follow path" );
			return (node_t *)ERROR_RESULT;
		}

		SC_APDU_Response sStatusResponse = {0};
		if( get_file_response( ctx, sw, &sStatusResponse ) == ERROR_RESULT ) {
			return (node_t *)ERROR_RESULT;
		}

		file_stats = node_new();
		parse_ef_node( file_stats, &mf_root,
				(EF_GSM_Response *)sStatusResponse.Data );
	}

	//If we've already read the data return it.
	if( file_stats->spec.ef_type.type != EMPTY ) {
		return file_stats;
	}

	int file_size = file_stats->spec.ef_type.ef_attr->file_size;
	SC_APDU_Response sDataResp = {0};
	sDataResp.Data = calloc( file_size, 1 );
	if( sDataResp.Data == NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}
	if( sim_getfile_contents( ctx, file_stats->spec.ef_type.ef_attr,
			&sDataResp ) == ERROR_RESULT ) {
		return (node_t *)ERROR_RESULT;
	}
	uint8_t  * epl = sDataResp.Data;

	//Count the number of records
	int i, cnt = 0;
	for( i = 0; i < file_size; i+=2 ) {
		if( *(epl+i) == 0xFF ) break;
		cnt++;
	}

	raw_records * records = (raw_records *)malloc( sizeof( raw_records ) );
	if( records == NULL ) {
		perror("malloc()");
		return (node_t *)ERROR_RESULT;
	}

	file_stats->spec.ef_type.type = RECORDS;
	file_stats->spec.ef_type.ef_records = records;
	records->num_records = cnt;
	records->record_size = 2;
	if( ( records->records = (char **)calloc( cnt, sizeof( char * ) ) )
			== NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}

	char * rec_buf = calloc( records->num_records, 3 ); //2+1 for null
	if( rec_buf == NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}
	char * rec_buf_tmp = rec_buf;
	for( i = 0; i < records->num_records; i++ ) {
		records->records[i] = rec_buf_tmp;
		*rec_buf_tmp++ = epl[i*2];
		*rec_buf_tmp++ = epl[i*2+1];
		*rec_buf_tmp++ = '\0';
	}

	dprintf( "Preferred Languages (In order of preference):" );
	for( i = 0; i < records->num_records; i++ ) {
		dprintf( "Record[%i]: %s", i+1, records->records[i] );
	}

	return file_stats;
}
*/


/*
 * Retrieves and parses the contents of the Abbreviated dialling numbers.
 *
 * Parents: 3F00, 7F10 (telecom)
 * File ID: 6F3A
 * Structure: Linear Fixed
 * Record Size: X+14
 * Update activity: LOW
 *
 * Access Conditions:
 * READ		 	- CHV1
 * UPDATE 		- CHV1
 * INVALIDATE	- CHV2
 * REHABILITATE	- CHV2
 */

/*
node_t * sim_get_adn( SIM_Context * ctx )
{
	node_t * file_stats;
	uint16_t sw;
	dprintf("Retrieving SIM ELP");
	//First we check if we actually have this information in our node tree
	if( ( file_stats = sim_getfile_node( 3, F_MASTER_FILE, F_DF_TELECOM,
			F_EF_ADN ) ) == NULL ) {

		sw = sim_goto_path( ctx, 3, F_MASTER_FILE, F_DF_TELECOM, F_EF_ADN );
		if( !check_flag( sw, SC_EF_SELECTED ) ) {
			dlprintf( 2, "Unable to follow path" );
			return (node_t *)ERROR_RESULT;
		}

		SC_APDU_Response sStatusResponse = {0};
		if( get_file_response( ctx, sw, &sStatusResponse ) == ERROR_RESULT ) {
			return (node_t *)ERROR_RESULT;
		}

		file_stats = node_new();
		parse_ef_node( file_stats, &mf_root,
				(EF_GSM_Response *)sStatusResponse.Data );
	}

	//If we've already read the data return it.
	if( file_stats->spec.ef_type.type != EMPTY ) {
		return file_stats;
	}

	int file_size = file_stats->spec.ef_type.ef_attr->file_size;
	SC_APDU_Response sDataResp = {0};
	sDataResp.Data = calloc( file_size, 1 );
	if( sDataResp.Data == NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}
	if( sim_getfile_contents( ctx, file_stats->spec.ef_type.ef_attr,
			&sDataResp ) == ERROR_RESULT ) {
		return (node_t *)ERROR_RESULT;
	}
	//XXX finish parsing this
	dprintf("Not Implemented yet");


	uint8_t  * adn = sDataResp.Data;
	int i;
	int rec_size = file_stats->spec.ef_type.ef_attr->length_of_record;

	raw_records * records = node_allocate_records( file_size / rec_size,
			rec_size );
	if( records == NULL ) {
		return (node_t *)ERROR_RESULT;
	}

	int j;
	for( i = 0; i < records->num_records; i++ ) {
		records->records[i] = adn+(i*rec_size);
		printf( "Record[%d] = ", i);
		for( j = 0; j < rec_size; j++ ) {
			printf( "%02X", (uint8_t)records->records[i][j] );
		}
		printf("\n");
	}

	return file_stats;
}
*/


/*
 * Retrieves and parses the contents of the Fixed Dialling Numbers.
 *
 * Parents: 3F00, 7F10 (telecom)
 * File ID: 6F3B
 * Structure: Linear Fixed
 * Record Size: X+14
 * Update activity: LOW
 *
 * Access Conditions:
 * READ		 	- CHV1
 * UPDATE 		- CHV1
 * INVALIDATE	- ADM
 * REHABILITATE	- ADM
 */
/*
node_t * sim_get_fdn( SIM_Context * ctx )
{
	node_t * file_stats;
	uint16_t sw;
	dprintf("Retrieving SIM ELP");
	//First we check if we actually have this information in our node tree
	if( ( file_stats = sim_getfile_node( 3, F_MASTER_FILE, F_DF_TELECOM,
			F_EF_FDN ) ) == NULL ) {

		sw = sim_goto_path( ctx, 3, F_MASTER_FILE, F_DF_TELECOM, 0x6F49 );
		if( !check_flag( sw, SC_EF_SELECTED ) ) {
			dlprintf( 2, "Unable to follow path" );
			return (node_t *)ERROR_RESULT;
		}

		SC_APDU_Response sStatusResponse = {0};
		if( get_file_response( ctx, sw, &sStatusResponse ) == ERROR_RESULT ) {
			return (node_t *)ERROR_RESULT;
		}

		file_stats = node_new();
		parse_ef_node( file_stats, &mf_root,
				(EF_GSM_Response *)sStatusResponse.Data );
	}

	//If we've already read the data return it.
	if( file_stats->spec.ef_type.type != EMPTY ) {
		return file_stats;
	}

	int file_size = file_stats->spec.ef_type.ef_attr->file_size;
	SC_APDU_Response sDataResp = {0};
	sDataResp.Data = calloc( file_size, 1 );
	if( sDataResp.Data == NULL ) {
		perror("calloc()");
		return (node_t *)ERROR_RESULT;
	}
	if( sim_getfile_contents( ctx, file_stats->spec.ef_type.ef_attr,
			&sDataResp ) == ERROR_RESULT ) {
		return (node_t *)ERROR_RESULT;
	}
	//XXX finish parsing this
	dprintf("Not Implemented yet");


	uint8_t  * adn = sDataResp.Data;
	int i;
	int rec_size = file_stats->spec.ef_type.ef_attr->length_of_record;

	raw_records * records = node_allocate_records( file_size / rec_size,
			rec_size );
	if( records == NULL ) {
		return (node_t *)ERROR_RESULT;
	}

	int j;
	for( i = 0; i < records->num_records; i++ ) {
		records->records[i] = adn+(i*rec_size);
		printf( "Record[%d] = ", i);
		for( j = 0; j < rec_size; j++ ) {
			printf( "%c", (uint8_t)records->records[i][j] );
		}
		printf("\n");
	}

	return file_stats;
}
*/
