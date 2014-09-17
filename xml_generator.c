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
#include <stdio.h>
#include "xml_generator.h"
#include "apdu_proto.h"
#include "include.h"

FILE * fxml;
int setup_file( char * filepath )
{
	if( ( fxml = (FILE *)fopen( filepath, "w" ) ) < 0 ) {
		perror("open()");
		exit(1);
	}
	return TRUE;
}

void print_permissions( uint8_t perm )
{
	if( perm == 0 ) {
		fprintf( fxml, "ALW" );
	}
	else if( perm == 15 ) {
		fprintf( fxml, "NEV" );
	}
	else {
		fprintf( fxml, "PIN%d", perm );
	}
}

int dump_dir( node_t * dir ) {
	fprintf( fxml, "<df id=\"%04X\" numchildren=\"%X\"", dir->file_id,
			dir->num_children );
	if( dir->name != NULL ) {
		fprintf( fxml, " name=\"%s\"", dir->name );
	}
	if( dir->description != NULL ) {
		fprintf( fxml, " descr=\"%s\"", dir->description );
	}
	fprintf( fxml, ">" );
	if( dir->parent ) {
		fprintf( fxml, "<parent>%04X</parent>", dir->parent->file_id );
	}
	fprintf( fxml,
			"<numfiles>%X</numfiles>"
			"<numdirs>%X</numdirs>",
			dir->spec.df_type.num_files,
			dir->spec.df_type.num_dirs );
	fprintf( fxml, "<attributes>");
	DF_GSM_Response * attr = dir->spec.df_type.df_attr;
	fprintf( fxml, "<type>%02X</type>"
			"<numfiles>%X</numfiles>"
			"<numfolders>%X</numfolders>"
			"<freemem>%04X</freemem>"
			"<chv1>"
			"<status>%s</status>"
			"<initialized>%s</initialized>"
			"<triesleft>%d</triesleft>"
			"</chv1>"
			"<chv2>"
			"<initialized>%s</initialized>"
			"<triesleft>%d</triesleft>"
			"</chv2>"
			"<unlockchv1>"
			"<initialized>%s</initialized>"
			"<triesleft>%d</triesleft>"
			"</unlockchv1>"
			"<unlockchv2>"
			"<initialized>%s</initialized>"
			"<triesleft>%d</triesleft>"
			"</unlockchv2>"
			"<numcodes>%d</numcodes>",
			attr->type,
			dir->spec.df_type.num_files,
			dir->spec.df_type.num_dirs,
			attr->mem_free,
			( ( CHV1_DISABLED( attr->characteristics ) ) ? "DISABLED" : "ENABLED" ),
			( ( GET_CHV_INITIALIZED( attr->chv1_status ) ) ? "TRUE" : "FALSE" ),
			GET_CHV_REMAINING( attr->chv1_status ),
			( ( GET_CHV_INITIALIZED( attr->chv2_status ) ) ? "TRUE" : "FALSE" ),
			GET_CHV_REMAINING( attr->chv2_status ),
			( ( GET_CHV_INITIALIZED( attr->uchv1_status ) ) ? "TRUE" : "FALSE" ),
			GET_CHV_REMAINING( attr->uchv1_status ),
			( ( GET_CHV_INITIALIZED( attr->uchv2_status ) ) ? "TRUE" : "FALSE" ),
			GET_CHV_REMAINING( attr->uchv2_status ),
			attr->ncodes
			);
	//fprintf
	//dir->spec.df_type.num_dirs
	fprintf( fxml, "</attributes>" );
	fprintf( fxml, "<children>");
	node_t * child = dir->first_child;
	raw_records * rdata;
	char * tmp;
	int i,j;
	while( child ) {
		if( child->file_type == T_EF ) {
			EF_GSM_Response * efattr = child->spec.ef_type.ef_attr;
			fprintf( fxml, "<ef id=\"%04X\"", child->file_id );
			if( child->name != NULL ) {
				fprintf( fxml, "name=\"%s\" ", child->name );
			}
			if( child->description != NULL ) {
				fprintf( fxml, "descr=\"%s\"", child->description );
			}
			fprintf( fxml, ">" );
			fprintf( fxml, "<attributes>");
			fprintf( fxml,
					"<size>%04X</size>"
					"<type>%02X</type>"
					//"<increaseallowed>%s</increaseallowed>"
					"<invalidated><status>%s</status><readable>%s</readable></invalidated>",
					//"<structure>%s</structure>",
					efattr->file_size,
					efattr->type,
					( IS_INVALIDATED( efattr->status ) ? "TRUE" : "FALSE" ),
					( READABLE_IF_INVALIDATED( efattr->status ) ? "TRUE" : "FALSE" )
					);
			fprintf( fxml, "<permissions>");
			fprintf( fxml, "<read>");
			print_permissions( GET_HIGH4( efattr->access[0] ) );
			fprintf( fxml, "</read>" );
			fprintf( fxml, "<update>");
			print_permissions( GET_LOW4( efattr->access[0] ) );
			fprintf( fxml, "</update>" );
			fprintf( fxml, "<increase>");
			print_permissions( GET_HIGH4( efattr->access[1] ) );
			fprintf( fxml, "</increase>" );
			fprintf( fxml, "<rehabilitate>");
			print_permissions( GET_HIGH4( efattr->access[2] ) );
			fprintf( fxml, "</rehabilitate>" );
			fprintf( fxml, "<invalidate>");
			print_permissions( GET_HIGH4( efattr->access[2] ) );
			fprintf( fxml, "</invalidate>" );
			fprintf( fxml, "</permissions>");
			switch( efattr->ef_structure ) {
				case EF_TRANSPARENT:
					fprintf( fxml, "<structure>TRANSPARENT</structure>");
					break;
				case EF_LINEAR:
					fprintf( fxml,
							"<structure>LINEAR</structure>"
							"<recordlength>%02X</recordlength>",
							efattr->length_of_record
							);
				case EF_CYCLIC:
					fprintf( fxml,
							"<structure>CYCLIC</structure>"
							"<recordlength>%02X</recordlength>"
							"<increaseallowed>%s</increaseallowed>",
							efattr->length_of_record,
							( INCREASE_ALLOWED( efattr->increase_allowed ) ? "TRUE" : "FALSE" )
							);
			}
			fprintf( fxml, "</attributes>" );
			fprintf( fxml, "<contents>" );
			switch( child->spec.ef_type.type ) {
				case EMPTY:
					fprintf( fxml, "<type>EMPTY</type>");
					break;
				case RAW:
					fprintf( fxml, "<type>RAW</type>");
					fprintf( fxml, "<data>");
					tmp = (char *)child->spec.ef_type.ef_rawdata;
					for( i = 0; i < child->spec.ef_type.ef_attr->file_size; i++ ) {
						fprintf( fxml, "%02X", (uint8_t)tmp[i] );
					}
					fprintf( fxml, "</data>");
					if( child->spec.ef_type.decoded.ef_rawdata != NULL ) {
						fprintf( fxml, "<decoded>%s</decoded>",
								child->spec.ef_type.decoded.ef_rawdata );
					}
					break;
				case RECORDS:
					rdata = child->spec.ef_type.ef_records;
					fprintf( fxml, "<type>RECORDS</type>");
					fprintf( fxml,
							"<numrecords>%X</numrecords>"
							"<recordsize>%X</recordsize>",
							rdata->num_records,
							rdata->record_size
							);
					fprintf( fxml, "<data>");
					for( i = 0; i < rdata->num_records; i++ ) {
						tmp = rdata->records[i];
						fprintf( fxml, "<record id=\"%d\">", i+1 );
						for( j = 0; j < rdata->record_size; j++ ) {
							fprintf( fxml, "%02X", (uint8_t)tmp[j] );
						}
						fprintf( fxml, "</record>" );
					}
					fprintf( fxml, "</data>");
					break;
			}
			fprintf( fxml, "</contents>");
			fprintf( fxml, "</ef>" );
		}
		else if( child->file_type == T_DF ) {
			dump_dir( child );
		}
		else {
			printf("ERROR: Unknown type: %X", child->file_type );
		}
		child = child->next;
	}
	fprintf( fxml, "</children>");
	fprintf( fxml, "</df>" );
	return TRUE;
}

int generate_document( node_t * root )
{
	dump_dir( root );
	return 1;
}
