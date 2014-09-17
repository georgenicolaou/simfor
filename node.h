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
#ifndef NODE_H_
#define NODE_H_
#include <stdint.h>
#include "apdu_proto.h"

/*
 * Internal Stuff -------------------------------------------------------------
 */
#define DEFAULT_ALLOC 200

typedef struct _node_bucket {
	int total_items;
	int num_used;
	uint8_t * buffer;
	struct _node_bucket * prev;
} node_bucket;

/*
 * Exported stuff -------------------------------------------------------------
 */

typedef enum {
	EMPTY,
	RAW,
	RECORDS
} ef_datatype;

typedef struct {
	int num_records;
	int record_size;
	char ** records;
} raw_records;

typedef struct _node_t {
	uint16_t file_id;
	char * name;
	char * description;
	uint8_t file_type; //Copy of type field replied by SIM
	int num_children;
	struct _node_t * parent;
	union {
		struct {
			int num_dirs;
			int num_files;
			DF_GSM_Response * df_attr;
		} df_type;
		struct {
			ef_datatype type;
			union {
				uint8_t * ef_rawdata;
				raw_records * ef_records;
			};
			union { //XXX add md5/sha1 signatures for data?
				uint8_t * ef_rawdata;
				raw_records * ef_records;
			} decoded;
			EF_GSM_Response * ef_attr;
		} ef_type;
	} spec;
	//Directory's first and last childs
	struct _node_t * first_child;
	struct _node_t * last_child;

	//Childrens chain
	struct _node_t * next;
	struct _node_t * prev;
} node_t;

int node_init();
void node_kill();
node_t * node_new();
void node_add_child( node_t * node, node_t * child );
node_t * node_get_child( node_t * node, uint16_t file_id );
raw_records * node_allocate_records( int num_records, int record_size );
int is_parent( node_t * node, uint16_t file_id );
#endif /* NODE_H_ */
