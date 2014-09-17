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
#include "node.h"
#include "include.h"

node_bucket root = {0};
node_bucket * bucket = NULL;

int node_init()
{
	if( ( root.buffer = (uint8_t *)calloc(
			DEFAULT_ALLOC, sizeof(node_t) ) ) == NULL ) {
		return FALSE;
	}
	root.total_items = DEFAULT_ALLOC;
	root.num_used = 0;
	bucket = &root;
	return TRUE;
}

void node_kill()
{
	if( root.total_items == 0 || root.buffer == NULL ) return;
	node_bucket * curr = bucket;
	node_bucket * tmp = bucket;

	while( curr ) {
		tmp = curr->prev;
		if( curr->total_items != 0 && curr->buffer != NULL ) {
			free(curr->buffer);
		}
		if( curr != &root ) {
			free(curr);
		}
		curr = tmp;
	}
}

node_t * node_new()
{
	if( bucket->total_items == 0 ) return NULL;

	node_t * new;
	if( bucket->num_used == bucket->total_items ) {
		uint8_t *new_buf;

		//Allocate new bucket structure and populate
		node_bucket * newbucket;
		if( ( newbucket = calloc( 1, sizeof(node_bucket) ) ) == NULL ) {
			perror("calloc()");
			return NULL;
		}
		newbucket->prev = bucket;
		int len_new = bucket->total_items * 2;
		if( (new_buf = (uint8_t *)calloc( len_new, sizeof(node_t) )) == NULL ) {
			return NULL;
		}
		newbucket->total_items = len_new;
		newbucket->num_used = 0;
		newbucket->buffer = new_buf;
		bucket = newbucket;
	}
	new = (node_t *)( bucket->buffer + sizeof(node_t) * bucket->num_used );
	bucket->num_used++;
	return new;
}

void node_add_child( node_t * node, node_t * child )
{
	node_t * curr;
	if( child == NULL || node == NULL ) {
		dlprintf( 3, "NULL given" );
		return;
	}

	if( node->first_child == NULL ) {
		node->num_children = 1;
		node->first_child = child;
		return;
	}
	else if( node->last_child == NULL ) {
		curr = node->first_child;
		while( curr->next ) {
			curr = curr->next;
		}
	}
	else {
		curr = node->last_child;
	}
	curr->next = child;
	child->prev = curr;
	node->last_child = child;
	node->num_children++;
	return;
}

int is_parent( node_t * node, uint16_t file_id )
{
	uint16_t this_id = node->file_id;
	while( node->parent ) {
		if( this_id == node->file_id ) {
			return TRUE;
		}
		node = node->parent;
	}
	return FALSE;
}

node_t * node_get_child( node_t * node, uint16_t file_id )
{
	if( node == NULL ) return NULL;
	if( node->num_children == 0 ) return NULL;
	if( node->first_child == NULL ) {
		dlprintf( 3, "Node with children has NULL first child" );
		return NULL;
	}
	node_t * curr = node->first_child;
	while( curr ) {
		if( curr->file_id == file_id ) return curr;
		curr = curr->next;
	}
	return NULL;
}

raw_records * node_allocate_records( int num_records, int record_size )
{
	raw_records * rec;
	if( ( rec = calloc( sizeof(raw_records), 1 ) ) == NULL ) {
		perror("calloc()");
		return NULL;
	}

	rec->num_records = num_records;
	rec->record_size = record_size;
	if( ( rec->records = calloc( num_records, sizeof(char *) ) ) == NULL ) {
		perror("calloc()");
		return NULL;
	}
	return rec;
}
