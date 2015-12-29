#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cn-cbor/cn-cbor.h>

#include "json.h"

const cn_cbor * ParseString(char * rgch, int ib, int cch)
{
	char ch;
	int ib2;
	cn_cbor * node = NULL;
	cn_cbor * parent = NULL;
	cn_cbor * root = NULL;

	for (; ib < cch; ib++) {
		node = NULL;
		ch = rgch[ib];
		switch (ch) {
		case '{':
			node = cn_cbor_map_create(NULL, NULL);
			break;

		case '}':
			parent = parent->parent;
			break;

		case '[':
			node = cn_cbor_array_create(NULL, NULL);
			break;

		case ']':
			parent = parent->parent;
			break;

		case ' ':
		case '\r':
		case '\n':
		case':':
		case ',':
			break;

		case '"':
			for (ib2 = ib + 1; ib2 < cch; ib2++) if (rgch[ib2] == '"') break;
			rgch[ib2] = 0;
			node = cn_cbor_string_create(&rgch[ib+1], NULL, NULL);
			rgch[ib2] = '"';
			ib = ib2;
			break;

		default:
			fprintf(stderr, "Parse failure @ '%s'\n", &rgch[ib]);
			break;
		}

		if ((node != NULL) && (parent != NULL)) {
			node->parent = parent;
			if (parent->last_child != NULL) {
				parent->last_child->next = node;
				parent->last_child = node;
			}
			else {
				parent->first_child = node;
			}
			parent->last_child = node;
			parent->length++;

			if ((node->type == CN_CBOR_MAP) || (node->type == CN_CBOR_ARRAY)) {
				parent = node;
			}
		}
		if (parent == NULL) {
			parent = node;
			if (root == NULL) root = node;
		}
	}

	return root;
}

const cn_cbor * ParseJson(char * fileName)
{
	int     cch;
	char	rgch[8 * 1024];
    FILE * fp = fopen(fileName, "r");

	if (fp == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", fileName);
		exit(1);
	}

	cch = fread(rgch, 1, sizeof(rgch), fp);
	fclose(fp);

	return ParseString(rgch, 0, cch);
}
