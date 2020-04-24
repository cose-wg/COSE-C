#pragma once

const cn_cbor* ParseJson(const char* fileName);
unsigned char* base64_decode(const char* data,
	size_t input_length,
	size_t* output_length);
unsigned char* hex_decode(const char* data,
	size_t input_length,
	size_t* output_length);
