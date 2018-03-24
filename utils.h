#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

unsigned int _copy(uint8_t *to, unsigned int to_len, 
	const uint8_t *from, unsigned int from_len);

void printb(const uint8_t *bytes, unsigned short length);

void _set(void *to, uint8_t val, unsigned int len);

uint8_t _double_byte(uint8_t a);

int _compare(const uint8_t *a, const uint8_t *b, size_t size);

#endif
