/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Utility to store a node id in the external flash
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "sys/node-id.h"
#include "contiki-conf.h"
#include "dev/xmem.h"
#include <string.h>

#define CHECK_LEN 2

unsigned short node_id = 0;
static const unsigned char check[CHECK_LEN] = { 0xad , 0xde };

/*---------------------------------------------------------------------------*/
void
node_id_restore(void)
{
  unsigned char buf[CHECK_LEN];
  xmem_pread(buf, CHECK_LEN, NODE_ID_XMEM_OFFSET);
  
  if(memcmp(buf, check, CHECK_LEN)) {
    node_id = 0;
  } else {
    node_id_restore_data(&node_id, sizeof(node_id), NODE_ID_OFFSET);
  }
}
/*---------------------------------------------------------------------------*/
void
node_id_burn(unsigned short id)
{
  node_id_burn_data(&id, sizeof(id));
}
/*---------------------------------------------------------------------------*/
void
node_id_burn_data(void *data, unsigned short data_len)
{
  node_id_erase_data();
  xmem_pwrite(check, CHECK_LEN, NODE_ID_XMEM_OFFSET);
  xmem_pwrite(data, data_len, NODE_ID_XMEM_OFFSET + CHECK_LEN);
}
/*---------------------------------------------------------------------------*/
void
node_id_restore_data(void *result,
    unsigned short result_len,
    unsigned short offset)
{
  xmem_pread(result, result_len, NODE_ID_XMEM_OFFSET + CHECK_LEN + offset);
}
/*---------------------------------------------------------------------------*/
void
node_id_erase_data(void)
{
  xmem_erase(XMEM_ERASE_UNIT_SIZE, NODE_ID_XMEM_OFFSET);
}
/*---------------------------------------------------------------------------*/
