/**
 * \addtogroup coresec
 * @{
 */

/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
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
 *         Fully pairwise keys.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/fully.h"
#include "sys/node-id.h"
#include "lib/aes-128.h"
#include <string.h>

static uint8_t key[AES_128_BLOCK_SIZE];

/*---------------------------------------------------------------------------*/
//TODO: look further at this function...
static uint8_t *
get_secret_with(struct neighbor_ids *ids)
{
  if(ids->short_addr >= FULLY_MAX_NODES) {
    return NULL;
  }
  node_id_restore_data(key,
      AES_128_BLOCK_SIZE,
      NODE_ID_KEYING_MATERIAL_OFFSET + ids->short_addr * AES_128_BLOCK_SIZE);
  
  return key;
}
/*---------------------------------------------------------------------------*/
//TODO: see where this used (presumably when compromised nodes need to be ignored)
static void
ignore(void)
{
  
}
/*---------------------------------------------------------------------------*/
const struct apkes_scheme fully_apkes_scheme = {
  ignore,
  get_secret_with,
  get_secret_with
};
/*---------------------------------------------------------------------------*/

/** @} */
