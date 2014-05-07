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
 *         Localized Encryption and Authentication Protocol (LEAP).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/leap.h"
#include "sys/node-id.h"
#include "lib/aes-128.h"
#include <string.h>

#define INDIVIDUAL_KEY_LEN              (LEAP_MASTER_KEY_LEN)

/* Cryptographic material */
static uint8_t master_key[LEAP_MASTER_KEY_LEN];
static uint8_t individual_key[INDIVIDUAL_KEY_LEN];
/* Used for decrypting and verifying HELLOACKs */
static uint8_t temporary_individual_key[INDIVIDUAL_KEY_LEN];
static int erased;

/*---------------------------------------------------------------------------*/
static void
generate_individual_key(uint8_t *individual_key, const linkaddr_t *address)
{
  AES_128.set_key(master_key);
  memset(individual_key, 0, INDIVIDUAL_KEY_LEN);
  memcpy(individual_key, address->u8, sizeof(linkaddr_t));
  aes_128_padded_encrypt(individual_key, INDIVIDUAL_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
static uint8_t *
get_secret_with_hello_sender(struct neighbor_ids *ids)
{
  return individual_key;
}
/*---------------------------------------------------------------------------*/
static uint8_t *
get_secret_with_helloack_sender(struct neighbor_ids *ids)
{
  if(erased) {
    return NULL;
  }
  
  generate_individual_key(temporary_individual_key, &ids->extended_addr);
  
  return temporary_individual_key;
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  node_id_restore_data(master_key, LEAP_MASTER_KEY_LEN, NODE_ID_KEYING_MATERIAL_OFFSET);
  node_id_erase_data();
  generate_individual_key(individual_key, &linkaddr_node_addr);
}
/*---------------------------------------------------------------------------*/
static void
on_done(void)
{
  memset(master_key, 0, LEAP_MASTER_KEY_LEN);
  memset(temporary_individual_key, 0, INDIVIDUAL_KEY_LEN);
  erased = 1;
}
/*---------------------------------------------------------------------------*/
const struct apkes_scheme leap_apkes_scheme = {
  init,
  get_secret_with_hello_sender,
  get_secret_with_helloack_sender,
  on_done
};
/*---------------------------------------------------------------------------*/

/** @} */
