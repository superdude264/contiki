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
 *         Preloads the cryptographic material of LEAP.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "dev/leds.h"
#include "dev/watchdog.h"
#include "sys/node-id.h"
#include "sys/etimer.h"
#include "lib/prng.h"
#include "net/llsec/coresec/leap.h"
#include <stdio.h>
#include <string.h>

static struct etimer etimer;

/*---------------------------------------------------------------------------*/
static void
preload(void)
{
  uint8_t data[sizeof(node_id) + PRNG_SEED_LEN + LEAP_MASTER_KEY_LEN]
      = { 0x00 , 0x00 ,
          0xAA , 0xAA , 0xAA , 0xAA ,
          0xBB , 0xBB , 0xBB , 0xBB ,
          0xCC , 0xCC , 0xCC , 0xCC ,
          0xDD , 0xDD , 0xDD , 0xDD ,
          
          0x11 , 0x11 , 0x11 , 0x11 ,
          0x22 , 0x22 , 0x22 , 0x22 ,
          0x33 , 0x33 , 0x33 , 0x33 ,
          0x44 , 0x44 , 0x44 , 0x44 };
  
  memcpy(data, &node_id, sizeof(node_id));
  node_id_burn_data(data, sizeof(node_id) + PRNG_SEED_LEN + LEAP_MASTER_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
static void
restore(void)
{
  uint8_t i;
  unsigned char seed[PRNG_SEED_LEN];
  unsigned char master_key[LEAP_MASTER_KEY_LEN];
  
  node_id_restore();
  printf("Restored node id: 0x%04X\n", node_id);
  
  node_id_restore_data(seed, PRNG_SEED_LEN, NODE_ID_SEED_OFFSET);
  printf("Restored seed: ");
  for(i = 0; i < PRNG_SEED_LEN; i++) {
    printf("%X", seed[i]);
  }
  printf("\n");
  
  node_id_restore_data(master_key, LEAP_MASTER_KEY_LEN, NODE_ID_KEYING_MATERIAL_OFFSET);
  printf("Restored master key: ");
  for(i = 0; i < LEAP_MASTER_KEY_LEN; i++) {
    printf("%X", master_key[i]);
  }
  printf("\n");
}
/*---------------------------------------------------------------------------*/
PROCESS(preload_process, "Preload process");
AUTOSTART_PROCESSES(&preload_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(preload_process, ev, data)
{
  PROCESS_BEGIN();

  etimer_set(&etimer, 5*CLOCK_SECOND);
  PROCESS_WAIT_UNTIL(etimer_expired(&etimer));

  watchdog_stop();
  leds_on(LEDS_RED);
  
  preload();
  
  leds_on(LEDS_BLUE);
  
  restore();
  
  leds_off(LEDS_RED + LEDS_BLUE);
  watchdog_start();
  while(1) {
    PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
