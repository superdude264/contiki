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
 *         Neighbor management for compromise-resilient LLSEC drivers.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/neighbor.h"
#include "net/llsec/coresec/apkes.h"
#include "net/llsec/anti-replay.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/packetbuf.h"
#include "sys/etimer.h"
#include <string.h>

#ifdef NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL
#define UPDATE_CHECK_INTERVAL NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL
#else /* NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL */
#define UPDATE_CHECK_INTERVAL (60 * 5)
#endif /* NEIGHBOR_CONF_UPDATE_CHECK_INTERVAL */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

MEMB(neighbors_memb, struct neighbor, NEIGHBOR_MAX);
LIST(neighbor_list);
#if NEIGHBOR_SEND_UPDATES
PROCESS(update_check_process, "update_check_process");
#endif /* NEIGHBOR_SEND_UPDATES */

/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_head(void)
{
  return list_head(neighbor_list);
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_next(struct neighbor *previous)
{
  return list_item_next(previous);
}
/*---------------------------------------------------------------------------*/
static void
add(struct neighbor *new_neighbor)
{
  struct neighbor *current;
  struct neighbor *next;
  
  current = list_head(neighbor_list);
  
  if(!current) {
    new_neighbor->local_index = 0;
    list_add(neighbor_list, new_neighbor);
  } else {
    while(((next = list_item_next(current)))) {
      if((next->local_index - current->local_index) > 1) {
        break;
      }
      current = next;
    }
    new_neighbor->local_index = current->local_index + 1;
    list_insert(neighbor_list, current, new_neighbor);
  }
}
/*---------------------------------------------------------------------------*/
static void
remove_expired_tentatives(void)
{
  struct neighbor *next;
  struct neighbor *to_be_removed_neighbor;
  
  next = list_head(neighbor_list);
  while(next) {
    if(next->expiration_time <= clock_seconds()) {
      to_be_removed_neighbor = next;
      next = list_item_next(next);
      neighbor_remove(to_be_removed_neighbor);
    } else {
      next = list_item_next(next);
    }
  }
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_new(void)
{
  struct neighbor *new_neighbor;
  
  remove_expired_tentatives();
  new_neighbor = memb_alloc(&neighbors_memb);
  if(!new_neighbor) {
    PRINTF("neighbor: ERROR\n");
    return NULL;
  }
  add(new_neighbor);
  return new_neighbor;
}
/*---------------------------------------------------------------------------*/
struct neighbor *
neighbor_get(const linkaddr_t *extended_addr)
{
  struct neighbor *next;
  
  next = list_head(neighbor_list);
  while(next) {
    if(linkaddr_cmp(&next->ids.extended_addr, extended_addr)) {
      return next;
    }
    next = list_item_next(next);
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
neighbor_update_ids(struct neighbor_ids *ids, void *short_addr)
{
  memcpy(ids->extended_addr.u8,
      packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8,
      sizeof(linkaddr_t));
  memcpy(&ids->short_addr, short_addr, NEIGHBOR_SHORT_ADDR_LEN);
}
/*---------------------------------------------------------------------------*/
void
neighbor_update(struct neighbor *neighbor, uint8_t *data)
{
  anti_replay_init_info(&neighbor->anti_replay_info);
  neighbor->status = NEIGHBOR_PERMANENT;
  neighbor->foreign_index = data[0];
#if NEIGHBOR_SEND_UPDATES
  stimer_set(&neighbor->update_timer, data[1] * 60);
#endif /* NEIGHBOR_SEND_UPDATES */
#if NEIGHBOR_BROADCAST_KEY_LEN
  memcpy(&neighbor->broadcast_key, data + 2, NEIGHBOR_BROADCAST_KEY_LEN);
#endif /* NEIGHBOR_BROADCAST_KEY_LEN */
  
#if DEBUG
  {
    uint8_t i;
    
    PRINTF("neighbor: Neighbor %04X:\n", neighbor->ids.short_addr);
    PRINTF("neighbor: Foreign index: %i Local index: %i\n", neighbor->foreign_index, neighbor->local_index);
#if NEIGHBOR_SEND_UPDATES
    PRINTF("neighbor: Expires within %lumin\n", neighbor->update_timer.interval / 60);
#endif /* NEIGHBOR_SEND_UPDATES */
    
#if NEIGHBOR_BROADCAST_KEY_LEN
    PRINTF("neighbor: Broadcast key: ");
    for(i = 0; i < NEIGHBOR_BROADCAST_KEY_LEN; i++) {
      PRINTF("%x", neighbor->broadcast_key[i]);
    }
    PRINTF("\n");
#endif /* NEIGHBOR_BROADCAST_KEY_LEN */
    
    PRINTF("neighbor: Pairwise key: ");
    for(i = 0; i < NEIGHBOR_PAIRWISE_KEY_LEN; i++) {
      PRINTF("%x", neighbor->pairwise_key[i]);
    }
    PRINTF("\n");
  }
#endif /* DEBUG */
}
/*---------------------------------------------------------------------------*/
void
neighbor_remove(struct neighbor *neighbor)
{
  list_remove(neighbor_list, neighbor);
  memb_free(&neighbors_memb, neighbor);
}
/*---------------------------------------------------------------------------*/
void
neighbor_init(void)
{
  memb_init(&neighbors_memb);
  list_init(neighbor_list);
#if NEIGHBOR_SEND_UPDATES
  process_start(&update_check_process, NULL);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(update_check_process, ev, data)
{
  static struct etimer update_check_timer;
  struct neighbor *next;
  
  PROCESS_BEGIN();
  
  PRINTF("neighbor: started update_check_process\n");
  etimer_set(&update_check_timer, UPDATE_CHECK_INTERVAL * CLOCK_SECOND);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&update_check_timer));
    
    next = list_head(neighbor_list);
    while(next) {
      if(!stimer_expired(&next->update_timer)
          && (stimer_remaining(&next->update_timer) <= UPDATE_CHECK_INTERVAL + 20)) {
        apkes_send_update(next);
      }
      next = list_item_next(next);
    }
    
    etimer_reset(&update_check_timer);
  }
  
  PROCESS_END();
#endif /* NEIGHBOR_SEND_UPDATES */
}
/*---------------------------------------------------------------------------*/
void
neighbor_on_got_updated(struct neighbor *sender)
{
  sender->expiration_time = clock_seconds() + NEIGHBOR_EXPIRATION_INTERVAL * 60;/*
  PRINTF("neighbor: Awaiting UPDATE (or another frame) in %imin\n", NEIGHBOR_EXPIRATION_INTERVAL);*/
}
/*---------------------------------------------------------------------------*/
#if NEIGHBOR_SEND_UPDATES
void
neighbor_on_updated(struct neighbor *receiver)
{
  stimer_restart(&receiver->update_timer);/*
  PRINTF("neighbor: Next UPDATE in %lumin\n", stimer_remaining(&receiver->update_timer) / 60);*/
}
#endif /* NEIGHBOR_SEND_UPDATES */
/*---------------------------------------------------------------------------*/

/** @} */
