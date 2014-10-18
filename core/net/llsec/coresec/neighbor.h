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

#ifndef NEIGHBOR_H_
#define NEIGHBOR_H_

#include "net/llsec/llsec802154.h"
#include "net/llsec/anti-replay.h"
#include "net/linkaddr.h"
#include "net/nbr-table.h"
#include "sys/clock.h"
#include "sys/stimer.h"

#ifdef NEIGHBOR_CONF_MAX
#define NEIGHBOR_MAX                    NEIGHBOR_CONF_MAX
#else /* NEIGHBOR_CONF_MAX */
#define NEIGHBOR_MAX                    NBR_TABLE_MAX_NEIGHBORS
#endif /* NEIGHBOR_CONF_MAX */

#ifdef NEIGHBOR_CONF_BROADCAST_KEY_LEN
#define NEIGHBOR_BROADCAST_KEY_LEN      NEIGHBOR_CONF_BROADCAST_KEY_LEN
#else /* NEIGHBOR_CONF_BROADCAST_KEY_LEN */
#define NEIGHBOR_BROADCAST_KEY_LEN      0
#endif /* NEIGHBOR_CONF_BROADCAST_KEY_LEN */

#ifdef NEIGHBOR_CONF_PAIRWISE_KEY_LEN
#define NEIGHBOR_PAIRWISE_KEY_LEN       NEIGHBOR_CONF_PAIRWISE_KEY_LEN
#else /* NEIGHBOR_CONF_PAIRWISE_KEY_LEN */
#define NEIGHBOR_PAIRWISE_KEY_LEN       16
#endif /* NEIGHBOR_CONF_PAIRWISE_KEY_LEN */

#ifdef NEIGHBOR_CONF_EXPIRATION_INTERVAL
#define NEIGHBOR_EXPIRATION_INTERVAL    NEIGHBOR_CONF_EXPIRATION_INTERVAL
#else /* NEIGHBOR_CONF_EXPIRATION_INTERVAL */
#define NEIGHBOR_EXPIRATION_INTERVAL    60
#endif /* NEIGHBOR_CONF_EXPIRATION_INTERVAL */

#ifdef NEIGHBOR_CONF_SEND_UPDATES
#define NEIGHBOR_SEND_UPDATES           NEIGHBOR_CONF_SEND_UPDATES
#else /* NEIGHBOR_CONF_SEND_UPDATES */
#define NEIGHBOR_SEND_UPDATES           1
#endif /* NEIGHBOR_CONF_SEND_UPDATES */

#define NEIGHBOR_SHORT_ADDR_LEN         2

struct neighbor_ids {
  
  /** TODO We assume a LoWPAN-wide PAN-ID */
  /* uint16_t pan_id; */
  
  /** TODO We assume that this is always an extended address */
  linkaddr_t extended_addr;
  
  uint16_t short_addr;
};

enum neighbor_status {
  NEIGHBOR_PERMANENT = 0,
  /** Tentative <-> no ACK received so far */
  NEIGHBOR_TENTATIVE,
  NEIGHBOR_AWAITING_ACK
};

/**
 * Neighbor data - keys are set by apkes_schemes
 */
struct neighbor {
  struct neighbor *next;
  
  struct neighbor_ids ids;
  
  enum neighbor_status status;
  
  /** Index of this neighbor */
  uint8_t local_index;
  
  /** Index on the neighboring node (permanent neighbors only) */
  uint8_t foreign_index;
  
#if NEIGHBOR_SEND_UPDATES
  /** 
   * This is when we will send an UPDATE command (unless we send
   * a unicast to this neighbor beforehand).
   */
  struct stimer update_timer;
#endif /* NEIGHBOR_SEND_UPDATES */
  
  /**
   * This is when this neighbor is removed (unless an authentic
   * frame or an UPDATE command arrives beforehand.)
   */
  unsigned long expiration_time;
    
  /** Anti-replay information */
  struct anti_replay_info anti_replay_info;
  
  union {
  
    /** Pointer to metadata (tentative neighbors only) */
    void *metadata_ptr;
    
    /** Metadata (tentative neighbors only) */
    uint8_t metadata[NEIGHBOR_PAIRWISE_KEY_LEN];
    
    /** Established pairwise key (permanent neighbors only) */
    uint8_t pairwise_key[NEIGHBOR_PAIRWISE_KEY_LEN];
  };
  
#if NEIGHBOR_BROADCAST_KEY_LEN
  /** The broadcast keys is known by all neighbors, but is only used for encryption */
  uint8_t broadcast_key[NEIGHBOR_BROADCAST_KEY_LEN];
#endif /* NEIGHBOR_BROADCAST_KEY_LEN */
};

struct neighbor *neighbor_head(void);
struct neighbor *neighbor_next(struct neighbor *previous);
struct neighbor *neighbor_new(void);
struct neighbor *neighbor_get(const linkaddr_t *extended_addr);
void neighbor_on_got_updated(struct neighbor *sender);
#if NEIGHBOR_SEND_UPDATES
void neighbor_on_updated(struct neighbor *receiver);
#endif /* NEIGHBOR_SEND_UPDATES */
void neighbor_update_ids(struct neighbor_ids *ids, void *short_addr);
void neighbor_update(struct neighbor *neighbor, uint8_t *data);
void neighbor_remove(struct neighbor *neighbor);
void neighbor_init(void);

#endif /* NEIGHBOR_H_ */

/** @} */
