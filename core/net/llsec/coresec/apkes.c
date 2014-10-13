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
 *         Adaptable Pairwise Key Establishment Scheme (APKES).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/apkes.h"
#include "net/llsec/coresec/apkes-trickle.h"
#include "net/llsec/coresec/coresec.h"
#include "net/llsec/coresec/ebeap.h"
#include "net/llsec/anti-replay.h"
#include "net/packetbuf.h"
#include "lib/prng.h"
#include "lib/memb.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/node-id.h"
#include <string.h>

/* Command frame identifiers */
#define HELLO_IDENTIFIER          0x0A
#define HELLOACK_IDENTIFIER       0x0B
#define ACK_IDENTIFIER            0x0C

#if EBEAP_WITH_ENCRYPTION
/* command frame identifier || local index of receiver || broadcast key */
#define HELLOACK_LEN              (1 + 1 + NEIGHBOR_BROADCAST_KEY_LEN)
#else /* EBEAP_WITH_ENCRYPTION */
/* command frame identifier || local index of receiver || short address */
#define HELLOACK_LEN              (1 + 1 + NEIGHBOR_SHORT_ADDR_LEN)
#endif /* EBEAP_WITH_ENCRYPTION */

#define CHALLENGE_LEN             (NEIGHBOR_PAIRWISE_KEY_LEN/2)

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

struct wait_timer {
  struct ctimer ctimer;
  struct neighbor *neighbor;
};

static void wait_callback(void *ptr);
static void send_helloack(struct neighbor *receiver);
static void send_ack(struct neighbor *receiver);

MEMB(wait_timers_memb, struct wait_timer, APKES_MAX_TENTATIVE_NEIGHBORS);
/* A random challenge, which will be attached to HELLO commands */
static uint8_t our_challenge[CHALLENGE_LEN];

/*---------------------------------------------------------------------------*/
static void
generate_pairwise_key(uint8_t *result, uint8_t *shared_secret)
{
  CORESEC_SET_PAIRWISE_KEY(shared_secret);
  aes_128_padded_encrypt(result, NEIGHBOR_PAIRWISE_KEY_LEN);
}
/*---------------------------------------------------------------------------*/
void
apkes_broadcast_hello(void)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(HELLO_IDENTIFIER, &linkaddr_null);
  
  /* write payload */
  prng_rand(our_challenge, CHALLENGE_LEN);
  memcpy(payload, our_challenge, CHALLENGE_LEN);
  payload += CHALLENGE_LEN;
  memcpy(payload, &node_id, NEIGHBOR_SHORT_ADDR_LEN);
  
  packetbuf_set_datalen(1         /* command frame identifier */
      + CHALLENGE_LEN             /* challenge */
      + NEIGHBOR_SHORT_ADDR_LEN); /* short address */
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_hello(struct neighbor *sender, uint8_t *payload)
{
  struct wait_timer *free_wait_timer;
  clock_time_t waiting_period;
  
  PRINTF("apkes: Received HELLO\n");
  
  free_wait_timer = memb_alloc(&wait_timers_memb);
  if(!free_wait_timer) {
    PRINTF("apkes: HELLO flood?\n");
    return;
  }
  
  if(sender || !((sender = neighbor_new()))) {
    memb_free(&wait_timers_memb, free_wait_timer);
    return;
  }
  
  /* Create tentative neighbor */
  sender->status = NEIGHBOR_TENTATIVE;
  neighbor_update_ids(&sender->ids, payload + CHALLENGE_LEN);
  
  /* Write challenges to sender->metadata */
  memcpy(sender->metadata, payload, CHALLENGE_LEN);
  prng_rand(sender->metadata + CHALLENGE_LEN, CHALLENGE_LEN);
  
  /* Set up waiting period */
  waiting_period = (APKES_MAX_WAITING_PERIOD * (uint32_t) random_rand()) / RANDOM_RAND_MAX;
  sender->expiration_time = clock_seconds() + ((APKES_MAX_WAITING_PERIOD + APKES_ACK_DELAY) / CLOCK_SECOND);
  free_wait_timer->neighbor = sender;
  ctimer_set(&free_wait_timer->ctimer,
      waiting_period,
      wait_callback,
      free_wait_timer);
  
  PRINTF("apkes: Will send HELLOACK in %lus\n", waiting_period / CLOCK_SECOND);
}
/*---------------------------------------------------------------------------*/
static void
wait_callback(void *ptr)
{
  struct wait_timer *expired_wait_timer;
  
  PRINTF("apkes: wait_callback\n");
  
  expired_wait_timer = (struct wait_timer *) ptr;
  
  if(expired_wait_timer->neighbor->status == NEIGHBOR_TENTATIVE) {
    expired_wait_timer->neighbor->status = NEIGHBOR_AWAITING_ACK;
    send_helloack(expired_wait_timer->neighbor);
  }
  
  memb_free(&wait_timers_memb, expired_wait_timer);
}
/*---------------------------------------------------------------------------*/
static void
send_helloack(struct neighbor *receiver)
{
  uint8_t *payload;
  uint8_t *secret;
  
  payload = coresec_prepare_command_frame(HELLOACK_IDENTIFIER, &receiver->ids.extended_addr);
#if EBEAP_WITH_ENCRYPTION
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL | (1 << 2));
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_5_BYTE_KEY_ID_MODE);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, HELLOACK_IDENTIFIER);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1, node_id);
#else /* EBEAP_WITH_ENCRYPTION */
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  /* write payload */
  memcpy(payload, &receiver->local_index, 1);
#if EBEAP_WITH_ENCRYPTION
  memcpy(payload + 1, ebeap_broadcast_key, NEIGHBOR_BROADCAST_KEY_LEN);
#else /* EBEAP_WITH_ENCRYPTION */
  memcpy(payload + 1, &node_id, NEIGHBOR_SHORT_ADDR_LEN);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  packetbuf_set_datalen(HELLOACK_LEN);
  
  /* put our challenge right after the not-yet-written CCM*-MIC */
  memcpy(payload - 1 + HELLOACK_LEN + CORESEC_UNICAST_MIC_LENGTH,
      receiver->metadata + CHALLENGE_LEN,
      CHALLENGE_LEN);
  
  secret = APKES_SCHEME.get_secret_with_hello_sender(&receiver->ids);
  if(!secret) {
    PRINTF("apkes: could not get secret with HELLO sender\n");
    return;
  }
  generate_pairwise_key(receiver->pairwise_key, secret);
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_frame_secured(struct neighbor *neighbor)
{
  if(neighbor->status == NEIGHBOR_AWAITING_ACK) {
    /* --> must be HELLOACK */
    packetbuf_set_datalen(HELLOACK_LEN + CORESEC_UNICAST_MIC_LENGTH + CHALLENGE_LEN);
  }
}
/*---------------------------------------------------------------------------*/
static void
on_helloack(struct neighbor *sender, uint8_t *payload)
{
  struct neighbor_ids ids;
  uint8_t *secret;
  uint8_t key[NEIGHBOR_PAIRWISE_KEY_LEN];
#if EBEAP_WITH_ENCRYPTION
  uint16_t short_addr;
#endif /* EBEAP_WITH_ENCRYPTION */
  
  PRINTF("apkes: Received HELLOACK\n");
  
#if EBEAP_WITH_ENCRYPTION
  short_addr = packetbuf_attr(PACKETBUF_ATTR_KEY_SOURCE_BYTES_0_1);
  neighbor_update_ids(&ids, &short_addr);
#else /* EBEAP_WITH_ENCRYPTION */
  neighbor_update_ids(&ids,
      payload + 1);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  secret = APKES_SCHEME.get_secret_with_helloack_sender(&ids);
  if(!secret) {
    PRINTF("apkes: could not get secret with HELLOACK sender\n");
    return;
  }
  
  /* copy challenges and generate key */
  memcpy(key,
      our_challenge,
      CHALLENGE_LEN);
  memcpy(key + CHALLENGE_LEN,
      payload - 1 + HELLOACK_LEN + CORESEC_UNICAST_MIC_LENGTH,
      CHALLENGE_LEN);
  packetbuf_set_datalen(packetbuf_datalen() - CHALLENGE_LEN);
  
  generate_pairwise_key(key, secret);
  if(!coresec_decrypt_verify_unicast(key)) {
    PRINTF("apkes: Invalid HELLOACK\n");
    return;
  }
  
  if(sender) {
    switch(sender->status) {
    case(NEIGHBOR_PERMANENT):
      if(anti_replay_was_replayed(&sender->anti_replay_info)) {
        return;
      }
      break;
    case(NEIGHBOR_TENTATIVE):
      break;
    default:
      return;
    }
  } else {
    /* sender unknown --> create new neighbor */
    sender = neighbor_new();
    if (!sender) {
      return;
    }
  }
  
  memcpy(sender->pairwise_key, key, NEIGHBOR_PAIRWISE_KEY_LEN);
  sender->ids = ids;
  neighbor_update(sender, payload);
  send_ack(sender);
  apkes_trickle_on_new_neighbor();
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct neighbor *receiver)
{
  uint8_t *payload;
  
  payload = coresec_prepare_command_frame(ACK_IDENTIFIER, &receiver->ids.extended_addr);
#if EBEAP_WITH_ENCRYPTION
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL | (1 << 2));
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, ACK_IDENTIFIER);
#else /* EBEAP_WITH_ENCRYPTION */
  coresec_add_security_header(LLSEC802154_SECURITY_LEVEL & 3);
#endif /* EBEAP_WITH_ENCRYPTION */
  
  /* write payload */
  memcpy(payload, &receiver->local_index, 1);
  payload += 1;
#if EBEAP_WITH_ENCRYPTION
  memcpy(payload + 1, ebeap_broadcast_key, NEIGHBOR_BROADCAST_KEY_LEN);
  payload += NEIGHBOR_BROADCAST_KEY_LEN;
#endif /* LLSEC802154_USES_ENCRYPTION */
  /* TODO ACKs should be sent with short address as source address */ 
  memcpy(payload, &node_id, NEIGHBOR_SHORT_ADDR_LEN);
  
  packetbuf_set_datalen(1            /* command frame identifier */
      + 1                            /* local index of receiver */
#if LLSEC802154_USES_ENCRYPTION
      + NEIGHBOR_BROADCAST_KEY_LEN   /* broadcast key */
#endif /* LLSEC802154_USES_ENCRYPTION */
      + NEIGHBOR_SHORT_ADDR_LEN);    /* short address */
  
  coresec_send_command_frame();
}
/*---------------------------------------------------------------------------*/
static void
on_ack(struct neighbor *sender, uint8_t *payload)
{
  PRINTF("apkes: Received ACK\n");
  
  if(!sender
      || (sender->status != NEIGHBOR_AWAITING_ACK)
      || !coresec_decrypt_verify_unicast(sender->pairwise_key)) {
    PRINTF("apkes: Invalid ACK\n");
  } else {
    neighbor_update_ids(&sender->ids, payload + 1 + NEIGHBOR_BROADCAST_KEY_LEN);
    neighbor_update(sender, payload);
    apkes_trickle_on_new_neighbor();
  }
}
/*---------------------------------------------------------------------------*/
static void
on_command_frame(uint8_t command_frame_identifier,
    struct neighbor *sender,
    uint8_t *payload)
{
  switch(command_frame_identifier) {
  case HELLO_IDENTIFIER:
    on_hello(sender, payload);
    break;
  case HELLOACK_IDENTIFIER:
    on_helloack(sender, payload);
    break;
  case ACK_IDENTIFIER:
    on_ack(sender, payload);
    break;
  default:
    PRINTF("apkes: Received unknown command with identifier %x \n", command_frame_identifier);
  }
}
/*---------------------------------------------------------------------------*/
void
apkes_init(void)
{
  memb_init(&wait_timers_memb);
  APKES_SCHEME.init();
}
/*---------------------------------------------------------------------------*/
const struct coresec_scheme apkes_coresec_scheme = {
  apkes_trickle_is_bootstrapped,
  apkes_trickle_bootstrap,
  on_command_frame,
  on_frame_secured
};
/*---------------------------------------------------------------------------*/

/** @} */
