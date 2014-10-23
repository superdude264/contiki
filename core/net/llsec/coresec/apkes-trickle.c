/**
 * \addtogroup coresec
 * @{
 */

/*
 * Copyright (c) 2014, Fraunhofer Heinrich-Hertz-Institut.
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
 *         Trickles HELLOs.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/coresec/apkes.h"
#include "net/llsec/coresec/apkes-trickle.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include <string.h>

#ifdef APKES_TRICKLE_CONF_IMIN
#define IMIN                      APKES_TRICKLE_CONF_IMIN
#else /* APKES_TRICKLE_CONF_IMIN */
#define IMIN                      (30 * CLOCK_SECOND)
#endif /* APKES_TRICKLE_CONF_IMIN */

#ifdef APKES_TRICKLE_CONF_IMAX
#define IMAX                      APKES_TRICKLE_CONF_IMAX
#else /* APKES_TRICKLE_CONF_IMAX */
#define IMAX                      8
#endif /* APKES_TRICKLE_CONF_IMAX */

#ifdef APKES_TRICKLE_CONF_KEEP_THRESHOLD
#define KEEP_THRESHOLD            APKES_TRICKLE_CONF_KEEP_THRESHOLD
#else /* APKES_TRICKLE_CONF_KEEP_THRESHOLD */
#define KEEP_THRESHOLD            2
#endif /* APKES_TRICKLE_CONF_KEEP_THRESHOLD */

#ifdef APKES_TRICKLE_CONF_RESET_THRESHOLD
#define RESET_THRESHOLD           APKES_TRICKLE_CONF_RESET_THRESHOLD
#else /* APKES_TRICKLE_CONF_RESET_THRESHOLD */
#define RESET_THRESHOLD           APKES_MAX_TENTATIVE_NEIGHBORS
#endif /* APKES_TRICKLE_CONF_RESET_THRESHOLD */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

static void on_interval_expired(void *ptr);

/* The network layer will be started after bootstrapping */
static llsec_on_bootstrapped_t on_bootstrapped;
/* Counts new neighbors within the current Trickle interval */
static uint8_t new_neighbors_count;
static uint8_t trickle_doublings;
static struct ctimer trickle_timer;

/*---------------------------------------------------------------------------*/
static void
bootstrap(void)
{
  if(on_bootstrapped
      && ctimer_expired(&trickle_timer)
      && new_neighbors_count) {
    on_bootstrapped();
    on_bootstrapped = NULL;
  }
}
/*---------------------------------------------------------------------------*/
//TODO: look at this function
static clock_time_t
interval_size(void)
{
  return IMIN/CLOCK_SECOND << trickle_doublings;
}
/*---------------------------------------------------------------------------*/
static clock_time_t
round_up(clock_time_t I_minus_t)
{
  const clock_time_t min = APKES_MAX_WAITING_PERIOD + APKES_ACK_DELAY;
  
  return I_minus_t > min ? I_minus_t : min;
}
/*---------------------------------------------------------------------------*/
/* Corresponds to Rule 4 of Trickle */
static void
broadcast_hello(void *ptr)
{
  PRINTF("apkes-trickle: Broadcasting HELLO\n");
  
  /* TODO suppress */
  apkes_broadcast_hello();
  ctimer_set(&trickle_timer,
      round_up(interval_size() - trickle_timer.etimer.timer.interval),
      on_interval_expired,
      NULL);
}
/*---------------------------------------------------------------------------*/
/* Corresponds to Rule 6 of Trickle */
//TODO: look at this function
static void
on_interval_expired(void *ptr)
{
  clock_time_t half_interval_size;
  
  if((trickle_doublings < IMAX) && (new_neighbors_count < KEEP_THRESHOLD)) {
    trickle_doublings++;
    PRINTF("apkes-trickle: Doubling interval size\n");
  } else {
    PRINTF("apkes-trickle: Keeping interval size\n");
  }
  
  bootstrap();
  
  half_interval_size = interval_size()/2;
  new_neighbors_count = 0;
  ctimer_set(&trickle_timer,
      half_interval_size + ((half_interval_size * random_rand()) / RANDOM_RAND_MAX),
      broadcast_hello,
      NULL);
  PRINTF("apkes-trickle: I=%lus t=%lus\n", interval_size(), trickle_timer.etimer.timer.interval);
}
/*---------------------------------------------------------------------------*/
void
apkes_trickle_on_new_neighbor(void)
{
  if(++new_neighbors_count == RESET_THRESHOLD) {
    apkes_trickle_reset();
  }
  
  bootstrap();
}
/*---------------------------------------------------------------------------*/
void
apkes_trickle_stop(void)
{
  PRINTF("apkes-trickle: Stopping Trickle\n");
  ctimer_stop(&trickle_timer);
}
/*---------------------------------------------------------------------------*/
void
apkes_trickle_reset(void)
{
  PRINTF("apkes-trickle: Resetting Trickle\n");
  apkes_trickle_stop();
  trickle_doublings = KEEP_THRESHOLD;
  on_interval_expired(NULL);
}
/*---------------------------------------------------------------------------*/
int
apkes_trickle_is_bootstrapped(void)
{
  return on_bootstrapped == NULL;
}
/*---------------------------------------------------------------------------*/
void
apkes_trickle_bootstrap(llsec_on_bootstrapped_t on_bootstrapped_param)
{
  on_bootstrapped = on_bootstrapped_param;
  apkes_init();
  broadcast_hello(NULL);
}
/*---------------------------------------------------------------------------*/

/** @} */
