/*
 * Copyright (C) 2018-2019 Eagle Eye Networks
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SRC_PNP_THREAD_HELPER_H_
#define SRC_PNP_THREAD_HELPER_H_

#include "pnp_common.h"
#include <pthread.h>

/**
 * @brief State machine representation of threads
 */
enum pnp_thread_state {
	PNP_THREAD_UNDEF,       //!< PNP_THREAD_UNDEF        Object not initialized
	PNP_THREAD_INITIALIZED, //!< PNP_THREAD_INITIALIZED  Object initialized and ready to start thread
	PNP_THREAD_SETUP,       //!< PNP_THREAD_SETUP        Thread started, but not yet fully running
	PNP_THREAD_RUNNING      //!< PNP_THREAD_RUNNING      Running thread
};

/**
 * @brief Helper function for creation of new joinable thread
 *
 * @param thread_id      Pointer to thread id variable, which will be
 *                       overwritten by the function
 * @param start_routine  Function that is a starting point for new thread
 * @param arg            Pointer to argument for a starting point function
 * @retval true          Successfully created new thread
 * @retval false         Failed to create new thread
 */
static inline bool pnp_thread_create_joinable(pthread_t *thread_id,
		void *(*start_routine)(void *),
		void *arg)
{
	pthread_attr_t attr;
	int ret;

	/* Create as joinable */
	if ((ret = pthread_attr_init(&attr)) != 0) {
		pnp_err("Failed to initialize pthread_attr_t");
		return false;
	}
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Create thread */
	if ((ret = pthread_create(thread_id, &attr, start_routine, arg)) != 0) {
		pthread_attr_destroy(&attr);
		return false;
	}

	pthread_attr_destroy(&attr);
	return true;
}

/**
 * @brief Helper function for creation of new detached thread
 *
 * @param thread_id      Pointer to thread id variable, which will be
 *                       overwritten by the function
 * @param start_routine  Function that is a starting point for new thread
 * @param arg            Pointer to argument for a starting point function
 * @retval true          Successfully created new thread
 * @retval false         Failed to create new thread
 */
static inline bool pnp_thread_create_detached(pthread_t *thread_id,
		void *(start_routine)(void *),
		void *arg)
{
	pthread_attr_t attr;
	int ret;

	/* Create as joinable */
	if ((ret = pthread_attr_init(&attr)) != 0) {
		pnp_err("Failed to initialize pthread_attr_t");
		return false;
	}
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/* Create thread */
	if ((ret = pthread_create(thread_id, &attr, start_routine, arg)) != 0) {
		pthread_attr_destroy(&attr);
		return false;
	}

	pthread_attr_destroy(&attr);
	return true;
}

#endif /* SRC_PNP_THREAD_HELPER_H_ */
