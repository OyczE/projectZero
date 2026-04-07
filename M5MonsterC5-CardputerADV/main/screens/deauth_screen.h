/**
 * @file deauth_screen.h
 * @brief Deauth attack running screen
 */

#ifndef DEAUTH_SCREEN_H
#define DEAUTH_SCREEN_H

#include "screen_manager.h"
#include "uart_handler.h"

// Parameters for creating the deauth screen
typedef struct {
    wifi_network_t *networks;  // Networks being attacked (ownership transferred)
    int count;                 // Number of networks
} deauth_screen_params_t;

/**
 * @brief Create the deauth running screen
 * @param params Pointer to deauth_screen_params_t
 * @return Created screen or NULL on failure
 */
screen_t* deauth_screen_create(void *params);

#endif // DEAUTH_SCREEN_H

