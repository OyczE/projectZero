/**
 * @file network_list_screen.h
 * @brief Network list screen with checkboxes
 */

#ifndef NETWORK_LIST_SCREEN_H
#define NETWORK_LIST_SCREEN_H

#include "screen_manager.h"
#include "uart_handler.h"

// Parameters for creating the network list screen
typedef struct {
    wifi_network_t *networks;  // Array of networks (ownership transferred)
    int count;                 // Number of networks
} network_list_params_t;

/**
 * @brief Create the network list screen
 * @param params Pointer to network_list_params_t
 * @return Created screen or NULL on failure
 */
screen_t* network_list_screen_create(void *params);

#endif // NETWORK_LIST_SCREEN_H
