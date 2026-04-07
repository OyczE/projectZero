/**
 * @file attack_select_screen.h
 * @brief Attack selection screen
 */

#ifndef ATTACK_SELECT_SCREEN_H
#define ATTACK_SELECT_SCREEN_H

#include "screen_manager.h"
#include "uart_handler.h"

// Parameters for creating the attack select screen
typedef struct {
    wifi_network_t *networks;  // Selected networks (ownership transferred)
    int count;                 // Number of networks
} attack_select_params_t;

/**
 * @brief Create the attack selection screen
 * @param params Pointer to attack_select_params_t
 * @return Created screen or NULL on failure
 */
screen_t* attack_select_screen_create(void *params);

#endif // ATTACK_SELECT_SCREEN_H
