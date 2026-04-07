/**
 * @file home_screen.h
 * @brief Home screen with main menu
 */

#ifndef HOME_SCREEN_H
#define HOME_SCREEN_H

#include "screen_manager.h"

/**
 * @brief Create the home screen
 * @param params Unused
 * @return Created screen or NULL on failure
 */
screen_t* home_screen_create(void *params);

#endif // HOME_SCREEN_H
