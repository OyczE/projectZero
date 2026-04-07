/**
 * @file placeholder_screen.h
 * @brief Placeholder screen for unimplemented features
 */

#ifndef PLACEHOLDER_SCREEN_H
#define PLACEHOLDER_SCREEN_H

#include "screen_manager.h"

/**
 * @brief Create a placeholder screen
 * @param params Title string (const char *)
 * @return Created screen or NULL on failure
 */
screen_t* placeholder_screen_create(void *params);

#endif // PLACEHOLDER_SCREEN_H
