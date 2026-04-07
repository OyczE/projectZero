/**
 * @file wifi_scan_screen.h
 * @brief WiFi scanning screen
 */

#ifndef WIFI_SCAN_SCREEN_H
#define WIFI_SCAN_SCREEN_H

#include "screen_manager.h"

/**
 * @brief Create the WiFi scan screen
 * @param params Unused
 * @return Created screen or NULL on failure
 */
screen_t* wifi_scan_screen_create(void *params);

#endif // WIFI_SCAN_SCREEN_H
