/**
 * @file wpasec_upload_screen.h
 * @brief WPA-SEC Upload screen - uploads captured handshakes to wpa-sec.stanev.org
 */

#ifndef WPASEC_UPLOAD_SCREEN_H
#define WPASEC_UPLOAD_SCREEN_H

#include "screen_manager.h"

/**
 * @brief Create the WPA-SEC upload screen
 * @param params Not used
 * @return Screen instance
 */
screen_t* wpasec_upload_screen_create(void *params);

#endif // WPASEC_UPLOAD_SCREEN_H
