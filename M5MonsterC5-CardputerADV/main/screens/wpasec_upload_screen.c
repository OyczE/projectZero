/**
 * @file wpasec_upload_screen.c
 * @brief WPA-SEC Upload screen implementation
 *
 * Flow:
 * 1. Check WiFi connection → if not connected show error
 * 2. Send "wpasec_key read" to check if API key is configured
 * 3. If key missing → show instructions
 * 4. If key present + WiFi + SD card → send "wpasec_upload" and display results
 *
 * Redraws are deferred to on_tick (main task) to avoid SPI bus conflicts
 * with UART callbacks running on a separate task/core.
 */

#include "wpasec_upload_screen.h"
#include "uart_handler.h"
#include "text_ui.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "WPASEC";

// Getter for board SD card status (defined in main.c)
extern bool is_board_sd_missing(void);

// Screen states
typedef enum {
    STATE_CHECKING_KEY,
    STATE_NO_WIFI,
    STATE_NO_KEY,
    STATE_NO_SD,
    STATE_UPLOADING,
    STATE_UPLOAD_DONE,
    STATE_UPLOAD_FAILED,
} wpasec_state_t;

// Screen user data
typedef struct {
    wpasec_state_t state;
    volatile bool needs_redraw;   // set from UART callback, consumed in on_tick
    int uploaded;
    int duplicate;
    int failed;
} wpasec_data_t;

// Forward declarations
static void draw_screen(screen_t *self);
static void upload_callback(const char *line, void *user_data);

/**
 * @brief UART callback for wpasec_key read response
 * Runs on the UART RX task — must NOT touch display/SPI.
 */
static void key_check_callback(const char *line, void *user_data)
{
    wpasec_data_t *data = (wpasec_data_t *)user_data;
    if (!data || data->state != STATE_CHECKING_KEY) return;

    // Check for "WPA-SEC key: not set"
    if (strstr(line, "WPA-SEC key:") != NULL) {
        if (strstr(line, "not set") != NULL) {
            ESP_LOGI(TAG, "WPA-SEC key not set");
            data->state = STATE_NO_KEY;
            data->needs_redraw = true;
        } else {
            // Key is present - check SD card and proceed to upload
            ESP_LOGI(TAG, "WPA-SEC key found, starting upload");
            if (is_board_sd_missing()) {
                data->state = STATE_NO_SD;
                data->needs_redraw = true;
            } else {
                data->state = STATE_UPLOADING;
                data->needs_redraw = true;
                // Switch to upload callback before sending command
                uart_register_line_callback(upload_callback, data);
                uart_send_command("wpasec_upload");
            }
        }
    }
}

/**
 * @brief UART callback for wpasec_upload response
 * Runs on the UART RX task — must NOT touch display/SPI.
 */
static void upload_callback(const char *line, void *user_data)
{
    wpasec_data_t *data = (wpasec_data_t *)user_data;
    if (!data || data->state != STATE_UPLOADING) return;

    // Look for "Done: %d uploaded, %d duplicate, %d failed"
    if (strstr(line, "Done:") != NULL) {
        int uploaded = 0, duplicate = 0, failed = 0;
        const char *p = strstr(line, "Done:");
        if (p && sscanf(p, "Done: %d uploaded, %d duplicate, %d failed",
                        &uploaded, &duplicate, &failed) == 3) {
            ESP_LOGI(TAG, "Upload done: %d uploaded, %d duplicate, %d failed",
                     uploaded, duplicate, failed);
            data->uploaded = uploaded;
            data->duplicate = duplicate;
            data->failed = failed;
            data->state = STATE_UPLOAD_DONE;
            data->needs_redraw = true;
        } else {
            // "Done" found but could not parse numbers
            data->state = STATE_UPLOAD_FAILED;
            data->needs_redraw = true;
        }
    } else if (strstr(line, "Failed") != NULL || strstr(line, "Error") != NULL) {
        data->state = STATE_UPLOAD_FAILED;
        data->needs_redraw = true;
    }
}

static void draw_screen(screen_t *self)
{
    wpasec_data_t *data = (wpasec_data_t *)self->user_data;

    ui_clear();
    ui_draw_title("WPA-SEC Upload");

    switch (data->state) {
    case STATE_CHECKING_KEY:
        ui_print_center(3, "Checking key...", UI_COLOR_TEXT);
        break;

    case STATE_NO_WIFI:
        ui_print_center(3, "Connect to WiFi first!", UI_COLOR_HIGHLIGHT);
        break;

    case STATE_NO_KEY:
        ui_print_center(2, "Key not found.", UI_COLOR_HIGHLIGHT);
        ui_print_center(3, "Add your key to", UI_COLOR_TEXT);
        ui_print_center(4, "/lab/wpa-sec.txt", UI_COLOR_HIGHLIGHT);
        ui_print_center(5, "and reboot.", UI_COLOR_TEXT);
        break;

    case STATE_NO_SD:
        ui_print_center(3, "SD card missing!", UI_COLOR_HIGHLIGHT);
        break;

    case STATE_UPLOADING:
        ui_print_center(3, "Uploading...", UI_COLOR_TEXT);
        break;

    case STATE_UPLOAD_DONE: {
        char buf[32];
        ui_print_center(2, "Upload complete!", UI_COLOR_HIGHLIGHT);
        snprintf(buf, sizeof(buf), "Uploaded:  %d", data->uploaded);
        ui_print_center(3, buf, UI_COLOR_TEXT);
        snprintf(buf, sizeof(buf), "Duplicate: %d", data->duplicate);
        ui_print_center(4, buf, UI_COLOR_TEXT);
        snprintf(buf, sizeof(buf), "Failed:    %d", data->failed);
        ui_print_center(5, buf, UI_COLOR_TEXT);
        break;
    }

    case STATE_UPLOAD_FAILED:
        ui_print_center(3, "Failed to send.", UI_COLOR_HIGHLIGHT);
        break;
    }

    ui_draw_status("ESC:Back");
}

/**
 * @brief Tick handler — called every ~500ms from main loop (main task).
 * Safe to call display/SPI functions here.
 */
static void on_tick(screen_t *self)
{
    wpasec_data_t *data = (wpasec_data_t *)self->user_data;
    if (data && data->needs_redraw) {
        data->needs_redraw = false;
        draw_screen(self);
    }
}

static void on_key(screen_t *self, key_code_t key)
{
    (void)self;

    switch (key) {
    case KEY_ESC:
    case KEY_BACKSPACE:
        uart_clear_line_callback();
        screen_manager_pop();
        break;
    default:
        break;
    }
}

static void on_destroy(screen_t *self)
{
    wpasec_data_t *data = (wpasec_data_t *)self->user_data;

    uart_clear_line_callback();

    if (data) {
        free(data);
    }
}

screen_t* wpasec_upload_screen_create(void *params)
{
    (void)params;

    ESP_LOGI(TAG, "Creating WPA-SEC Upload screen...");

    screen_t *screen = screen_alloc();
    if (!screen) return NULL;

    wpasec_data_t *data = calloc(1, sizeof(wpasec_data_t));
    if (!data) {
        free(screen);
        return NULL;
    }

    screen->user_data = data;
    screen->on_key = on_key;
    screen->on_destroy = on_destroy;
    screen->on_draw = draw_screen;
    screen->on_tick = on_tick;

    // Step 1: Check WiFi — immediate, no async needed
    if (!uart_is_wifi_connected()) {
        data->state = STATE_NO_WIFI;
        draw_screen(screen);
        return screen;
    }

    // Step 2: Draw "Checking key..." first, THEN register callback & send command.
    // This way draw_screen finishes before the UART callback can set needs_redraw.
    data->state = STATE_CHECKING_KEY;
    draw_screen(screen);

    uart_register_line_callback(key_check_callback, data);
    uart_send_command("wpasec_key read");
    // Callback will set needs_redraw → on_tick (main loop) redraws safely.

    ESP_LOGI(TAG, "WPA-SEC Upload screen created");
    return screen;
}
