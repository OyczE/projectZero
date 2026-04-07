/**
 * @file placeholder_screen.c
 * @brief Placeholder screen implementation
 */

#include "placeholder_screen.h"
#include "text_ui.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "PLACEHOLDER";

typedef struct {
    char title[32];
} placeholder_data_t;

static void draw_screen(screen_t *self)
{
    placeholder_data_t *data = (placeholder_data_t *)self->user_data;
    
    ui_clear();
    
    // Draw title
    ui_draw_title(data->title);
    
    // Draw message
    ui_print_center(3, "Coming Soon", RGB565(255, 170, 0));
    ui_print_center(5, "[Under Development]", UI_COLOR_DIMMED);
    
    // Draw status bar
    ui_draw_status("ESC/ENTER:Back");
}

static void on_key(screen_t *self, key_code_t key)
{
    (void)self;
    
    switch (key) {
        case KEY_ESC:
        case KEY_Q:
        case KEY_ENTER:
            screen_manager_pop();
            break;
            
        default:
            break;
    }
}

static void on_destroy(screen_t *self)
{
    if (self->user_data) {
        free(self->user_data);
    }
}

screen_t* placeholder_screen_create(void *params)
{
    const char *title = (const char *)params;
    if (!title) title = "Coming Soon";
    
    ESP_LOGI(TAG, "Creating placeholder screen: %s", title);
    
    screen_t *screen = screen_alloc();
    if (!screen) return NULL;
    
    placeholder_data_t *data = calloc(1, sizeof(placeholder_data_t));
    if (!data) {
        free(screen);
        return NULL;
    }
    
    strncpy(data->title, title, sizeof(data->title) - 1);
    
    screen->user_data = data;
    screen->on_key = on_key;
    screen->on_destroy = on_destroy;
    screen->on_draw = draw_screen;
    
    // Draw initial screen
    draw_screen(screen);
    
    ESP_LOGI(TAG, "Placeholder screen created");
    return screen;
}
