/**
 * @file display.h
 * @brief Simple display driver for Cardputer ST7789
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

// Cardputer Display Configuration (ST7789 1.14" 240x135)
#define DISPLAY_WIDTH       240
#define DISPLAY_HEIGHT      135

// Offset for ST7789 - adjusted for swap_xy=true, mirror(true,false)
#define DISPLAY_OFFSET_X    40
#define DISPLAY_OFFSET_Y    53

// Cardputer ST7789 Pin Configuration
#define DISPLAY_PIN_SCLK    36
#define DISPLAY_PIN_MOSI    35
#define DISPLAY_PIN_DC      34
#define DISPLAY_PIN_CS      37
#define DISPLAY_PIN_RST     33
#define DISPLAY_PIN_BL      38

// SPI Configuration
#define DISPLAY_SPI_HOST    SPI2_HOST
#define DISPLAY_SPI_FREQ    80000000  // 80 MHz

// RGB565 color helpers
#define RGB565(r, g, b) ((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | (((b) & 0xF8) >> 3))

// Common colors (RGB565)
#define COLOR_BLACK     0x0000
#define COLOR_WHITE     0xFFFF
#define COLOR_RED       0xF800
#define COLOR_GREEN     0x07E0
#define COLOR_BLUE      0x001F
#define COLOR_CYAN      0x07FF
#define COLOR_MAGENTA   0xF81F
#define COLOR_YELLOW    0xFFE0
#define COLOR_ORANGE    0xFD20
#define COLOR_GRAY      0x8410
#define COLOR_DARK_GRAY 0x2104

/**
 * @brief Initialize the display
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t display_init(void);

/**
 * @brief Draw a filled rectangle
 * @param x X coordinate
 * @param y Y coordinate
 * @param w Width
 * @param h Height
 * @param color RGB565 color
 */
void display_fill_rect(int x, int y, int w, int h, uint16_t color);

/**
 * @brief Draw a single pixel
 * @param x X coordinate
 * @param y Y coordinate
 * @param color RGB565 color
 */
void display_draw_pixel(int x, int y, uint16_t color);

/**
 * @brief Draw a horizontal line
 * @param x X start
 * @param y Y coordinate
 * @param w Width
 * @param color RGB565 color
 */
void display_draw_hline(int x, int y, int w, uint16_t color);

/**
 * @brief Draw a vertical line
 * @param x X coordinate
 * @param y Y start
 * @param h Height
 * @param color RGB565 color
 */
void display_draw_vline(int x, int y, int h, uint16_t color);

/**
 * @brief Draw a rectangle outline
 * @param x X coordinate
 * @param y Y coordinate
 * @param w Width
 * @param h Height
 * @param color RGB565 color
 */
void display_draw_rect(int x, int y, int w, int h, uint16_t color);

/**
 * @brief Clear the entire screen
 * @param color RGB565 color
 */
void display_clear(uint16_t color);

/**
 * @brief Set backlight brightness
 * @param brightness 0-100 percentage
 */
void display_set_backlight(uint8_t brightness);

/**
 * @brief Flush display buffer to screen (for buffered mode)
 */
void display_flush(void);

/**
 * @brief Get pointer to framebuffer for screenshot functionality
 * @return Pointer to RGB565 framebuffer (240x135 pixels)
 */
const uint16_t* display_get_framebuffer(void);

#endif // DISPLAY_H
