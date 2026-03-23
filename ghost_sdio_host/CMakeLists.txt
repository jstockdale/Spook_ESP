idf_component_register(
    SRCS "src/ghost_sdio_host.c"
    INCLUDE_DIRS "include"
    REQUIRES
        driver
        sdmmc
        esp_serial_slave_link
        esp_timer
        freertos
)
