set(COMPONENT_SRCS
    "main.c"
    "core/sdio_transport.c"
    "core/commandline.c"
    "core/system_manager.c"
    "core/callbacks.c"
    "core/dns_server.c"
    "core/utils.c"
    "managers/wifi_manager.c"
    "managers/ble_manager.c"
    "managers/ieee802154_manager.c"
    "managers/ap_manager.c"
    "managers/gps_manager.c"
    "managers/settings_manager.c"
    "managers/sd_card_manager.c"
    "managers/net_pipe.c"
    "vendor/pcap.c"
    "vendor/printer.c"
    "vendor/dial_client.c"
    "vendor/GPS/MicroNMEA.c"
    "vendor/GPS/gps_logger.c"
)

set(COMPONENT_ADD_INCLUDEDIRS
    "."
    "include"
)

idf_component_register(
    SRCS ${COMPONENT_SRCS}
    INCLUDE_DIRS ${COMPONENT_ADD_INCLUDEDIRS}
    REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_http_server
        esp_http_client
        esp_tls
        driver
        esp_driver_sdio
        esp_driver_uart
        esp_driver_usb_serial_jtag
        esp_driver_sdspi
        fatfs
        sdmmc
        bt
        ieee802154
        esp_timer
        esp_adc
        mbedtls
        json
        mdns
        lwip
        spi_flash
        vfs
)

# Bypass raw frame sanity check for frame injection
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)
