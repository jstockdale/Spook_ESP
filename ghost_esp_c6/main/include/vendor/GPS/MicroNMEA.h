#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    char talker_id[3];
    char message_id[4];
    bool valid;
    long latitude;
    long longitude;
    long altitude;
    long speed;
    long course;
    uint16_t year;
    uint8_t month, day, hour, minute, second;
    uint8_t num_satellites;
    uint8_t hdop;
} nmea_data_t;
void nmea_init(nmea_data_t *data);
bool nmea_process_char(nmea_data_t *data, char c);
double nmea_get_latitude(nmea_data_t *data);
double nmea_get_longitude(nmea_data_t *data);
double nmea_get_altitude(nmea_data_t *data);
#ifdef __cplusplus
}
#endif
