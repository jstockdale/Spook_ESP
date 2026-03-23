#include "vendor/GPS/MicroNMEA.h"
#include <string.h>
#include <stdlib.h>

#define NMEA_BUF_SIZE 128

static char s_buf[NMEA_BUF_SIZE];
static int s_buf_idx = 0;

void nmea_init(nmea_data_t *data) {
    memset(data, 0, sizeof(*data));
    s_buf_idx = 0;
}

static long parse_degrees(const char *s, int deg_digits) {
    /* Format: dddmm.mmmm -> returns millionths of degree */
    char deg_str[4] = {0};
    memcpy(deg_str, s, deg_digits);
    long deg = atol(deg_str);
    const char *min_str = s + deg_digits;
    double mins = atof(min_str);
    return (long)((deg + mins / 60.0) * 1000000.0);
}

static bool parse_sentence(nmea_data_t *data, const char *sentence) {
    if (sentence[0] != '$') return false;
    size_t len = strlen(sentence);
    if (len < 6) return false;

    /* Extract talker + message ID */
    data->talker_id[0] = sentence[1];
    data->talker_id[1] = sentence[2];
    data->message_id[0] = sentence[3];
    data->message_id[1] = sentence[4];
    data->message_id[2] = sentence[5];

    /* Split fields by comma */
    char copy[NMEA_BUF_SIZE];
    strncpy(copy, sentence, sizeof(copy) - 1);
    char *fields[20];
    int nfields = 0;
    char *p = copy;
    while (nfields < 20) {
        fields[nfields++] = p;
        char *next = strchr(p, ',');
        if (!next) break;
        *next = 0;
        p = next + 1;
    }

    /* Parse GGA (fix data) */
    if (strncmp(sentence + 3, "GGA", 3) == 0 && nfields >= 10) {
        if (fields[1][0]) {
            data->hour = (fields[1][0]-'0')*10 + (fields[1][1]-'0');
            data->minute = (fields[1][2]-'0')*10 + (fields[1][3]-'0');
            data->second = (fields[1][4]-'0')*10 + (fields[1][5]-'0');
        }
        if (fields[2][0] && fields[3][0]) {
            data->latitude = parse_degrees(fields[2], 2);
            if (fields[3][0] == 'S') data->latitude = -data->latitude;
        }
        if (fields[4][0] && fields[5][0]) {
            data->longitude = parse_degrees(fields[4], 3);
            if (fields[5][0] == 'W') data->longitude = -data->longitude;
        }
        int fix = atoi(fields[6]);
        data->valid = (fix > 0);
        data->num_satellites = atoi(fields[7]);
        data->hdop = (uint8_t)(atof(fields[8]) * 10);
        if (fields[9][0]) data->altitude = (long)(atof(fields[9]) * 1000);
        return true;
    }

    /* Parse RMC (recommended minimum) */
    if (strncmp(sentence + 3, "RMC", 3) == 0 && nfields >= 10) {
        data->valid = (fields[2][0] == 'A');
        if (fields[1][0]) {
            data->hour = (fields[1][0]-'0')*10 + (fields[1][1]-'0');
            data->minute = (fields[1][2]-'0')*10 + (fields[1][3]-'0');
            data->second = (fields[1][4]-'0')*10 + (fields[1][5]-'0');
        }
        if (fields[3][0] && fields[4][0]) {
            data->latitude = parse_degrees(fields[3], 2);
            if (fields[4][0] == 'S') data->latitude = -data->latitude;
        }
        if (fields[5][0] && fields[6][0]) {
            data->longitude = parse_degrees(fields[5], 3);
            if (fields[6][0] == 'W') data->longitude = -data->longitude;
        }
        if (fields[7][0]) data->speed = (long)(atof(fields[7]) * 1000);
        if (fields[8][0]) data->course = (long)(atof(fields[8]) * 1000);
        if (fields[9][0] && strlen(fields[9]) >= 6) {
            data->day = (fields[9][0]-'0')*10 + (fields[9][1]-'0');
            data->month = (fields[9][2]-'0')*10 + (fields[9][3]-'0');
            data->year = 2000 + (fields[9][4]-'0')*10 + (fields[9][5]-'0');
        }
        return true;
    }

    return false;
}

bool nmea_process_char(nmea_data_t *data, char c) {
    if (c == '$') {
        s_buf_idx = 0;
        s_buf[s_buf_idx++] = c;
    } else if (c == '\n' || c == '\r') {
        if (s_buf_idx > 0) {
            s_buf[s_buf_idx] = 0;
            s_buf_idx = 0;
            return parse_sentence(data, s_buf);
        }
    } else if (s_buf_idx < NMEA_BUF_SIZE - 1) {
        s_buf[s_buf_idx++] = c;
    }
    return false;
}

double nmea_get_latitude(nmea_data_t *data)  { return data->latitude / 1000000.0; }
double nmea_get_longitude(nmea_data_t *data) { return data->longitude / 1000000.0; }
double nmea_get_altitude(nmea_data_t *data)  { return data->altitude / 1000.0; }
