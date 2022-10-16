#include <stdio.h>
#include <stdlib.h>

typedef enum {
    one = 1,
    two,
    three,
    Max,
}palyod_ele;
typedef struct {
    palyod_ele id;
    char name[128];
}play_info_e;

static play_info_e g_playod_infos[] = {
    {
        .id = one,
        .name = "Host",
    },
    {
        .id = two,
        .name = "IP",
    },
    {
        .id = three,
        .name = "port"
    },
};

int main() {
    int type_cnt = sizeof(g_playod_infos) / sizeof(g_playod_infos[0]);
    int i = 0;
    int type_id = 0;
    char *data = "IP";
    for(i = 0; i < type_cnt; i++){
        if (0 == strncasecmp(data, g_playod_infos[i].name, strlen(g_playod_infos[i].name))) {
            type_id = g_playod_infos[i].id;
            printf("type_id :%d\n", type_id);
            break;
        }
    }

    return 0;
}