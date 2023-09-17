/*
 * (C) 2020-2023 by Kyle Huff <code@curetheitch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "nftop.h"
#include "util.h"
#include "display.h"

enum NFTOP_F_COLUMNS {
    NFTOP_FLAGS_COL_ID      = (1u << 0),
    NFTOP_FLAGS_COL_IN      = (1u << 1),
    NFTOP_FLAGS_COL_OUT     = (1u << 2),
    NFTOP_FLAGS_COL_PROTO   = (1u << 3),
    NFTOP_FLAGS_COL_SRC     = (1u << 4),
    NFTOP_FLAGS_COL_SPORT   = (1u << 5),
    NFTOP_FLAGS_COL_STATUS  = (1u << 6),
    NFTOP_FLAGS_COL_DST     = (1u << 7),
    NFTOP_FLAGS_COL_DPORT   = (1u << 8),
    NFTOP_FLAGS_COL_TX      = (1u << 9),
    NFTOP_FLAGS_COL_RX      = (1u << 10),
    NFTOP_FLAGS_COL_SUM     = (1u << 11),
};

int NFTOP_DEFAULT_COLUMNS = 0xfbe;
int NFTOP_FLAGS_COLUMNS = 0xfbe;

void disableColumn(int column) {
    NFTOP_FLAGS_COLUMNS &= column;
}

void enableColumn(int column) {
    NFTOP_FLAGS_COLUMNS |= (~column);
}

void displayWrite(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
#ifdef ENABLE_NCURSES
    if (is_redirected()) {
        vprintf(fmt, args);
    } else {
        vw_printw(w, fmt, args);
    }
#else
    vprintf(fmt, args);
#endif
    va_end(args);
}

void displayInit() {

    if (is_redirected()) {
        setvbuf(stdout, NULL, _IONBF, 0);
    } else {
#ifdef ENABLE_NCURSES
        SCREEN *s = newterm(NULL, stdin, stdout);
        if (s == NULL) {
            exit(1);
        }
        cbreak();
        noecho();

        w = newwin(0, 0, 0, 0);
        start_color();
        use_default_colors();

        init_color(COLOR_BLACK, 0, 0, 0);
        init_color(COLOR_WHITE, 999, 999, 999);
        init_pair(1, COLOR_BLACK, COLOR_WHITE);

        refresh();
        wrefresh(w);
        keypad(w, 1);
        nodelay(w, 1);
        curs_set(0);
#else
    displayWrite("\033[?25l"); // hide cursor
    if (!NFTOP_U_CONTINUOUS) {
        displayWrite("\033[?1049h"); // create new screen (tput smcup)
        displayWrite("\033[?7l"); // disable line-wrapping
    }
    set_conio_terminal_mode();
#endif
    }
}

void displayClose() {
#ifdef ENABLE_NCURSES
    endwin();
    delwin(w);
    delscreen(0);
#endif
    if (!is_redirected()) {
        displayWrite("\033[?1049l"); // restore screen (tput rmcup)
    }
    displayWrite("\033[?7h"); // enable line-wrapping
    displayWrite("\033[?25h"); // restore cursor
    fflush(stdout);
}

void displayClear() {
#ifdef ENABLE_NCURSES
    if (!is_redirected()) {
        werase(w);
    } else {
        fflush(stdout);
    }
#else
    if (!is_redirected() && ! NFTOP_U_CONTINUOUS) {
        printf("\033[1;1H\033[2J");  	// clear screen
        printf("\033[39m\033[49m");     // reset fg/bg color
    }
    fflush(stdout);
#endif
}

void displayRefresh() {
#ifndef ENABLE_NCURSES
    if (!is_redirected() && !NFTOP_U_CONTINUOUS) {
        printf("\033[0;30;40m\033[K");
        printf("\033[0m");
    }
    fflush(stdout);
#endif
}

#ifdef ENABLE_NCURSES
void getwinsize(WINDOW *w, int *max_y, int *max_x) {
    getmaxyx(w, *max_y, *max_x);
#else
void getwinsize(struct winsize w, short unsigned int *_max_y, short unsigned int *_max_x) {
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    *_max_x = w.ws_col;
    *_max_y = w.ws_row;
#endif
}

void displayHeader() {
    char *rx_all_s, *tx_all_s, *sum_all_s, *run_status, *uom, *bb, *l3enabled;
    char *pad = " ";

#ifdef ENABLE_NCURSES
    int max_x, max_y;
#else
    short unsigned int max_y, max_x;
    max_y = 0;
    max_x = 0;
#endif

    NFTOP_CT_ITER = 0;

    getwinsize(w, &max_y, &max_x);

    if (max_x % 2 == 1) { // coerce max_x to an even number
        max_x--;
    }

    if (NFTOP_U_REPORT_WIDE) {
        NFTOP_MAX_HOSTNAME = max_x - 99;
    } else {
        NFTOP_MAX_HOSTNAME = max_x - 64;
    }

    if (NFTOP_U_DISPLAY_ID)
        NFTOP_MAX_HOSTNAME -= 11;
    if (NFTOP_U_DISPLAY_STATUS)
        NFTOP_MAX_HOSTNAME -= 13;

    if (NFTOP_U_DISPLAY_AGE != 0)
        NFTOP_MAX_HOSTNAME -= (NFTOP_U_REPORT_WIDE ? 9 : 19);

    if (NFTOP_MAX_HOSTNAME < 10)
        NFTOP_MAX_HOSTNAME = 10;

    rx_all_s = formatUOM(NFTOP_RX_ALL);
    tx_all_s = formatUOM(NFTOP_TX_ALL);
    sum_all_s = formatUOM(NFTOP_TX_ALL + NFTOP_RX_ALL);

    if (!NFTOP_FLAGS_PAUSE)
        displayClear();

    displayWrite("[NFTOP] Connections: %-5d |", NFTOP_CT_COUNT);

    if (NFTOP_FLAGS_PAUSE) {
        run_status = " PAUSED  ";
    } else {
        run_status = " RUNNING ";
    }

    if (NFTOP_U_BYTES)
        bb = "| Bps ";
    else
        bb = "| bps ";

    if (NFTOP_U_IPV4 && NFTOP_U_IPV6)
        l3enabled = "| 46 ";
    else if (NFTOP_U_IPV4)
        l3enabled = "| v4 ";
    else
        l3enabled = "| v6 ";

    if (NFTOP_U_SI)
        uom = "| SI  ";
    else
        uom = "| IEC ";

    displayWrite("%-9s", run_status);
    displayWrite("| %03ds ", NFTOP_U_INTERVAL);
    displayWrite("%-5s", bb);
    displayWrite("%-5s", l3enabled);
    displayWrite("%-5s", uom);

    if (!NFTOP_FLAGS_DEV_ONLY) {
        if (NFTOP_U_DISPLAY_ID)
            displayWrite("%*s", (NFTOP_U_REPORT_WIDE ? 11 : 11), pad);
        if (NFTOP_U_DISPLAY_STATUS)
            displayWrite("%*s", (NFTOP_U_REPORT_WIDE ? 13 : 13), pad);
    }

    if (NFTOP_U_REPORT_WIDE || NFTOP_FLAGS_DEV_ONLY) {
        if (NFTOP_U_DISPLAY_AGE == 0) {
            displayWrite("%*s", (NFTOP_MAX_HOSTNAME - 3), pad);
        } else {
            displayWrite("%*s", (NFTOP_MAX_HOSTNAME - 14), pad);
        }

        NFTOP_MAX_HOSTNAME = (NFTOP_MAX_HOSTNAME - 4) / 2;

        if (NFTOP_U_DISPLAY_AGE != 0)
            NFTOP_MAX_HOSTNAME -= 6;

        displayWrite("%12s ", tx_all_s);
        displayWrite("%12s ", rx_all_s);
        displayWrite("%13s", sum_all_s);
    } else {
        if (!NFTOP_FLAGS_DEV_ONLY) {
            displayWrite("%*s", (NFTOP_MAX_HOSTNAME-25), pad);
        }

        displayWrite("%12s ", tx_all_s);
        displayWrite("%13s", sum_all_s);

        displayWrite("\n");

        displayWrite("%*s", NFTOP_MAX_HOSTNAME+36, pad);

        if (NFTOP_U_DISPLAY_ID)
            displayWrite("%11s", pad);
        if (NFTOP_U_DISPLAY_STATUS)
            displayWrite("%13s", pad);

        displayWrite("%12s ", rx_all_s);
    }

#ifdef ENABLE_NCURSES
	wattron(w, COLOR_PAIR(1));
#else
    if (NFTOP_U_REPORT_WIDE == 1) {
        gotoxy(0, 2); // move cursor to 2nd line
    } else {
        gotoxy(0, 3); // move cursor to 3rd line
    }
    displayWrite("\033[30;47m\033[K");	// white background black/grey text
#endif

    if (!NFTOP_FLAGS_DEV_ONLY) {
        if (NFTOP_U_DISPLAY_ID)
            displayWrite(" %s%1s%7s", "ID", getSortIndicator(NFTOP_SORT_ID), " ");

        if (NFTOP_U_REPORT_WIDE) {
            displayWrite("%s%1s%-14s", " IN", getSortIndicator(NFTOP_SORT_IN), " ");
            displayWrite("%s%1s%-13s", "OUT", getSortIndicator(NFTOP_SORT_OUT), " ");
        } else {
            displayWrite("%s%1s%-13s", " DEV", getSortIndicator(NFTOP_SORT_IN), " ");
        }
        displayWrite("%-7s%1s", "PROTO", getSortIndicator(NFTOP_SORT_OUT));
        displayWrite("%-*s", NFTOP_MAX_HOSTNAME+1, "SRC");
    } else {
        displayWrite(" DEVICE %10s", pad);
        displayWrite(" ADDRESS %36s", pad);
    }

    if (NFTOP_U_REPORT_WIDE == 1 && !NFTOP_FLAGS_DEV_ONLY) {
        displayWrite("   SPORT%1s", getSortIndicator(NFTOP_SORT_SPORT), " ");
    } else if (!NFTOP_FLAGS_DEV_ONLY) {
        char *sort;
        if (NFTOP_U_SORT_FIELD == NFTOP_SORT_DPORT) {
            sort = getSortIndicator(NFTOP_SORT_DPORT);
        } else {
            sort = getSortIndicator(NFTOP_SORT_SPORT);
        }
        displayWrite("    PORT%1s%-1s", sort, " ");
    }

    if (NFTOP_U_DISPLAY_STATUS && !NFTOP_FLAGS_DEV_ONLY)
        displayWrite("%-13s", "STATUS ");

    if (NFTOP_U_REPORT_WIDE == 1 && !NFTOP_FLAGS_DEV_ONLY) {
        displayWrite("%-*s", NFTOP_MAX_HOSTNAME+1, "DST");
        displayWrite("   DPORT%1s%-1s", getSortIndicator(NFTOP_SORT_DPORT), " ");
    }

    if (NFTOP_U_REPORT_WIDE || NFTOP_FLAGS_DEV_ONLY) {
        displayWrite("%s%1s%-10s", "TX", getSortIndicator(NFTOP_SORT_TX), " ");
        displayWrite("%s%1s%-10s", "RX", getSortIndicator(NFTOP_SORT_RX), " ");
    } else {
        displayWrite("%s%1s%-7s", "TX/RX", getSortIndicator(NFTOP_SORT_RX), " ");
    }

    displayWrite("%s%1s%-9s", "SUM", getSortIndicator(NFTOP_SORT_SUM), " ");

    if (NFTOP_U_DISPLAY_AGE > 0 && !NFTOP_FLAGS_DEV_ONLY)
        displayWrite("   %s%1s%-13s", "AGE", getSortIndicator(NFTOP_SORT_AGE), " ");

#ifdef ENABLE_NCURSES
    wattroff(w, COLOR_PAIR(1));
#else
    displayWrite("\033[0m\033[J"); // reset formating and clear to end of screen
#endif

    displayWrite("\n");

    displayRefresh();

    free(rx_all_s);
    free(tx_all_s);
    free(sum_all_s);
}

void displayCTInfo(struct Connection *ct_info) {
    char *age, *pad = " ";
    char *format = "%4dd %2dh %2dm %2ds";
    int length, days, hours, minutes = 0;
    int seconds = ct_info->delta;

#ifdef ENABLE_NCURSES
    int max_x, max_y;
#else
    short unsigned int max_y, max_x;
    displayWrite("\033[0m\033[J"); // reset formating and clear to end of screen
#endif

    getwinsize(w, &max_y, &max_x);
    char *rx_s, *tx_s, *sum_s, *proto_name;

    if (is_redirected()) { // override the max rows/cols if writing to screen/file/pager/etc
        max_x = 9999;
        max_y = 9999;
    } else {
        if (NFTOP_CT_ITER > (max_y - (NFTOP_U_REPORT_WIDE ? 4 : 5))) {
            return;
        }
    }

    NFTOP_CT_ITER += (1 + (NFTOP_U_REPORT_WIDE ? 0 : 1));

	ct_info->status_str = '\0';

	if (ct_info->bps_sum >= NFTOP_U_THRESH) {
        if (NFTOP_U_DISPLAY_STATUS) {
            if ((!(ct_info->status & IPS_SEEN_REPLY))) {
                ct_info->status_str = "UNREPLIED";
            } else {
                if (ct_info->status & IPS_UNTRACKED) {
                    ct_info->status_str = "UNTRACKED";
                } else if (ct_info->status & IPS_ASSURED) {
                    ct_info->status_str = "ASSURED";
                } else if (ct_info->status & IPS_CONFIRMED) {
                    ct_info->status_str = "CONFIRMED";
                }
            }

            if (ct_info->status_l4 != 0) {
                switch(ct_info->status_l4) {
                    case TCP_CONNTRACK_TIME_WAIT:
                        ct_info->status_str = "TIME_WAIT";
                        break;
                    case TCP_CONNTRACK_CLOSE:
                        ct_info->status_str = "CLOSE";
                        break;
                    case TCP_CONNTRACK_CLOSE_WAIT:
                        ct_info->status_str = "CLOSE_WAIT";
                        break;
                    case TCP_CONNTRACK_FIN_WAIT:
                        ct_info->status_str = "FIN_WAIT";
                        break;
                    case TCP_CONNTRACK_SYN_SENT:
                    case TCP_CONNTRACK_SYN_SENT2:
                        ct_info->status_str = "SYN_SENT";
                        break;
                }
            }
        }

        tx_s = formatUOM(ct_info->bps_tx);
        rx_s = formatUOM(ct_info->bps_rx);
        sum_s = formatUOM(ct_info->bps_sum);
        proto_name = getIPProtocolName(ct_info->proto_l3, ct_info->proto_l4);

        if (NFTOP_U_DISPLAY_ID)
            displayWrite("%11u", ct_info->id);

        if (NFTOP_U_REDACT_SRC || NFTOP_U_REDACT_DST) {
            if (NFTOP_U_REDACT_SRC) {
                strcpy(ct_info->local.hostname_src, "REDACTED");
                strcpy(ct_info->local.src,          "REDACTED");
            }

            if (NFTOP_U_REDACT_DST) {
                strcpy(ct_info->local.hostname_dst, "REDACTED");
                strcpy(ct_info->local.dst,           "REDACTED");
            }
        } else {
            // truncate the hostname_dst/src to NTOP_MAX_HOSTNAME
            if (strlen(ct_info->local.hostname_src) > NFTOP_MAX_HOSTNAME)
                ct_info->local.hostname_src[NFTOP_MAX_HOSTNAME] = '\0';
            if (strlen(ct_info->local.hostname_dst) > NFTOP_MAX_HOSTNAME)
                ct_info->local.hostname_dst[NFTOP_MAX_HOSTNAME] = '\0';
            if (strlen(ct_info->local.src) > NFTOP_MAX_HOSTNAME)
                ct_info->local.src[NFTOP_MAX_HOSTNAME] = '\0';
            if (strlen(ct_info->local.dst) > NFTOP_MAX_HOSTNAME)
                ct_info->local.dst[NFTOP_MAX_HOSTNAME] = '\0';
        }

        if (NFTOP_U_REPORT_WIDE) {
            displayWrite(" %-16s %-16s %-7s %-*s ",
                ct_info->net_in_dev.name, ct_info->net_out_dev.name,
                proto_name, (NFTOP_MAX_HOSTNAME), (*ct_info->local.hostname_src != '\0' && NFTOP_U_NUMERIC_SRC == 0) ? ct_info->local.hostname_src : ct_info->local.src);
                if (NFTOP_U_NUMERIC_PORT || strlen(ct_info->local.sport_str) < 1) {
                    displayWrite("%8u ", ct_info->local.sport);
                } else {
                    displayWrite("%8s ", ct_info->local.sport_str);
                }
        } else {
            displayWrite(" %-16s %-7s %-*s ",
                ct_info->net_in_dev.name,
                proto_name, (NFTOP_MAX_HOSTNAME), (*ct_info->local.hostname_src != '\0' && NFTOP_U_NUMERIC_SRC == 0) ? ct_info->local.hostname_src : ct_info->local.src);
            if (NFTOP_U_NUMERIC_PORT || strlen(ct_info->local.sport_str) < 1) {
                displayWrite("%8u ", ct_info->local.sport);
            } else {
                displayWrite("%8s ", ct_info->local.sport_str);
            }
        }

        if (NFTOP_U_DISPLAY_STATUS)
            displayWrite("[%-10s] ", ct_info->status_str);

        if (NFTOP_U_REPORT_WIDE) {
            displayWrite("%-*s ", (NFTOP_MAX_HOSTNAME), (*ct_info->local.hostname_dst != '\0' && NFTOP_U_NUMERIC_DST == 0) ? ct_info->local.hostname_dst : ct_info->local.dst);
            if (NFTOP_U_NUMERIC_PORT || strlen(ct_info->local.dport_str) < 1) {
                displayWrite("%8u ", ct_info->local.dport);
            } else {
                displayWrite("%8s ", ct_info->local.dport_str);
            }
        }

        if (!NFTOP_U_REPORT_WIDE) {
            displayWrite("%12s [%12s]", tx_s, sum_s);
        } else {
            displayWrite("%12s %12s [%12s]", tx_s, rx_s, sum_s);
        }

        switch(NFTOP_U_DISPLAY_AGE) {
            case 1:
                length = snprintf(NULL, 0, "%ld", ct_info->delta); // get length of digits in ct_info->delta
                age = malloc(length + 1);
                snprintf(age, length+1, "%ld", ct_info->delta);
                displayWrite(" %10ss\n", age);
                free(age);
                break;
            case 2:
                days 	= seconds / (24 * 3600);
                hours 	= ((seconds - (24 * 3600)*days)) / 3600;
                minutes = ((seconds - (24 * 3600)*days) - (3600*hours)) / 60;
                seconds = ((seconds - (24 * 3600)*days) - (3600*hours) - (60*minutes));
                length 	= snprintf(NULL, 0, format, days, hours, minutes, seconds);
                age = malloc(length + 1);
                snprintf(age, length+1, format, days, hours, minutes, seconds);
                displayWrite(" %s\n", age);
                free(age);
                break;
            default:
                displayWrite("\n");
        }

        if (NFTOP_U_REPORT_WIDE != 1) {
            if (NFTOP_U_DISPLAY_ID)
                displayWrite("%11s", pad);

            displayWrite("  -> %-14s",  ct_info->net_out_dev.name);
            displayWrite("%6s   -> %-*s ", pad, (NFTOP_MAX_HOSTNAME - 5), (*ct_info->local.hostname_dst != '\0' && NFTOP_U_NUMERIC_DST == 0) ? ct_info->local.hostname_dst : ct_info->local.dst);
            if (NFTOP_U_NUMERIC_PORT || strlen(ct_info->local.dport_str) < 1) {
                displayWrite("%8u", ct_info->local.dport);
            } else {
                displayWrite("%8s", ct_info->local.dport_str);
            }
            if (NFTOP_U_DISPLAY_STATUS) {
                displayWrite("%13s", pad);
            }
            displayWrite("%13s\n", rx_s);

        }

        free(tx_s);
        free(rx_s);
        free(sum_s);
        free(proto_name);
	}
}

void displayDevices(struct Interface *devices_m) {
    struct Interface *curr_dev;
    char *rx_is, *tx_is, *sum_is, // interface counters
         *rx_as, *tx_as, *sum_as, // address counters
         *pad = " ";

    displayWrite("\033[0m\033[J"); // reset formating and clear to end of screen

    for (curr_dev = devices_m; curr_dev != NULL; curr_dev = curr_dev->next) {
        if ((curr_dev->flags & IFF_LOOPBACK) && NFTOP_U_NO_LOOPBACK == 1) {
            continue;
        }
        tx_is = formatUOM(curr_dev->bps_tx);
        rx_is = formatUOM(curr_dev->bps_rx);
        sum_is = formatUOM(curr_dev->bps_sum);

        if (curr_dev->n_addresses < 2) {
            displayWrite("%-16s %-*s %12s %12s %13s\n", curr_dev->name, 43, NFTOP_U_REDACT_SRC ? "REDACTED" : curr_dev->addresses->ip, tx_is, rx_is, sum_is);
        } else {
             if (NFTOP_U_CONTINUOUS || is_redirected()) {
                displayWrite("%-16s %-*s %12s %12s %13s\n", curr_dev->name, 43, "0.0.0.0", tx_is, rx_is, sum_is);
            } else {
                displayWrite("%-60s %12s %12s %13s\n", curr_dev->name, tx_is, rx_is, sum_is);
            }

            struct Address *addr = curr_dev->addresses;
            while (addr->ip != NULL) {
                tx_as = formatUOM(addr->bps_tx);
                rx_as = formatUOM(addr->bps_rx);
                sum_as = formatUOM(addr->bps_sum);
                if (NFTOP_U_CONTINUOUS || is_redirected()) {
                    displayWrite("%-16s %-43s %12s %12s %13s\n", curr_dev->name, NFTOP_U_REDACT_SRC ? "REDACTED" : addr->ip, tx_as, rx_as, sum_as);
                } else {
                    displayWrite("%16s %-43s %12s %12s %13s\n", pad, NFTOP_U_REDACT_SRC ? "REDACTED" : addr->ip, tx_as, rx_as, sum_as);
                }
                free(tx_as);
                free(rx_as);
                free(sum_as);
                addr = addr->next;
            }
        }

        free(tx_is);
        free(rx_is);
        free(sum_is);

    }
}