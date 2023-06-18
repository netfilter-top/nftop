/*
 * (C) 2020-2023 by Kyle Huff <code@curetheitch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef _NFTOP_DISP_H
#define _NFTOP_DISP_H

#ifndef ENABLE_NCURSES
#define gotoxy(x,y) printf("\033[%d;%dH", (y), (x))
#endif

void displayInit();
void displayClear();
void displayClose();
void displayHeader();
void displayRefresh();
void displayWrite(const char *fmt, ...);
void displayCTInfo(struct Connection *);
void displayDevices(struct Interface *);

#endif