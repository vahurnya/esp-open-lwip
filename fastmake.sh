#!/bin/sh
make -f Makefile.open clean
make -f Makefile.open COMPILE=gcc BOOT=none APP=0 SPI_SPEED=40 SPI_MODE=QIO SPI_SIZE_MAP=0
