#!/bin/bash
gcc oracle.c -o oracle -lcrypto -Wall
gcc solver.c -o solver -lcrypto -lpthread -Wall
