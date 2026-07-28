/*
 * main.c — Osprey entry point.
 *
 * First brick: no real argument parsing yet, print the banner, exit clean.
 * Compiles, links, runs, does nothing. Modules bolt on from here.
 */
#include <stdio.h>
#include "../include/osprey.h"

static void PrintBanner(void)
{
    printf("%s v%s - DCOM surface auditor (read-only)\n",
        OSPREY_NAME, OSPREY_VERSION);
}

int main(int argc, char** argv){
    (void)argc;
    (void)argv;   /* argument parsing arrives with the first real brick */

    PrintBanner();
    return EXIT_SUCCESS;
}