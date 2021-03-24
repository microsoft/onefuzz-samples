#pragma once

/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* FileReader.h:  Declaration of functions used to read in a CAL file
*
*********************************************************************/

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <fstream>

using namespace std;

void *Parse(unsigned char *in, size_t len);
void *LoadCalendarFileFromStream(ifstream *inputfile);
void *LoadCalendarFileFromFilePointer(FILE *fp);
void *LoadCalendarFileFromFileHandle(HANDLE h);
void *LoadCalendarFileFromPath(const char *pszFileName);