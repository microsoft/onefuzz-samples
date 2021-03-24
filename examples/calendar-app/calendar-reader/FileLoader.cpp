/*********************************************************************
* Microsoft Security Risk Detection
* Developer Center Demo Application
* (c) 2017 Microsoft Corp
*
* CalendarApi.cpp:  Definition of functions used to read in a CAL file
*
*********************************************************************/

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include "CalendarLib.h"

/// <summary>
/// Calls the ParseCalendarFileBuffer function that returns a Calendar
/// object and that is exported from CalendarLib
/// </summary>
void *Parse(unsigned char *in, size_t len)
{
	if (IsBugEnabled(TRYEXCEPT))
	{
		__try
		{
			return ParseCalendarFileBuffer(in, len);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return NULL;
		}
	}
	else
	{
		return ParseCalendarFileBuffer(in, len);
	}
}

void *LoadCalendarFileFromFilePointer(FILE *pFile)
{
	fseek(pFile, 0L, SEEK_END);
	size_t size = ftell(pFile);
	fseek(pFile, 0L, SEEK_SET);

	unsigned char *p = (unsigned char *)malloc(size);
	if (!p)
	{
		return NULL;
	}

	fread(p, 1, size, pFile);
	void *t = Parse(p, size);
	free(p);
	return (void *)t;
}

void *LoadCalendarFileFromFileHandle(HANDLE h)
{
	DWORD size = GetFileSize(h, NULL);
	HANDLE MappingHandle = CreateFileMapping(h, NULL, PAGE_READONLY, 0, 0, NULL);
	if (MappingHandle == NULL)
	{
		return NULL;
	}

	void *p = MapViewOfFile(MappingHandle, FILE_MAP_READ, 0, 0, 0);
	if (!p)
	{
		CloseHandle(MappingHandle);
		return NULL;
	}

	void *t = Parse((unsigned char *)p, size);
	UnmapViewOfFile(p);
	CloseHandle(MappingHandle);
	return t;
}

void *LoadCalendarFileFromStream(ifstream *inputfile)
{
	inputfile->seekg(0, inputfile->end);
	size_t size = (size_t)inputfile->tellg();
	inputfile->seekg(0, inputfile->beg);

	unsigned char * buffer = new unsigned char[size];
	if (!buffer)
	{
		return NULL;
	}
	inputfile->read((char *)buffer, size);
	inputfile->close();

	void *p = Parse(buffer, size);
	delete[] buffer;
	return (void *)p;
}

void *LoadCalendarFileFromPath(const char *pszFileName)
{
	printf("-> Loading CAL file: %s\n", pszFileName);

	ifstream inputfile(pszFileName, ios::binary);
	if (inputfile)
	{
		return LoadCalendarFileFromStream(&inputfile);
	}
	else
	{
		printf("ERROR: no return from inputfile");
		return NULL;
	}
}