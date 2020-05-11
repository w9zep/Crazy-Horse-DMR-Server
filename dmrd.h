/*
	Include files for dmrd.cpp, dmrdx.cpp

	Pi-Star-compatible DMR server (MMDVM protocol), 
	Created April 2020, Michael Wagner, W9ZEP
	(c) 2020 Michael J Wagner

	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details at 
	https://www.gnu.org/licenses
*/

#ifndef _DMRD_H
#define _DMRD_H

#ifndef WIN32
#define LINUX
#endif

#ifdef WIN32
#pragma warning (disable : 4786)
#pragma warning (disable : 4018)
#pragma warning (disable : 4244)	
#endif


#include "stdio.h"
#include "stdlib.h"
#include "time.h"
#include "errno.h"
#include "assert.h"
#include <iostream>
#include <iterator>
#include <string>
#include <map>

typedef unsigned char byte;
typedef byte BYTE;
typedef unsigned short word;		// 16 bit   
typedef word WORD;
typedef unsigned long dword;		// 32 bit
typedef dword DWORD;
typedef char const *PCSTR;

#ifdef WIN32

#include "winsock2.h"
#include "process.h"
#include "io.h"

typedef unsigned __int64 u64;

#define getinaddr(ADDR) ((ADDR).sin_addr.S_un.S_addr)
#define PTHREAD_PROC(NAME) unsigned _stdcall NAME (void *threadcookie)
typedef HANDLE pthread_t;
typedef int pthread_attr_t;
typedef unsigned (_stdcall *PTHREADPROC)(void *);
typedef int socklen_t;
int pthread_create (pthread_t *, const pthread_attr_t *, PTHREADPROC, void *);
#define GetInetError() ((int)GetLastError())
#define SetInetError(E) (SetLastError(E))
#define CLOSESOCKET closesocket

#else	// linux

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <memory.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef unsigned long long u64;

dword GetTickCount();

#define getinaddr(ADDR) ((ADDR).sin_addr.s_addr)
#define PTHREAD_PROC(NAME) void * NAME (void *threadcookie)
#define GetInetError() ((int)errno)
#define SetInetError(E) (errno = (E))
#define CLOSESOCKET close	 

#define Sleep(MS)	do { \
						if(MS) \
							usleep((MS) * 1000); \
						else \
							sched_yield();} \
					while(0)

#endif

#define inrange(V,L,H) ((V) >= (L) && (V) <= (H))

#ifdef WIN32
#define eq(A,B) (stricmp((A),(B))==0)
#else
#define eq(A,B) (strcasecmp((A),(B))==0)
#endif 

void init_process();
int open_udp (int port);
bool IsOptionPresent (int argc, char **argv, PCSTR arg);
byte * make_sha256_hash (void const *pSrc, int nSize, byte *dest, void const *pSalt, int nSaltSize);
bool select_rx (int sock, int wait_secs);
PCSTR skipspaces (PCSTR p, bool bSkipTabs=true, bool bSkipCtrl=false);
void trim (std::string &s);

template <class X> void swap (X &a, X &b)
{
	X temp;
	temp = a;
	a = b;
	b = temp;
}

class memfile
{
public:

	byte				*m_pData;
	dword				m_nSize;
	dword				m_nAlloc;
	dword				m_nPos;		// Read/write pos
	dword				m_nAllocSize;

private:

	void Init() {

		m_pData = NULL;
		m_nSize = 0;
		m_nAlloc = 0;
		m_nPos = 0;
	}

public:

	memfile(int nAllocSize=65536) {

		Init();
		m_nAllocSize = nAllocSize;
	}

	virtual ~memfile() {

		Close();
	}

	virtual bool IsOpen() const {return true;}	// Always open

	virtual bool Open_(PCSTR pPath=NULL, int nFlags=0, int nCreateMode=0660) {

		Close();	// This will re-init
		return true;
	}

	virtual bool Creat(PCSTR pPath=NULL, int nCreateMode=0) {
	
		return Open_ (NULL);
	}

	virtual bool Close() {

		if (m_pData) 
			free(m_pData);
			
		Init();

		return true;
	}

	virtual dword GetSize () const {

		return m_nSize;
	}

	virtual dword GetPos() const {

		return m_nPos;
	}

	void SetSize (int nSize) {

		if (nSize == 0) {

			Creat();
		}

		else {

			m_pData = (byte*) realloc (m_pData, nSize);

			if (nSize && !m_pData)
				throw (int) ENOMEM;

			m_nSize = m_nAlloc = nSize;
			m_nPos = 0;
		}
	}

	virtual dword Seek (dword nPos, int nFrom=SEEK_SET) {

		switch (nFrom) {

			case SEEK_SET:

				m_nPos = (int) nPos;
				break;

			case SEEK_END:

				m_nPos = (int) nPos + m_nSize;
				break;

			case SEEK_CUR:

				m_nPos += (int) nPos;
				break;

			default:
				throw (int) EINVAL;
				break;
		}

		return m_nPos;
	}

	virtual int Read (void *buf, int nCount) {

		if (nCount < 1)
			return 0;

		if (!buf)
			throw (int) EINVAL;

		if (m_nPos < 0)
			throw (int) EINVAL;

		int i;

		for (i=0; i < nCount && m_nPos < m_nSize; i++) {

			((byte*)buf)[i] = m_pData[m_nPos++];
		}

		return i;
	}

	virtual int Write (void const *buf, int nCount) {

		if (nCount < 1)
			return 0;

		if (!buf)
			throw (int) EINVAL;

		if (m_nPos < 0)
			throw (int) EINVAL;

		int i;

		for (i=0; i < nCount; i++) {

			while (!m_pData || m_nPos >= m_nAlloc) {

				m_nAlloc = m_nPos + m_nAllocSize;

				m_pData = (byte*) realloc (m_pData, m_nAlloc);

				if (!m_pData) {

					Init();
					throw (int) ENOMEM;
				}
			}

			m_pData[m_nPos++] = ((byte*)buf)[i];

			if (m_nPos > m_nSize)
				m_nSize = m_nPos;
		}

		return i;
	}

	virtual void Unlock () {

		// Does nothing
	}

};

typedef std::map <std::string, std::string> STRINGMAP;

typedef STRINGMAP::iterator STRINGMAP_ITERATOR;

class config_file
{
public:

	STRINGMAP values;
	
	bool load (PCSTR path) {

		FILE *f = fopen (path, "r");

		if (!f)
			return false;

		std::string section;

		char temp[1000];

		while (fgets(temp, sizeof(temp), f)) {

			PCSTR p = skipspaces(temp);

			if (*p == '#' || *p == '\r' || *p == '\n')		// comment or blank line?
				continue;

			if (*p == '[') {		// new section?

				p = skipspaces(p+1);

				section = "";

				while (*p && *p != ']' && *p != '#' && *p != '\r' && *p != '\n')
					section += *p++;

				trim(section);
			}

			else {		// name

				std::string name, val;

				while (*p && *p != '=' && *p != '#' && *p != '\r' && *p != '\n')
					name += *p++;

				trim(name);

				if (*p == '=') {		// value?

					p = skipspaces(p+1);

					while (*p && *p != '#' && *p != '\r' && *p != '\n')
						val += *p++;

					trim(val);

					if (eq(val.c_str(), "false") || eq(val.c_str(), "off") || eq(val.c_str(), "no") || eq(val.c_str(), "disable") || eq(val.c_str(), "disabled"))
						val = "0";

					else if (eq(val.c_str(), "true") || eq(val.c_str(), "on") || eq(val.c_str(), "yes") || eq(val.c_str(), "enable") || eq(val.c_str(), "enabled"))
						val = "1";
				}

				std::string key;

				key = section;
				key += "|";
				key += name;

				values[key] = val;
			}
		}

		fclose (f);

		return true;
	}	

	void dump() {

		for (STRINGMAP_ITERATOR it = values.begin(); it != values.end(); it++) {

			std::string const &key = (*it).first;
			std::string &value = (*it).second;

			printf ("%s = %s\n", (PCSTR)key.c_str(), (PCSTR)value.c_str());
		}
	}

	bool getvalue (PCSTR section, PCSTR name, std::string &ret) {

		std::string key;

		key = section;
		key += "|";
		key += name;

		if (values.find(key) == values.end())
			return false;

		ret = values[key];
		return true;
	}

	std::string getstring (PCSTR section, PCSTR name, PCSTR Default="") {

		std::string val;
		
		if (getvalue (section, name, val))
			return val;

		return Default;
	}

	int getint (PCSTR section, PCSTR name, int Default=0) {

		std::string val;
		
		if (getvalue (section, name, val))
			return atoi(val.c_str());

		return Default;
	}

};

#endif

