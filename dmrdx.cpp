/*
	Helper functions for dmrd.cpp

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

#include "dmrd.h"

bool select_rx (int sock, int wait_secs)
{
	fd_set read;

	FD_ZERO (&read);

	FD_SET (sock, &read);

	timeval t;

	t.tv_sec = wait_secs;
	t.tv_usec = 0;

	int ret = select (sock + 1, &read, NULL, NULL, &t);     

	if (ret == -1)
		return false;

	return !!ret;
}

int open_udp (int port)
{
	int err;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock == -1) 
		return -1;

	int on = true;
	
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &on, sizeof(on));

	sockaddr_in addr;

	memset (&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (bind (sock, (sockaddr*) &addr, sizeof(addr)) == -1) {

		err = errno;
		CLOSESOCKET(sock);
		errno = err;
		return -1;
	}

	// Allow broadcast

	int bArg = true;

	if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST, (char*) &bArg, sizeof(bArg)) == -1) {

		err = errno;
		CLOSESOCKET(sock);
		errno = err;
		return -1;
	}

	return sock;
}

#ifdef WIN32
int pthread_create (pthread_t *th, const pthread_attr_t *pAttr, PTHREADPROC pProc, void *pArg)
{
	assert(th);

	unsigned hThread = 0;
	
	if (_beginthreadex (NULL, 0, pProc, pArg, 0, &hThread) == 0)
		return errno;

	*th = (pthread_t) hThread;		 

	return 0;
}
#endif

// SHA256 

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

typedef struct {
	BYTE data[64];
	DWORD datalen;
	u64 bitlen;
	DWORD state[8];
} SHA256_CTX;

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const DWORD k[64] = {
	
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	DWORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	int i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

static void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	int i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

byte * make_sha256_hash (void const *pSrc, int nSize, byte *dest, void const *pSalt, int nSaltSize)
{
	SHA256_CTX ctx;

	sha256_init (&ctx);

	sha256_update(&ctx, (byte*)pSrc, nSize);
	
	if (pSalt)
		sha256_update(&ctx, (byte*)pSalt, nSaltSize);

	sha256_final(&ctx, dest);

	return dest;	
}

bool IsOptionPresent (int argc, char **argv, PCSTR arg)
{
	for (int i=1; i < argc; i++) {

		if (strcmp(argv[i],arg)==0)
			return true;
	}

	return false;
}

#ifdef LINUX
dword GetTickCount() 
{
	struct timeval now;
	
	gettimeofday(&now, NULL);

	u64 ticks = (u64) now.tv_sec * 1000;
	
	ticks += now.tv_usec / 1000;
	
	return (DWORD) ticks;
};
#endif

void trim (std::string &s) {

	int x = s.size() - 1;

	while (x >= 0 && isspace(s[x]))
		s.erase(x--);
}

PCSTR skipspaces (PCSTR p, bool bSkipTabs, bool bSkipCtrl)
{
	while (*p) {

		if (*p == ' ') {

			p ++;
		}

		else if (bSkipCtrl && *p > 0 && *p < ' ') {

			p ++;
		}

		else if (bSkipTabs && *p == '\t') {

			p ++;
		}

		else
			break;
	}

	return p;
}

static void _init_process() 
{
	assert(sizeof(WORD) == 2);
	assert(sizeof(DWORD) == 4);
	assert(sizeof(word) == 2);
	assert(sizeof(dword) == 4);
	assert(sizeof(u64) == 8);
	setbuf(stdout,NULL);
}

void init_process()
{
	_init_process();

#ifdef WIN32

	WSADATA wsa; 
	WSAStartup (MAKEWORD(1,1), &wsa);
	_umask(0);

#else

	signal(SIGPIPE,SIG_IGN);
	//signal(SIGSEGV,SIG_IGN);
	//signal(SIGCHLD,SIG_IGN);
	signal(SIGCHLD,SIG_DFL);
	struct rlimit r;
	memset (&r, 0, sizeof(r));
	setrlimit(RLIMIT_CORE, &r);	// no core dumps
	umask(0);

#endif
}

