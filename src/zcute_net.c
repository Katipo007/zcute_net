#include <stddef.h>
#include <stdbool.h>

#define ZCUTE_NET_NOOP ((void)0)

extern void* zcute_net_allocate(size_t num_bytes, void* ctx);
extern void zcute_net_free(void* mem, void* ctx);
extern void zcute_net_assert(bool cond);
extern void* zcute_net_memcpy(void* dest, const void* src, size_t count);
extern void* zcute_net_memset(void* dest, int ch, size_t count);
extern int zcute_net_memcmp(const void* lhs, const void* rhs, size_t count);

#define CN_ALLOC zcute_net_allocate
#define CN_FREE zcute_net_free
#define CN_MEMCPY zcute_net_memcpy
#define CN_MEMSET zcute_net_memset
#define CN_ASSERT(cond) zcute_net_assert(cond)
//#define CN_STRNCPY zcute_net_strncpy
//#define CN_STRLEN zcute_net_strlen
//#define CN_STRNCMP zcute_net_strncmp
#define CN_MEMCMP zcute_net_memcmp
//#define CN_SNPRINTF zcute_net_snprintf
//#define CN_FPRINTF zcute_net_fprintf
#define CN_PRINTF(...) ZCUTE_NET_NOOP

#define CUTE_NET_IMPLEMENTATION
#include "cute_net.h"
