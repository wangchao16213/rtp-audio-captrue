#ifndef PCAPPP_IP_UTILS
#define PCAPPP_IP_UTILS

#include <stdint.h>
#ifdef LINUX
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#ifdef MAC_OS_X
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <ws2tcpip.h>
#endif
#ifdef FREEBSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/// @file

#if defined(WIN32) && !defined(_MSC_VER)
/**
 * Convert a network format address to presentation format.
 * @param[in] af Address family, can be either AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param[in] src Network address structure, can be either in_addr (IPv4) or in6_addr (IPv6)
 * @param[out] dst Network address string representation
 * @param[in] size 'dst' Maximum size
 * @return pointer to presentation format address ('dst'), or NULL (see errno).
 */
const char* inet_ntop(int af, const void* src, char* dst, size_t size);

/**
 * Convert from presentation format (which usually means ASCII printable)
 * to network format (which is usually some kind of binary format).
 * @param[in] af Address family, can be either AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param[in] src Network address string representation
 * @param[out] dst Network address structure result, can be either in_addr (IPv4) or in6_addr (IPv6)
 * @return
 * 1 if the address was valid for the specified address family;
 * 0 if the address wasn't valid ('dst' is untouched in this case);
 * -1 if some other error occurred ('dst' is untouched in this case, too)
 */
int inet_pton(int af, const char* src, void* dst);
#endif


/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	namespace internal
	{
		/**
		 * Extract IPv4 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Address in in_addr format
		 */
		in_addr* sockaddr2in_addr(struct sockaddr *sa);

		/**
		 * Extract IPv6 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Address in in6_addr format
		 */
		in6_addr* sockaddr2in6_addr(struct sockaddr *sa);

		/**
		 * Converts a sockaddr format address to its string representation
		 * @param[in] sa Address in sockaddr format
		 * @param[out]  resultString String representation of the address
		 */
		void sockaddr2string(struct sockaddr *sa, char* resultString);

		/**
		 * Convert a in_addr format address to 32bit representation
		 * @param[in] inAddr Address in in_addr format
		 * @return Address in 32bit format
		 */
		uint32_t in_addr2int(in_addr inAddr);
	} // namespace internal
} // namespace pcpp
#endif