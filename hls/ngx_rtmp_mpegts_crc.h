/**
 * \file crc.h
 * Functions and types for CRC checks.
 *
 * Generated on Thu May  5 15:32:22 2016,
 * by pycrc v0.9, https://pycrc.org
 * using the configuration:
 *    Width         = 32
 *    Poly          = 0x04c11db7
 *    Xor_In        = 0xffffffff
 *    ReflectIn     = False
 *    Xor_Out       = 0x00000000
 *    ReflectOut    = False
 *    Algorithm     = table-driven
 *****************************************************************************/
#ifndef _NGX_RTMP_MPEGTS_CRC_H_INCLUDED_
#define _NGX_RTMP_MPEGTS_CRC_H_INCLUDED_


#include <ngx_core.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * The definition of the used algorithm.
 *
 * This is not used anywhere in the generated code, but it may be used by the
 * application code to call algoritm-specific code, is desired.
 *****************************************************************************/
#define CRC_ALGO_TABLE_DRIVEN 1


/**
 * The type of the CRC values.
 *
 * This type must be big enough to contain at least 32 bits.
 *****************************************************************************/
typedef uint_fast32_t ngx_rtmp_mpegts_crc_t;


/**
 * Calculate the initial crc value.
 *
 * \return     The initial crc value.
 *****************************************************************************/
static ngx_inline ngx_rtmp_mpegts_crc_t ngx_rtmp_mpegts_crc_init(void)
{
    return 0xffffffff;
}


/**
 * Update the crc value with new data.
 *
 * \param crc      The current crc value.
 * \param data     Pointer to a buffer of \a data_len bytes.
 * \param data_len Number of bytes in the \a data buffer.
 * \return         The updated crc value.
 *****************************************************************************/
ngx_rtmp_mpegts_crc_t ngx_rtmp_mpegts_crc_update(ngx_rtmp_mpegts_crc_t crc,
    const void *data, size_t data_len);


/**
 * Calculate the final crc value.
 *
 * \param crc  The current crc value.
 * \return     The final crc value.
 *****************************************************************************/
static ngx_inline ngx_rtmp_mpegts_crc_t
ngx_rtmp_mpegts_crc_finalize(ngx_rtmp_mpegts_crc_t crc)
{
    return crc ^ 0x00000000;
}


#ifdef __cplusplus
}           /* closing brace for extern "C" */
#endif

#endif      /* _NGX_RTMP_MPEGTS_CRC_H_INCLUDED_ */
