/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

KERNEL_FQ void m32500_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };
    u32x md4_initial[4];
    u32x modified_pw[8];
    const u32x modified_pw_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, &modified_pw[0], &modified_pw[4]);

    w0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    w0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
    w0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
    w0[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
    w1[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
    w1[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
    w1[2] = salt_bufs[SALT_POS_HOST].salt_buf[6];
    w1[3] = salt_bufs[SALT_POS_HOST].salt_buf[7];


    append_0x80_2x4_VV (w0, w1, salt_bufs[SALT_POS_HOST].salt_len);


    w3[2] = salt_bufs[SALT_POS_HOST].salt_len * 8;
    w3[3] = 0;

    md4_map_custom_pw_to_context(md4_initial,modified_pw,modified_pw_len,u32x);

    u32x a = md4_initial[0];
    u32x b = md4_initial[1];
    u32x c = md4_initial[2];
    u32x d = md4_initial[3];

  /**
   * digest
   */
  const u32x search[4] =
          {
                  digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0] - md4_initial[DGST_R0],
                  digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1] - md4_initial[DGST_R1],
                  digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2] - md4_initial[DGST_R2],
                  digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3] - md4_initial[DGST_R3]
          };

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m32500_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m32500_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m32500_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    u32x md4_initial[4];
    u32x modified_pw[8];
    const u32x modified_pw_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, &modified_pw[0], &modified_pw[4]);

    w0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    w0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
    w0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
    w0[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
    w1[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
    w1[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
    w1[2] = salt_bufs[SALT_POS_HOST].salt_buf[6];
    w1[3] = salt_bufs[SALT_POS_HOST].salt_buf[7];


    append_0x80_2x4_VV (w0, w1, salt_bufs[SALT_POS_HOST].salt_len);


    w3[2] = salt_bufs[SALT_POS_HOST].salt_len * 8;
    w3[3] = 0;

    md4_map_custom_pw_to_context(md4_initial,modified_pw,modified_pw_len,u32);

    u32x a = md4_initial[0];
    u32x b = md4_initial[1];
    u32x c = md4_initial[2];
    u32x d = md4_initial[3];

    /**
     * digest
     */
    const u32 search[4] =
            {
                    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0] - md4_initial[DGST_R0],
                    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1] - md4_initial[DGST_R1],
                    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2] - md4_initial[DGST_R2],
                    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3] - md4_initial[DGST_R3]
            };

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m32500_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m32500_s16 (KERN_ATTR_RULES ())
{
}
