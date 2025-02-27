
#include "macros.inc"

.align 2
.global PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_bot
.global _PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_bot
#ifndef __clang__
.type PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_bot, %function
#endif
PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_bot:
_PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_bot:

    push_all
    Q         .req w20
    BarrettM  .req w21
    src0      .req x0
    src1      .req x1
    table     .req x28
    counter   .req x19

    ldrsh Q, [x2, #0]
    ldrsh BarrettM, [x2, #8]

    add table, x1, #64

    add src0, x0, #256*0
    add src1, x0, #256*1

    mov counter, #4
    _intt_bot_loop:

    ld4 {v16.4S, v17.4S, v18.4S, v19.4S}, [src0]
    ld4 {v20.4S, v21.4S, v22.4S, v23.4S}, [src1]

    trn1 v24.4S, v16.4S, v20.4S
    ld2 { v0.8H,  v1.8H}, [table], #32
    trn2 v28.4S, v16.4S, v20.4S
    ld2 { v2.8H,  v3.8H}, [table], #32
    trn1 v25.4S, v17.4S, v21.4S
    ld2 { v4.8H,  v5.8H}, [table], #32
    trn2 v29.4S, v17.4S, v21.4S
    ld2 { v6.8H,  v7.8H}, [table], #32
    trn1 v26.4S, v18.4S, v22.4S
    ld2 { v8.8H,  v9.8H}, [table], #32
    trn2 v30.4S, v18.4S, v22.4S
    ld2 {v10.8H, v11.8H}, [table], #32
    trn1 v27.4S, v19.4S, v23.4S
    ld2 {v12.8H, v13.8H}, [table], #32
    trn2 v31.4S, v19.4S, v23.4S
    ld2 {v14.8H, v15.8H}, [table], #32

    dup v0.8H, Q
    mov v1.H[0], BarrettM

    do_butterfly_vec_bot v28, v30, v18, v19, v29, v31,  v0, v12, v13, v14, v15
    do_butterfly_vec_mixed_rev v28, v30, v18, v19, v29, v31, v24, v26, v16, v17, v25, v27,  v0, v12, v13, v14, v15,  v8,  v9, v10, v11
    do_butterfly_vec_mixed_rev v24, v26, v16, v17, v25, v27, v28, v29, v18, v19, v30, v31,  v0,  v8,  v9, v10, v11,  v6,  v7,  v6,  v7
    do_butterfly_vec_mixed_rev v28, v29, v18, v19, v30, v31, v24, v25, v16, v17, v26, v27,  v0,  v6,  v7,  v6,  v7,  v4,  v5,  v4,  v5
    do_butterfly_vec_mixed_rev v24, v25, v16, v17, v26, v27, v24, v25, v18, v19, v28, v29,  v0,  v4,  v5,  v4,  v5,  v2,  v3,  v2,  v3
    do_butterfly_vec_mixed_rev v24, v25, v18, v19, v28, v29, v26, v27, v16, v17, v30, v31,  v0,  v2,  v3,  v2,  v3,  v2,  v3,  v2,  v3
    do_butterfly_vec_top v26, v27, v16, v17, v30, v31,  v0,  v2,  v3,   v2, v3

    qo_barrett v24, v25, v26, v27, v16, v17, v18, v19,  v1,  #11,  v0

    trn1 v16.4S, v24.4S, v28.4S
    trn2 v20.4S, v24.4S, v28.4S
    trn1 v17.4S, v25.4S, v29.4S
    trn2 v21.4S, v25.4S, v29.4S
    trn1 v18.4S, v26.4S, v30.4S
    trn2 v22.4S, v26.4S, v30.4S
    trn1 v19.4S, v27.4S, v31.4S
    trn2 v23.4S, v27.4S, v31.4S

    st4 {v16.4S, v17.4S, v18.4S, v19.4S}, [src0], #64
    st4 {v20.4S, v21.4S, v22.4S, v23.4S}, [src1], #64

    sub counter, counter, #1
    cbnz counter, _intt_bot_loop

    .unreq    Q
    .unreq    BarrettM
    .unreq    src0
    .unreq    src1
    .unreq    table
    .unreq    counter
    pop_all

    br lr

.align 2
.global PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_top
.global _PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_top
#ifndef __clang__
.type PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_top, %function
#endif
PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_top:
_PQCLEAN_KYBER1024_AARCH64_asm_intt_SIMD_top:

    push_all
    Q         .req w20
    BarrettM  .req w21
    invN      .req w22
    invN_f    .req w23
    src0      .req x0
    src1      .req x1
    src2      .req x2
    src3      .req x3
    src4      .req x4
    src5      .req x5
    src6      .req x6
    src7      .req x7
    src8      .req x8
    src9      .req x9
    src10     .req x10
    src11     .req x11
    src12     .req x12
    src13     .req x13
    src14     .req x14
    src15     .req x15
    table     .req x28
    counter   .req x19

    ldrsh Q, [x2, #0]
    ldrsh BarrettM, [x2, #8]
    ldr   invN, [x2, #10]
    ldr   invN_f, [x2, #14]

    mov table, x1

    add  src0, x0,  #32*0
    add  src1, x0,  #32*1
    add  src2, x0,  #32*2
    add  src3, x0,  #32*3
    add  src4, x0,  #32*4
    add  src5, x0,  #32*5
    add  src6, x0,  #32*6
    add  src7, x0,  #32*7
    add  src8, x0,  #32*8
    add  src9, x0,  #32*9
    add src10, x0, #32*10
    add src11, x0, #32*11
    add src12, x0, #32*12
    add src13, x0, #32*13
    add src14, x0, #32*14
    add src15, x0, #32*15

    ld1 { v0.8H,  v1.8H,  v2.8H,  v3.8H}, [table], #64

    mov  v0.H[0], Q

    dup v24.8H, Q
    dup v25.8H, BarrettM

    ld1 { v4.8H}, [ src0]
    ld1 { v5.8H}, [ src1]
    ld1 { v6.8H}, [ src2]
    ld1 { v7.8H}, [ src3]
    ld1 { v8.8H}, [ src4]
    ld1 { v9.8H}, [ src5]
    ld1 {v10.8H}, [ src6]
    ld1 {v11.8H}, [ src7]

    ld1 {v12.8H}, [ src8]
    ld1 {v13.8H}, [ src9]
    ld1 {v14.8H}, [src10]
    ld1 {v15.8H}, [src11]
    ld1 {v16.8H}, [src12]
    ld1 {v17.8H}, [src13]
    ld1 {v18.8H}, [src14]
    ld1 {v19.8H}, [src15]

    qo_butterfly_bot v12, v14, v16, v18, v28, v29, v30, v31, v13, v15, v17, v19,  v0,  v3, 0, 1,  v3, 2, 3,  v3, 4, 5,  v3, 6, 7
    qo_butterfly_mixed_rev v12, v14, v16, v18, v28, v29, v30, v31, v13, v15, v17, v19,  v4,  v6,  v8, v10, v20, v21, v22, v23,  v5,  v7,  v9, v11,  v0,  v3, 0, 1,  v3, 2, 3,  v3, 4, 5,  v3, 6, 7,  v3, 0, 1,  v3, 2, 3,  v3, 4, 5,  v3, 6, 7
    qo_butterfly_mixed_rev  v4,  v6,  v8, v10, v20, v21, v22, v23,  v5,  v7,  v9, v11, v12, v13, v16, v17, v28, v29, v30, v31, v14, v15, v18, v19,  v0,  v2, 0, 1,  v2, 2, 3,  v2, 4, 5,  v2, 6, 7,  v1, 4, 5,  v1, 4, 5,  v1, 6, 7,  v1, 6, 7
    qo_butterfly_mixed_rev v12, v13, v16, v17, v28, v29, v30, v31, v14, v15, v18, v19,  v4,  v5,  v8,  v9, v20, v21, v22, v23,  v6,  v7, v10, v11,  v0,  v1, 4, 5,  v1, 4, 5,  v1, 6, 7,  v1, 6, 7,  v1, 0, 1,  v1, 0, 1,  v1, 2, 3,  v1, 2, 3
    qo_butterfly_mixed_rev  v4,  v5,  v8,  v9, v20, v21, v22, v23,  v6,  v7, v10, v11, v12, v13, v14, v15, v28, v29, v30, v31, v16, v17, v18, v19,  v0,  v1, 0, 1,  v1, 0, 1,  v1, 2, 3,  v1, 2, 3,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7
    qo_butterfly_mixed_rev v12, v13, v14, v15, v28, v29, v30, v31, v16, v17, v18, v19,  v4,  v5,  v6,  v7, v20, v21, v22, v23,  v8,  v9, v10, v11,  v0,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5
    qo_butterfly_top  v4,  v5,  v6,  v7, v20, v21, v22, v23,  v8,  v9, v10, v11,  v0,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5

    qo_barrett_vec  v4,  v5,  v12,  v13, v20, v21, v22, v23, v25, #11, v24

    mov v0.S[1], invN_f

    qo_butterfly_bot  v4,  v5,  v6,  v7, v28, v29, v30, v31, v12, v13, v14, v15,  v0,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3
    qo_butterfly_mixed_rev  v4,  v5,  v6,  v7, v28, v29, v30, v31, v12, v13, v14, v15,  v8,  v9, v10, v11, v20, v21, v22, v23, v16, v17, v18, v19,  v0,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3
    qo_butterfly_top  v8,  v9, v10, v11, v20, v21, v22, v23, v16, v17, v18, v19,  v0,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3

    mov v0.S[1], invN

    sqrdmulh v28.8H,  v4.8H,  v0.H[2]
    sqrdmulh v29.8H,  v5.8H,  v0.H[2]
    sqrdmulh v30.8H,  v6.8H,  v0.H[2]
    sqrdmulh v31.8H,  v7.8H,  v0.H[2]
    sqrdmulh v20.8H,  v8.8H,  v0.H[2]
    sqrdmulh v21.8H,  v9.8H,  v0.H[2]
    sqrdmulh v22.8H, v10.8H,  v0.H[2]
    sqrdmulh v23.8H, v11.8H,  v0.H[2]

    mul       v4.8H,  v4.8H,  v0.H[3]
    mul       v5.8H,  v5.8H,  v0.H[3]
    mul       v6.8H,  v6.8H,  v0.H[3]
    mul       v7.8H,  v7.8H,  v0.H[3]
    mul       v8.8H,  v8.8H,  v0.H[3]
    mul       v9.8H,  v9.8H,  v0.H[3]
    mul      v10.8H, v10.8H,  v0.H[3]
    mul      v11.8H, v11.8H,  v0.H[3]

    mls       v4.8H, v28.8H,  v0.H[0]
    mls       v5.8H, v29.8H,  v0.H[0]
    mls       v6.8H, v30.8H,  v0.H[0]
    mls       v7.8H, v31.8H,  v0.H[0]
    mls       v8.8H, v20.8H,  v0.H[0]
    mls       v9.8H, v21.8H,  v0.H[0]
    mls      v10.8H, v22.8H,  v0.H[0]
    mls      v11.8H, v23.8H,  v0.H[0]

    st1 { v4.8H}, [ src0], #16
    ld1 { v4.8H}, [ src0]
    st1 { v5.8H}, [ src1], #16
    ld1 { v5.8H}, [ src1]
    st1 { v6.8H}, [ src2], #16
    ld1 { v6.8H}, [ src2]
    st1 { v7.8H}, [ src3], #16
    ld1 { v7.8H}, [ src3]
    st1 { v8.8H}, [ src4], #16
    ld1 { v8.8H}, [ src4]
    st1 { v9.8H}, [ src5], #16
    ld1 { v9.8H}, [ src5]
    st1 {v10.8H}, [ src6], #16
    ld1 {v10.8H}, [ src6]
    st1 {v11.8H}, [ src7], #16
    ld1 {v11.8H}, [ src7]

    st1 {v12.8H}, [ src8], #16
    ld1 {v12.8H}, [ src8]
    st1 {v13.8H}, [ src9], #16
    ld1 {v13.8H}, [ src9]
    st1 {v14.8H}, [src10], #16
    ld1 {v14.8H}, [src10]
    st1 {v15.8H}, [src11], #16
    ld1 {v15.8H}, [src11]
    st1 {v16.8H}, [src12], #16
    ld1 {v16.8H}, [src12]
    st1 {v17.8H}, [src13], #16
    ld1 {v17.8H}, [src13]
    st1 {v18.8H}, [src14], #16
    ld1 {v18.8H}, [src14]
    st1 {v19.8H}, [src15], #16
    ld1 {v19.8H}, [src15]

    qo_butterfly_bot v12, v14, v16, v18, v28, v29, v30, v31, v13, v15, v17, v19,  v0,  v3, 0, 1,  v3, 2, 3,  v3, 4, 5,  v3, 6, 7
    qo_butterfly_mixed_rev v12, v14, v16, v18, v28, v29, v30, v31, v13, v15, v17, v19,  v4,  v6,  v8, v10, v20, v21, v22, v23,  v5,  v7,  v9, v11,  v0,  v3, 0, 1,  v3, 2, 3,  v3, 4, 5,  v3, 6, 7,  v3, 0, 1,  v3, 2, 3,  v3, 4, 5,  v3, 6, 7
    qo_butterfly_mixed_rev  v4,  v6,  v8, v10, v20, v21, v22, v23,  v5,  v7,  v9, v11, v12, v13, v16, v17, v28, v29, v30, v31, v14, v15, v18, v19,  v0,  v2, 0, 1,  v2, 2, 3,  v2, 4, 5,  v2, 6, 7,  v1, 4, 5,  v1, 4, 5,  v1, 6, 7,  v1, 6, 7
    qo_butterfly_mixed_rev v12, v13, v16, v17, v28, v29, v30, v31, v14, v15, v18, v19,  v4,  v5,  v8,  v9, v20, v21, v22, v23,  v6,  v7, v10, v11,  v0,  v1, 4, 5,  v1, 4, 5,  v1, 6, 7,  v1, 6, 7,  v1, 0, 1,  v1, 0, 1,  v1, 2, 3,  v1, 2, 3
    qo_butterfly_mixed_rev  v4,  v5,  v8,  v9, v20, v21, v22, v23,  v6,  v7, v10, v11, v12, v13, v14, v15, v28, v29, v30, v31, v16, v17, v18, v19,  v0,  v1, 0, 1,  v1, 0, 1,  v1, 2, 3,  v1, 2, 3,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7
    qo_butterfly_mixed_rev v12, v13, v14, v15, v28, v29, v30, v31, v16, v17, v18, v19,  v4,  v5,  v6,  v7, v20, v21, v22, v23,  v8,  v9, v10, v11,  v0,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7,  v0, 6, 7,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5
    qo_butterfly_top  v4,  v5,  v6,  v7, v20, v21, v22, v23,  v8,  v9, v10, v11,  v0,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5,  v0, 4, 5

    qo_barrett_vec  v4,  v5,  v12,  v13, v20, v21, v22, v23, v25, #11, v24

    mov v0.S[1], invN_f

    qo_butterfly_bot  v4,  v5,  v6,  v7, v28, v29, v30, v31, v12, v13, v14, v15,  v0,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3
    qo_butterfly_mixed_rev  v4,  v5,  v6,  v7, v28, v29, v30, v31, v12, v13, v14, v15,  v8,  v9, v10, v11, v20, v21, v22, v23, v16, v17, v18, v19,  v0,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3
    qo_butterfly_top  v8,  v9, v10, v11, v20, v21, v22, v23, v16, v17, v18, v19,  v0,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3,  v0, 2, 3

    mov v0.S[1], invN

    sqrdmulh v28.8H,  v4.8H,  v0.H[2]
    sqrdmulh v29.8H,  v5.8H,  v0.H[2]
    sqrdmulh v30.8H,  v6.8H,  v0.H[2]
    sqrdmulh v31.8H,  v7.8H,  v0.H[2]
    sqrdmulh v20.8H,  v8.8H,  v0.H[2]
    sqrdmulh v21.8H,  v9.8H,  v0.H[2]
    sqrdmulh v22.8H, v10.8H,  v0.H[2]
    sqrdmulh v23.8H, v11.8H,  v0.H[2]

    mul       v4.8H,  v4.8H,  v0.H[3]
    mul       v5.8H,  v5.8H,  v0.H[3]
    mul       v6.8H,  v6.8H,  v0.H[3]
    mul       v7.8H,  v7.8H,  v0.H[3]
    mul       v8.8H,  v8.8H,  v0.H[3]
    mul       v9.8H,  v9.8H,  v0.H[3]
    mul      v10.8H, v10.8H,  v0.H[3]
    mul      v11.8H, v11.8H,  v0.H[3]

    mls       v4.8H, v28.8H,  v0.H[0]
    mls       v5.8H, v29.8H,  v0.H[0]
    mls       v6.8H, v30.8H,  v0.H[0]
    mls       v7.8H, v31.8H,  v0.H[0]
    mls       v8.8H, v20.8H,  v0.H[0]
    mls       v9.8H, v21.8H,  v0.H[0]
    mls      v10.8H, v22.8H,  v0.H[0]
    mls      v11.8H, v23.8H,  v0.H[0]

    st1 { v4.8H}, [ src0], #16
    st1 { v5.8H}, [ src1], #16
    st1 { v6.8H}, [ src2], #16
    st1 { v7.8H}, [ src3], #16
    st1 { v8.8H}, [ src4], #16
    st1 { v9.8H}, [ src5], #16
    st1 {v10.8H}, [ src6], #16
    st1 {v11.8H}, [ src7], #16

    st1 {v12.8H}, [ src8], #16
    st1 {v13.8H}, [ src9], #16
    st1 {v14.8H}, [src10], #16
    st1 {v15.8H}, [src11], #16
    st1 {v16.8H}, [src12], #16
    st1 {v17.8H}, [src13], #16
    st1 {v18.8H}, [src14], #16
    st1 {v19.8H}, [src15], #16

    .unreq    Q
    .unreq    BarrettM
    .unreq    invN
    .unreq    invN_f
    .unreq    src0
    .unreq    src1
    .unreq    src2
    .unreq    src3
    .unreq    src4
    .unreq    src5
    .unreq    src6
    .unreq    src7
    .unreq    src8
    .unreq    src9
    .unreq    src10
    .unreq    src11
    .unreq    src12
    .unreq    src13
    .unreq    src14
    .unreq    src15
    .unreq    table
    .unreq    counter
    pop_all

    br lr

























