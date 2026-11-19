//===-- Strlen for generic SIMD types -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_STRING_MEMORY_UTILS_GENERIC_INLINE_STRLEN_H
#define LLVM_LIBC_SRC_STRING_MEMORY_UTILS_GENERIC_INLINE_STRLEN_H

#include "hdr/stdint_proxy.h"
#include "src/__support/CPP/bit.h"
#include "src/__support/CPP/simd.h"
#include "src/__support/common.h"
#include "src/__support/macros/optimization.h"

namespace LIBC_NAMESPACE_DECL {
namespace clang_vector {

// Exploit the underlying integer representation to do a variable shift.
template <typename byte_ty>
LIBC_INLINE constexpr cpp::simd_mask<byte_ty> shift_mask(cpp::simd_mask<char> m,
                                                         size_t shift) {
  using bitmask_ty = cpp::internal::get_as_integer_type_t<cpp::simd_mask<char>>;
  bitmask_ty r = cpp::bit_cast<bitmask_ty>(m) >> shift;
  return cpp::bit_cast<cpp::simd_mask<byte_ty>>(r);
}

LIBC_NO_SANITIZE_OOB_ACCESS LIBC_INLINE size_t string_length(const char *src) {
  constexpr cpp::simd<char> null_byte = cpp::splat('\0');

  size_t alignment = alignof(cpp::simd<char>);
  const cpp::simd<char> *aligned = reinterpret_cast<const cpp::simd<char> *>(
      __builtin_align_down(src, alignment));

  cpp::simd<char> chars = cpp::load<cpp::simd<char>>(aligned, /*aligned=*/true);
  cpp::simd_mask<char> mask = chars == null_byte;
  size_t offset = src - reinterpret_cast<const char *>(aligned);
  if (cpp::any_of(shift_mask<char>(mask, offset)))
    return cpp::find_first_set(shift_mask<char>(mask, offset));

  for (;;) {
    chars = cpp::load<cpp::simd<char>>(++aligned, /*aligned=*/true);
    mask = chars == null_byte;
    if (cpp::any_of(mask))
      return (reinterpret_cast<const char *>(aligned) - src) +
             cpp::find_first_set(mask);
  }
}

LIBC_INLINE static void *calculate_find_first_character_return(
    const char *src, cpp::simd_mask<char> c_mask, size_t n_left) {
  size_t c_offset = cpp::find_first_set(c_mask);
  if (n_left <= c_offset)
    return nullptr;
  return const_cast<char *>(src) + c_offset;
}

template <size_t N>
LIBC_NO_SANITIZE_OOB_ACCESS LIBC_ALWAYS_INLINE static void *
find_first_small(const unsigned char *s, cpp::simd<char> c_byte, size_t n) {
  static_assert(N >= 2 && N <= 4);
  using Vector = cpp::simd<char>;
  using Mask = cpp::simd_mask<char>;
  constexpr size_t VEC_SIZE = sizeof(Vector);

  const unsigned char *ptrs[N];
  Mask masks[N];
  for (size_t i = 0; i < N - 1; ++i) {
    ptrs[i] = s + i * VEC_SIZE;
    masks[i] = cpp::load<Vector>(ptrs[i], /*aligned=*/false) == c_byte;
  }
  ptrs[N - 1] = s + n - VEC_SIZE;
  masks[N - 1] = cpp::load<Vector>(ptrs[N - 1], /*aligned=*/false) == c_byte;

  Mask combined = masks[0] | masks[1];
  if constexpr (N == 3)
    combined = combined | masks[2];
  else if constexpr (N == 4)
    combined = combined | (masks[2] | masks[3]);

  if (cpp::any_of(combined)) {
    for (size_t i = 0; i < N - 1; ++i)
      if (cpp::any_of(masks[i]))
        return const_cast<unsigned char *>(ptrs[i]) +
               cpp::find_first_set(masks[i]);
    return const_cast<unsigned char *>(ptrs[N - 1]) +
           cpp::find_first_set(masks[N - 1]);
  }
  return nullptr;
}

// loop_aligned must be LOOP_BLOCK_SIZE-aligned and n > 0, so the entire
// LOOP_BLOCK_SIZE block lies on the same page as *loop_aligned and cannot
// cross a page boundary even on the final partial block.
LIBC_NO_SANITIZE_OOB_ACCESS LIBC_ALWAYS_INLINE static void *
find_first_aligned_loop(const cpp::simd<char> *loop_aligned,
                        cpp::simd<char> c_byte, size_t n) {
  using Vector = cpp::simd<char>;
  using Mask = cpp::simd_mask<char>;
  constexpr size_t VEC_SIZE = sizeof(Vector);
  constexpr size_t LOOP_BLOCK_SIZE = 4 * VEC_SIZE;

  LIBC_LOOP_NOUNROLL
  while(true) {
    Mask m0 = cpp::load<Vector>(loop_aligned, /*aligned=*/true) == c_byte;
    Mask m1 = cpp::load<Vector>(loop_aligned + 1, /*aligned=*/true) == c_byte;
    Mask m2 = cpp::load<Vector>(loop_aligned + 2, /*aligned=*/true) == c_byte;
    Mask m3 = cpp::load<Vector>(loop_aligned + 3, /*aligned=*/true) == c_byte;
    if (LIBC_UNLIKELY(cpp::any_of((m0 | m1) | (m2 | m3)))) {
      size_t found_offset;
      if (cpp::any_of(m0))
        found_offset = cpp::find_first_set(m0);
      else if (cpp::any_of(m1))
        found_offset = VEC_SIZE + cpp::find_first_set(m1);
      else if (cpp::any_of(m2))
        found_offset = 2 * VEC_SIZE + cpp::find_first_set(m2);
      else
        found_offset = 3 * VEC_SIZE + cpp::find_first_set(m3);
      if (found_offset >= n)
        return nullptr;
      return const_cast<char *>(reinterpret_cast<const char *>(loop_aligned)) +
             found_offset;
    }
    if (n <= LOOP_BLOCK_SIZE)
      return nullptr;
    loop_aligned += 4;
    n -= LOOP_BLOCK_SIZE;
  }
}

LIBC_NO_SANITIZE_OOB_ACCESS LIBC_ALWAYS_INLINE static void *
find_first_character(const unsigned char *s, unsigned char c, size_t n) {
  // s doesn't have to be dereferenceable if there is nothing to search.
  if (n == 0)
    return nullptr;

  using Vector = cpp::simd<char>;
  using Mask = cpp::simd_mask<char>;
  constexpr size_t VEC_SIZE = sizeof(Vector);
  constexpr size_t LOOP_BLOCK_SIZE = 4 * VEC_SIZE;
  constexpr size_t MIN_PAGE_SIZE = 4096;
  static_assert((MIN_PAGE_SIZE & (MIN_PAGE_SIZE - 1)) == 0 &&
                    MIN_PAGE_SIZE >= LOOP_BLOCK_SIZE,
                "4x vector block must not cross a page boundary.");

  Vector c_byte = c;

  if (n <= LOOP_BLOCK_SIZE) {
    const uintptr_t page_offset =
        reinterpret_cast<uintptr_t>(s) & (MIN_PAGE_SIZE - 1);
    if (LIBC_LIKELY(page_offset <= MIN_PAGE_SIZE - LOOP_BLOCK_SIZE)) {
      if (n <= VEC_SIZE) {
        Mask m0 = cpp::load<Vector>(s, /*aligned=*/false) == c_byte;
        return cpp::any_of(m0)
                   ? calculate_find_first_character_return(
                         reinterpret_cast<const char *>(s), m0, n)
                   : nullptr;
      }
      if (n <= 2 * VEC_SIZE)
        return find_first_small<2>(s, c_byte, n);
      if (n <= 3 * VEC_SIZE)
        return find_first_small<3>(s, c_byte, n);
      return find_first_small<4>(s, c_byte, n);
    }
  }

  const Vector *loop_aligned;
  if (LOOP_BLOCK_SIZE <= 64 && n > LOOP_BLOCK_SIZE) {
    if constexpr (LOOP_BLOCK_SIZE <= 64) {
      // Align s down to LOOP_BLOCK_SIZE; all 4 vectors lie on the same page.
      const Vector *block = reinterpret_cast<const Vector *>(
          __builtin_align_down(s, LOOP_BLOCK_SIZE));
      size_t offset = static_cast<size_t>(
          s - reinterpret_cast<const unsigned char *>(block));
      using BitMask = cpp::internal::get_as_integer_type_t<Mask>;
      uint64_t combined = 0;
      for (size_t i = 0; i < 4; ++i) {
        Mask m = cpp::load<Vector>(block + i, /*aligned=*/true) == c_byte;
        combined |= static_cast<uint64_t>(cpp::bit_cast<BitMask>(m))
                    << (i * VEC_SIZE);
      }
      combined >>= offset;
      if (LIBC_UNLIKELY(combined != 0))
        return const_cast<unsigned char *>(s) + cpp::countr_zero(combined);
      n -= LOOP_BLOCK_SIZE - offset;
      loop_aligned = block + 4;
    }
  } else {
    // Fallback for page-crossing small inputs or wide vectors (LOOP_BLOCK_SIZE
    // > 64): step aligned vectors until done or LOOP_BLOCK_SIZE-aligned.
    const Vector *aligned = reinterpret_cast<const Vector *>(
        __builtin_align_down(s, alignof(Vector)));
    size_t offset = static_cast<size_t>(
        s - reinterpret_cast<const unsigned char *>(aligned));
    Mask cmp_v = shift_mask<unsigned char>(
        cpp::load<Vector>(aligned, /*aligned=*/true) == c_byte, offset);
    if (cpp::any_of(cmp_v))
      return calculate_find_first_character_return(
          reinterpret_cast<const char *>(s), cmp_v, n);
    if (n <= VEC_SIZE - offset)
      return nullptr;
    n -= VEC_SIZE - offset;
    ++aligned;

    while ((reinterpret_cast<uintptr_t>(aligned) & (LOOP_BLOCK_SIZE - 1)) !=
           0) {
      Mask m = cpp::load<Vector>(aligned, /*aligned=*/true) == c_byte;
      if (cpp::any_of(m))
        return calculate_find_first_character_return(
            reinterpret_cast<const char *>(aligned), m, n);
      if (n <= VEC_SIZE)
        return nullptr;
      n -= VEC_SIZE;
      ++aligned;
    }
    loop_aligned = aligned;
  }
  return find_first_aligned_loop(loop_aligned, c_byte, n);
}

} // namespace clang_vector

} // namespace LIBC_NAMESPACE_DECL

#endif // LLVM_LIBC_SRC_STRING_MEMORY_UTILS_GENERIC_INLINE_STRLEN_H
