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

LIBC_NO_SANITIZE_OOB_ACCESS LIBC_INLINE static void *
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

  const uintptr_t page_offset =
      reinterpret_cast<uintptr_t>(s) & (MIN_PAGE_SIZE - 1);
  const Vector *loop_aligned;
  if (LIBC_LIKELY(page_offset <= MIN_PAGE_SIZE - LOOP_BLOCK_SIZE)) {
    if (n <= VEC_SIZE) {
      Mask m0 = cpp::load<Vector>(s, /*aligned=*/false) == c_byte;
      if (cpp::any_of(m0))
        return calculate_find_first_character_return(
            reinterpret_cast<const char *>(s), m0, n);
      return nullptr;
    }

    if (n <= 2 * VEC_SIZE) {
      Mask m0 = cpp::load<Vector>(s, /*aligned=*/false) == c_byte;
      const unsigned char *tail = s + n - VEC_SIZE;
      Mask m1 = cpp::load<Vector>(tail, /*aligned=*/false) == c_byte;
      if (cpp::any_of(m0 | m1)) {
        if (cpp::any_of(m0))
          return const_cast<unsigned char *>(s) + cpp::find_first_set(m0);
        return const_cast<unsigned char *>(tail) + cpp::find_first_set(m1);
      }
      return nullptr;
    }

    if (n <= 3 * VEC_SIZE) {
      Mask m0 = cpp::load<Vector>(s, /*aligned=*/false) == c_byte;
      Mask m1 = cpp::load<Vector>(s + VEC_SIZE, /*aligned=*/false) == c_byte;
      const unsigned char *tail = s + n - VEC_SIZE;
      Mask m2 = cpp::load<Vector>(tail, /*aligned=*/false) == c_byte;
      if (cpp::any_of((m0 | m1) | m2)) {
        if (cpp::any_of(m0))
          return const_cast<unsigned char *>(s) + cpp::find_first_set(m0);
        if (cpp::any_of(m1))
          return const_cast<unsigned char *>(s + VEC_SIZE) +
                 cpp::find_first_set(m1);
        return const_cast<unsigned char *>(tail) + cpp::find_first_set(m2);
      }
      return nullptr;
    }

    if (n <= LOOP_BLOCK_SIZE) {
      Mask m0 = cpp::load<Vector>(s, /*aligned=*/false) == c_byte;
      Mask m1 = cpp::load<Vector>(s + VEC_SIZE, /*aligned=*/false) == c_byte;
      Mask m2 =
          cpp::load<Vector>(s + 2 * VEC_SIZE, /*aligned=*/false) == c_byte;
      const unsigned char *tail = s + n - VEC_SIZE;
      Mask m3 = cpp::load<Vector>(tail, /*aligned=*/false) == c_byte;
      if (cpp::any_of((m0 | m1) | (m2 | m3))) {
        if (cpp::any_of(m0))
          return const_cast<unsigned char *>(s) + cpp::find_first_set(m0);
        if (cpp::any_of(m1))
          return const_cast<unsigned char *>(s + VEC_SIZE) +
                 cpp::find_first_set(m1);
        if (cpp::any_of(m2))
          return const_cast<unsigned char *>(s + 2 * VEC_SIZE) +
                 cpp::find_first_set(m2);
        return const_cast<unsigned char *>(tail) + cpp::find_first_set(m3);
      }
      return nullptr;
    }

    Mask m0 = cpp::load<Vector>(s, /*aligned=*/false) == c_byte;
    Mask m1 = cpp::load<Vector>(s + VEC_SIZE, /*aligned=*/false) == c_byte;
    Mask m2 = cpp::load<Vector>(s + 2 * VEC_SIZE, /*aligned=*/false) == c_byte;
    Mask m3 = cpp::load<Vector>(s + 3 * VEC_SIZE, /*aligned=*/false) == c_byte;
    if (LIBC_UNLIKELY(cpp::any_of((m0 | m1) | (m2 | m3)))) {
      if (cpp::any_of(m0))
        return const_cast<unsigned char *>(s) + cpp::find_first_set(m0);
      if (cpp::any_of(m1))
        return const_cast<unsigned char *>(s + VEC_SIZE) +
               cpp::find_first_set(m1);
      if (cpp::any_of(m2))
        return const_cast<unsigned char *>(s + 2 * VEC_SIZE) +
               cpp::find_first_set(m2);
      return const_cast<unsigned char *>(s + 3 * VEC_SIZE) +
             cpp::find_first_set(m3);
    }
    const unsigned char *next_block = reinterpret_cast<const unsigned char *>(
        __builtin_align_down(s + LOOP_BLOCK_SIZE, LOOP_BLOCK_SIZE));
    n -= static_cast<size_t>(next_block - s);
    loop_aligned = reinterpret_cast<const Vector *>(next_block);
    goto main_loop;
  }

  {
    const Vector *aligned = reinterpret_cast<const Vector *>(
        __builtin_align_down(s, alignof(Vector)));
    Vector chars = cpp::load<Vector>(aligned, /*aligned=*/true);
    size_t offset = static_cast<size_t>(
        s - reinterpret_cast<const unsigned char *>(aligned));
    Mask cmp_v = shift_mask<unsigned char>(chars == c_byte, offset);
    if (cpp::any_of(cmp_v))
      return calculate_find_first_character_return(
          reinterpret_cast<const char *>(s), cmp_v, n);
    size_t first_bytes = VEC_SIZE - offset;
    if (n <= first_bytes)
      return nullptr;
    n -= first_bytes;
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

main_loop:
  // loop_aligned is LOOP_BLOCK_SIZE-aligned and n > 0, so the entire
  // LOOP_BLOCK_SIZE block lies on the same page as *loop_aligned and cannot
  // cross a page boundary even on the final partial block.
  LIBC_LOOP_NOUNROLL
  for (;;) {
    Vector v0 = cpp::load<Vector>(loop_aligned, /*aligned=*/true);
    Vector v1 = cpp::load<Vector>(loop_aligned + 1, /*aligned=*/true);
    Vector v2 = cpp::load<Vector>(loop_aligned + 2, /*aligned=*/true);
    Vector v3 = cpp::load<Vector>(loop_aligned + 3, /*aligned=*/true);
    Mask m0 = v0 == c_byte;
    Mask m1 = v1 == c_byte;
    Mask m2 = v2 == c_byte;
    Mask m3 = v3 == c_byte;
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

} // namespace clang_vector

} // namespace LIBC_NAMESPACE_DECL

#endif // LLVM_LIBC_SRC_STRING_MEMORY_UTILS_GENERIC_INLINE_STRLEN_H
