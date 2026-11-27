// RUN: not llvm-mc -triple x86_64-unknown-unknown %s -o /dev/null 2>&1 | FileCheck %s

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacor16x16x16 %ymm4, %ymm5, %ymm6 {%k1}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacor16x16x16 %ymm4, %ymm5, %ymm6 {%k1} {z}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacor16x16x16 (%rax){1to16}, %ymm5, %ymm6

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacor16x16x16 %zmm4, %zmm5, %zmm6 {%k1}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacor16x16x16 %zmm4, %zmm5, %zmm6 {%k1} {z}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacor16x16x16 (%rax){1to32}, %zmm5, %zmm6

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacxor16x16x16 %ymm4, %ymm5, %ymm6 {%k1}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacxor16x16x16 %ymm4, %ymm5, %ymm6 {%k1} {z}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacxor16x16x16 (%rax){1to16}, %ymm5, %ymm6

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacxor16x16x16 %zmm4, %zmm5, %zmm6 {%k1}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacxor16x16x16 %zmm4, %zmm5, %zmm6 {%k1} {z}

// CHECK: :[[@LINE+1]]:{{[0-9]+}}: error: invalid operand for instruction
vbmacxor16x16x16 (%rax){1to32}, %zmm5, %zmm6
