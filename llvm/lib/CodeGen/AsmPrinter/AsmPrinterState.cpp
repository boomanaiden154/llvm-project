//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/AsmPrinterState.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"

using namespace llvm;

INITIALIZE_PASS(AsmPrinterStateWrapperPass, "asm-printer-state",
                "Asm Printer State", false, true)
char AsmPrinterStateWrapperPass::ID = 0;

AnalysisKey AsmPrinterStateAnalysis::Key;
