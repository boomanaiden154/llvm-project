//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Implements the AsmPrinterState Analysis, which holds information that
// AsmPrinter needs to propagate across functions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_ASMPRINTERSTATE_H
#define LLVM_CODEGEN_ASMPRINTERSTATE_H

#include "llvm/IR/Analysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/CodeGen/AsmPrinterHandler.h"
#include "../lib/CodeGen/AsmPrinter/EHStreamer.h"

namespace llvm {

class AsmPrinterState {
public:
  /// A handle to the EH info emitter (if present).
  // Only for EHStreamer subtypes, but some C++ compilers will incorrectly warn
  // us if we declare that directly.
  SmallVector<std::unique_ptr<EHStreamer>, 1> EHHandlers;

  // A vector of all Debuginfo emitters we should use. Protected so that
  // targets can add their own. This vector maintains ownership of the
  // emitters.
  SmallVector<std::unique_ptr<AsmPrinterHandler>, 2> Handlers;
  size_t NumUserHandlers = 0;
};

class LLVM_ABI AsmPrinterStateWrapperPass : public ImmutablePass {
  AsmPrinterState State;

public:
  LLVM_ABI static char ID;
  LLVM_ABI AsmPrinterStateWrapperPass(): ImmutablePass(ID) {}

  AsmPrinterState &getState() { return State; }
};

class LLVM_ABI AsmPrinterStateAnalysis
    : public AnalysisInfoMixin<AsmPrinterStateAnalysis> {
  AsmPrinterState State;

public:
  LLVM_ABI static AnalysisKey Key;

  class Result {
    AsmPrinterState &State;
    Result(AsmPrinterState &State) : State(State) {}
    friend class AsmPrinterStateAnalysis;

  public:
    AsmPrinterState &getState() { return State; }

    bool invalidate(Module &, const PreservedAnalyses &,
                 ModuleAnalysisManager::Invalidator &) {
      return false;
    }
  };

  LLVM_ABI Result run(Module &M, ModuleAnalysisManager &) {
    return Result(State);
  }
};

} // namespace llvm

#endif // LLVM_CODEGEN_ASMPRINTERSTATE_H
