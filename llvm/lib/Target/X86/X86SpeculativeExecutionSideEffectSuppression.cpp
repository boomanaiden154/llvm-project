//===-- X86SpeculativeExecutionSideEffectSuppression.cpp ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This file contains the X86 implementation of the speculative execution side
/// effect suppression mitigation.
///
/// This must be used with the -mlvi-cfi flag in order to mitigate indirect
/// branches and returns.
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Pass.h"
#include "llvm/Target/TargetMachine.h"
using namespace llvm;

#define DEBUG_TYPE "x86-seses"

STATISTIC(NumLFENCEsInserted, "Number of lfence instructions inserted");

static cl::opt<bool> EnableSpeculativeExecutionSideEffectSuppression(
    "x86-seses-enable-without-lvi-cfi",
    cl::desc("Force enable speculative execution side effect suppression. "
             "(Note: User must pass -mlvi-cfi in order to mitigate indirect "
             "branches and returns.)"),
    cl::init(false), cl::Hidden);

static cl::opt<bool> OneLFENCEPerBasicBlock(
    "x86-seses-one-lfence-per-bb",
    cl::desc(
        "Omit all lfences other than the first to be placed in a basic block."),
    cl::init(false), cl::Hidden);

namespace {

constexpr StringRef X86SESESPassName =
    "X86 Speculative Execution Side Effect Suppression";

class X86SpeculativeExecutionSideEffectSuppressionLegacy
    : public MachineFunctionPass {
public:
  X86SpeculativeExecutionSideEffectSuppressionLegacy()
      : MachineFunctionPass(ID) {}

  static char ID;
  StringRef getPassName() const override { return X86SESESPassName; }

  bool runOnMachineFunction(MachineFunction &MF) override;
};
} // namespace

char X86SpeculativeExecutionSideEffectSuppressionLegacy::ID = 0;

// This function returns whether the passed instruction uses a memory addressing
// mode that is constant. We treat all memory addressing modes that read
// from a register that is not %rip as non-constant. Note that the use
// of the EFLAGS register results in an addressing mode being considered
// non-constant, therefore all JCC instructions will return false from this
// function since one of their operands will always be the EFLAGS register.
static bool hasConstantAddressingMode(const MachineInstr &MI) {
  for (const MachineOperand &MO : MI.uses())
    if (MO.isReg() && X86::RIP != MO.getReg())
      return false;
  return true;
}

bool runX86SpeculativeExecutionSideEffectSuppression(MachineFunction &MF) {

  const auto &OptLevel = MF.getTarget().getOptLevel();
  const X86Subtarget &Subtarget = MF.getSubtarget<X86Subtarget>();

  // Check whether SESES needs to run as the fallback for LVI at O0, whether the
  // user explicitly passed an SESES flag, or whether the SESES target feature
  // was set.
  if (!EnableSpeculativeExecutionSideEffectSuppression &&
      !(Subtarget.useLVILoadHardening() && OptLevel == CodeGenOptLevel::None) &&
      !Subtarget.useSpeculativeExecutionSideEffectSuppression())
    return false;

  LLVM_DEBUG(dbgs() << "********** " << X86SESESPassName << " : "
                    << MF.getName() << " **********\n");
  bool Modified = false;
  const X86InstrInfo *TII = Subtarget.getInstrInfo();
  for (MachineBasicBlock &MBB : MF) {
    MachineInstr *FirstTerminator = nullptr;
    // Keep track of whether the previous instruction was an LFENCE to avoid
    // adding redundant LFENCEs.
    bool PrevInstIsLFENCE = false;
    for (auto &MI : MBB) {

      if (MI.getOpcode() == X86::LFENCE) {
        PrevInstIsLFENCE = true;
        continue;
      }
      // We want to put an LFENCE before any instruction that
      // may load or store. This LFENCE is intended to avoid leaking any secret
      // data due to a given load or store. This results in closing the cache
      // and memory timing side channels. We will treat terminators that load
      // or store separately.
      if (MI.mayLoadOrStore() && !MI.isTerminator()) {
        if (!PrevInstIsLFENCE) {
          BuildMI(MBB, MI, DebugLoc(), TII->get(X86::LFENCE));
          NumLFENCEsInserted++;
          Modified = true;
        }
        if (OneLFENCEPerBasicBlock)
          break;
      }
      break;
    }
  }

  return Modified;
}

bool X86SpeculativeExecutionSideEffectSuppressionLegacy::runOnMachineFunction(
    MachineFunction &MF) {
  return runX86SpeculativeExecutionSideEffectSuppression(MF);
}

PreservedAnalyses X86SpeculativeExecutionSideEffectSuppressionPass::run(
    MachineFunction &MF, MachineFunctionAnalysisManager &MFAM) {
  return runX86SpeculativeExecutionSideEffectSuppression(MF)
             ? getMachineFunctionPassPreservedAnalyses()
                   .preserveSet<CFGAnalyses>()
             : PreservedAnalyses::all();
}

FunctionPass *
llvm::createX86SpeculativeExecutionSideEffectSuppressionLegacyPass() {
  return new X86SpeculativeExecutionSideEffectSuppressionLegacy();
}

INITIALIZE_PASS(X86SpeculativeExecutionSideEffectSuppressionLegacy, "x86-seses",
                "X86 Speculative Execution Side Effect Suppression", false,
                false)
