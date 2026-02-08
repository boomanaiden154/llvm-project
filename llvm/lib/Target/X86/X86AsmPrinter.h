//===-- X86AsmPrinter.h - X86 implementation of AsmPrinter ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_X86_X86ASMPRINTER_H
#define LLVM_LIB_TARGET_X86_X86ASMPRINTER_H

#include "X86TargetMachine.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/StaticDataProfileInfo.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/FaultMaps.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFunctionAnalysis.h"
#include "llvm/CodeGen/MachineFunctionAnalysisManager.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineOptimizationRemarkEmitter.h"
#include "llvm/CodeGen/MachinePassManager.h"
#include "llvm/CodeGen/StackMaps.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/Passes/CodeGenPassBuilder.h"

// Implemented in X86MCInstLower.cpp
namespace {
  class X86MCInstLower;
}

namespace llvm {
class MCStreamer;
class X86Subtarget;
class TargetMachine;

class LLVM_LIBRARY_VISIBILITY X86AsmPrinter : public AsmPrinter {
public:
  static char ID;

private:
  const X86Subtarget *Subtarget = nullptr;
  FaultMaps FM;
  std::unique_ptr<MCCodeEmitter> CodeEmitter;
  bool EmitFPOData = false;
  bool ShouldEmitWeakSwiftAsyncExtendedFramePointerFlags = false;
  bool IndCSPrefix = false;
  bool EnableImportCallOptimization = false;
  bool SplitChainedAtEndOfBlock = false;

  enum ImportCallKind : unsigned {
    IMAGE_RETPOLINE_AMD64_IMPORT_BR = 0x02,
    IMAGE_RETPOLINE_AMD64_IMPORT_CALL = 0x03,
    IMAGE_RETPOLINE_AMD64_INDIR_BR = 0x04,
    IMAGE_RETPOLINE_AMD64_INDIR_CALL = 0x05,
    IMAGE_RETPOLINE_AMD64_INDIR_BR_REX = 0x06,
    IMAGE_RETPOLINE_AMD64_CFG_BR = 0x08,
    IMAGE_RETPOLINE_AMD64_CFG_CALL = 0x09,
    IMAGE_RETPOLINE_AMD64_CFG_BR_REX = 0x0A,
    IMAGE_RETPOLINE_AMD64_SWITCHTABLE_FIRST = 0x010,
    IMAGE_RETPOLINE_AMD64_SWITCHTABLE_LAST = 0x01F,
  };
  struct ImportCallInfo {
    MCSymbol *CalleeSymbol;
    ImportCallKind Kind;
  };
  DenseMap<MCSection *, std::vector<ImportCallInfo>>
      SectionToImportedFunctionCalls;

  // This utility class tracks the length of a stackmap instruction's 'shadow'.
  // It is used by the X86AsmPrinter to ensure that the stackmap shadow
  // invariants (i.e. no other stackmaps, patchpoints, or control flow within
  // the shadow) are met, while outputting a minimal number of NOPs for padding.
  //
  // To minimise the number of NOPs used, the shadow tracker counts the number
  // of instruction bytes output since the last stackmap. Only if there are too
  // few instruction bytes to cover the shadow are NOPs used for padding.
  class StackMapShadowTracker {
  public:
    void startFunction(MachineFunction &MF) {
      this->MF = &MF;
    }
    void count(const MCInst &Inst, const MCSubtargetInfo &STI,
               MCCodeEmitter *CodeEmitter);

    // Called to signal the start of a shadow of RequiredSize bytes.
    void reset(unsigned RequiredSize) {
      RequiredShadowSize = RequiredSize;
      CurrentShadowSize = 0;
      InShadow = true;
    }

    // Called before every stackmap/patchpoint, and at the end of basic blocks,
    // to emit any necessary padding-NOPs.
    void emitShadowPadding(MCStreamer &OutStreamer, const MCSubtargetInfo &STI);
  private:
    const MachineFunction *MF = nullptr;
    bool InShadow = false;

    // RequiredShadowSize holds the length of the shadow specified in the most
    // recently encountered STACKMAP instruction.
    // CurrentShadowSize counts the number of bytes encoded since the most
    // recently encountered STACKMAP, stopping when that number is greater than
    // or equal to RequiredShadowSize.
    unsigned RequiredShadowSize = 0, CurrentShadowSize = 0;
  };

  StackMapShadowTracker SMShadowTracker;

  // All instructions emitted by the X86AsmPrinter should use this helper
  // method.
  //
  // This helper function invokes the SMShadowTracker on each instruction before
  // outputting it to the OutStream. This allows the shadow tracker to minimise
  // the number of NOPs used for stackmap padding.
  void EmitAndCountInstruction(MCInst &Inst);
  void LowerSTACKMAP(const MachineInstr &MI);
  void LowerPATCHPOINT(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerSTATEPOINT(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerFAULTING_OP(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerPATCHABLE_OP(const MachineInstr &MI, X86MCInstLower &MCIL);

  void LowerTlsAddr(X86MCInstLower &MCInstLowering, const MachineInstr &MI);

  // XRay-specific lowering for X86.
  void LowerPATCHABLE_FUNCTION_ENTER(const MachineInstr &MI,
                                     X86MCInstLower &MCIL);
  void LowerPATCHABLE_RET(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerPATCHABLE_TAIL_CALL(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerPATCHABLE_EVENT_CALL(const MachineInstr &MI, X86MCInstLower &MCIL);
  void LowerPATCHABLE_TYPED_EVENT_CALL(const MachineInstr &MI,
                                       X86MCInstLower &MCIL);

  void LowerFENTRY_CALL(const MachineInstr &MI, X86MCInstLower &MCIL);

  // KCFI specific lowering for X86.
  uint32_t MaskKCFIType(uint32_t Value);
  void EmitKCFITypePadding(const MachineFunction &MF, bool HasType = true);
  void LowerKCFI_CHECK(const MachineInstr &MI);

  // Address sanitizer specific lowering for X86.
  void LowerASAN_CHECK_MEMACCESS(const MachineInstr &MI);

  // Choose between emitting .seh_ directives and .cv_fpo_ directives.
  void EmitSEHInstruction(const MachineInstr *MI);

  void PrintSymbolOperand(const MachineOperand &MO, raw_ostream &O) override;
  void PrintOperand(const MachineInstr *MI, unsigned OpNo, raw_ostream &O);
  void PrintModifiedOperand(const MachineInstr *MI, unsigned OpNo,
                            raw_ostream &O, StringRef Modifier = {});
  void PrintPCRelImm(const MachineInstr *MI, unsigned OpNo, raw_ostream &O);
  void PrintLeaMemReference(const MachineInstr *MI, unsigned OpNo,
                            raw_ostream &O, StringRef Modifier = {});
  void PrintMemReference(const MachineInstr *MI, unsigned OpNo, raw_ostream &O,
                         StringRef Modifier = {});
  void PrintIntelMemReference(const MachineInstr *MI, unsigned OpNo,
                              raw_ostream &O, StringRef Modifier = {});
  const MCSubtargetInfo *getIFuncMCSubtargetInfo() const override;
  void emitMachOIFuncStubBody(Module &M, const GlobalIFunc &GI,
                              MCSymbol *LazyPointer) override;
  void emitMachOIFuncStubHelperBody(Module &M, const GlobalIFunc &GI,
                                    MCSymbol *LazyPointer) override;

  void emitCallInstruction(const llvm::MCInst &MCI);
  void maybeEmitNopAfterCallForWindowsEH(const MachineInstr *MI);

  // Emits a label to mark the next instruction as being relevant to Import Call
  // Optimization.
  void emitLabelAndRecordForImportCallOptimization(ImportCallKind Kind);

public:
  X86AsmPrinter(TargetMachine &TM, MCStreamer *Streamer);

  StringRef getPassName() const override {
    return "X86 Assembly Printer";
  }

  const X86Subtarget &getSubtarget() const { return *Subtarget; }

  void emitStartOfAsmFile(Module &M) override;

  void emitEndOfAsmFile(Module &M) override;

  void emitInstruction(const MachineInstr *MI) override;

  void emitInlineAsmEnd(const MCSubtargetInfo &StartInfo,
                        const MCSubtargetInfo *EndInfo,
                        const MachineInstr *MI) override;

  void emitBasicBlockEnd(const MachineBasicBlock &MBB) override;

  bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                       const char *ExtraCode, raw_ostream &O) override;
  bool PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNo,
                             const char *ExtraCode, raw_ostream &O) override;

  bool doInitialization(Module &M) override {
    SMShadowTracker.reset(0);
    SM.reset();
    FM.reset();
    return AsmPrinter::doInitialization(M);
  }

  bool runOnMachineFunction(MachineFunction &MF) override;
  void emitFunctionBodyStart() override;
  void emitFunctionBodyEnd() override;
  void emitKCFITypeId(const MachineFunction &MF) override;

  bool shouldEmitWeakSwiftAsyncExtendedFramePointerFlags() const override {
    return ShouldEmitWeakSwiftAsyncExtendedFramePointerFlags;
  }

  std::function<ProfileSummaryInfo *(Module &)> GetPSI;
  std::function<StaticDataProfileInfo *(Module &)> GetSDPI;
};

class X86AsmPrinterBeginPass : public PassInfoMixin<X86AsmPrinterBeginPass> {
public:
  X86AsmPrinterBeginPass(TargetMachine &TM, CreateMCStreamer CreateAsmStreamer)
      : TM(TM), CreateStreamer(CreateAsmStreamer) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    MachineModuleInfo &MMI = MAM.getResult<MachineModuleAnalysis>(M).getMMI();
    MMI.OutStreamer = cantFail(CreateStreamer(TM));
    X86AsmPrinter AsmPrinter(TM, MMI.OutStreamer.get());
    AsmPrinter.GetPSI = [&MAM](Module &M) {
      return &MAM.getResult<ProfileSummaryAnalysis>(M);
    };
    AsmPrinter.GetSDPI = [](Module &M) { return nullptr; };
    setupAsmPrinter(M, MAM, AsmPrinter);
    AsmPrinter.doInitialization(M);
    return PreservedAnalyses::all();
  }

private:
  TargetMachine &TM;
  CreateMCStreamer CreateStreamer;
};

class X86AsmPrinterPass : public PassInfoMixin<X86AsmPrinterPass> {
public:
  X86AsmPrinterPass(TargetMachine &TM)
      : TM(TM) {}

  PreservedAnalyses run(MachineFunction &MF, MachineFunctionAnalysisManager &MFAM) {
    const ModuleAnalysisManagerMachineFunctionProxy::Result &MAMProxy =
        MFAM.getResult<ModuleAnalysisManagerMachineFunctionProxy>(MF);
    MachineModuleInfo &MMI = MAMProxy
                                 .getCachedResult<MachineModuleAnalysis>(
                                     *MF.getFunction().getParent())
                                 ->getMMI();
    X86AsmPrinter AsmPrinter(TM, MMI.OutStreamer.get());
    AsmPrinter.GetPSI = [&MAMProxy](Module &M) {
      return MAMProxy.getCachedResult<ProfileSummaryAnalysis>(M);
    };
    AsmPrinter.GetSDPI = [](Module &M) { return nullptr; };
    AsmPrinter.GetMMI = [&MMI]() {
      return &MMI;
    };
    AsmPrinter.GetORE = [&MFAM](MachineFunction &MF) {
      return &MFAM.getResult<MachineOptimizationRemarkEmitterAnalysis>(MF);
    };
    AsmPrinter.GetMDT = [&MFAM](MachineFunction &MF) {
      return &MFAM.getResult<MachineDominatorTreeAnalysis>(MF);
    };
    AsmPrinter.GetMLI = [&MFAM](MachineFunction &MF) {
      return &MFAM.getResult<MachineLoopAnalysis>(MF);
    };
    AsmPrinter.MMI = &MMI;
    AsmPrinter.runOnMachineFunction(MF);
    return PreservedAnalyses::all();
  }

private:
  TargetMachine &TM;
};

class X86AsmPrinterEndPass : public PassInfoMixin<X86AsmPrinterEndPass> {
public:
  X86AsmPrinterEndPass(TargetMachine &TM) : TM(TM) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    MachineModuleInfo &MMI = MAM.getResult<MachineModuleAnalysis>(M).getMMI();
    X86AsmPrinter AsmPrinter(TM, MMI.OutStreamer.get());
    AsmPrinter.GetPSI = [&MAM](Module &M) {
      return &MAM.getResult<ProfileSummaryAnalysis>(M);
    };
    AsmPrinter.GetSDPI = [](Module &M) { return nullptr; };
    AsmPrinter.MMI = &MMI;
    setupAsmPrinter(M, MAM, AsmPrinter);
    AsmPrinter.doFinalization(M);
    return PreservedAnalyses::all();
  }
private:
  TargetMachine &TM;
};

} // end namespace llvm

#endif
