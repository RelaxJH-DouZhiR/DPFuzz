/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// new cpp lib = start =
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <set>
#include <stack>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <dirent.h>
// new cpp lib =  end  =

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

// new llvm lib = start =
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"

#include "llvm/Analysis/CFG.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"

#include "llvm/Analysis/LoopInfo.h"
// new llvm lib =  end  =

// Global variables = start =
std::string DPFuzztmp;
// Global variables =  end  =

using namespace llvm;

namespace
{

  class AFLCoverage : public ModulePass
  {

  public:
    static char ID;
    AFLCoverage() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;

    // StringRef getPassName() const override {
    //  return "American Fuzzy Lop Instrumentation";
    // }
  };

}

//==============================================================
// tool functions =  start  =
//==============================================================

static void getInstLoc(const Instruction *I, std::string &Filename, unsigned &Line) // 获取指令的所在行
{
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown())
  {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty())
    {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc())
  {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty())
    {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc)
      {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F)
{
  static const SmallVector<std::string, 8> Blacklist = {
      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan_handle_",
      "free",
      "malloc",
      "calloc",
      "realloc"};

  for (auto const &BlacklistFunc : Blacklist)
  {
    if (F->getName().startswith(BlacklistFunc))
    {
      return true;
    }
  }

  return false;
}

std::string getBBInf(BasicBlock &BB, Function &F, int index)
{
  std::string bbInf;
  unsigned bbLine;
  for (auto &I : BB)
  {
    std::string fileName;
    unsigned line;
    getInstLoc(&I, fileName, line);
    if (bbInf.empty() && !fileName.empty() && line)
    {
      bbInf = fileName + ":" + F.getName().str() + ":" + std::to_string(line) + ":" + std::to_string(index);
      break;
    }
  }
  //
  if (bbInf != "")
  {
    std::string file = DPFuzztmp + "/instrumentation.txt";
    std::ofstream ofs;
    ofs.open(file, std::ios::app);
    ofs << bbInf << std::endl;
    ofs.close();
    //
  }
  return bbInf;
}

void ERRPRINT(std::string e)
{
  outs().changeColor(raw_ostream::RED);
  outs() << e << "\n";
  outs().resetColor();
}

void NICEPRINT(std::string n)
{
  outs().changeColor(raw_ostream::GREEN);
  outs() << n << "\n";
  outs().resetColor();
}

//==============================================================
// tool functions =  end  =
//==============================================================

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M)
{
  // DPFuzz get env = start =
  char *home;
  home = getenv("HOME");
  if (home != NULL)
  {
    DPFuzztmp = std::string(home) + "/DPFuzztmp";
    const char *path = DPFuzztmp.c_str();
    if (access(path, F_OK) != 0)
    {
      ERRPRINT("we didn't find DPFuzztmp, please check the shell script!");
    }
  }
  else
  {
    ERRPRINT("We didn't find the home path in environment variables!");
    return false;
  }
  std::string filep = DPFuzztmp + "/instrumentation.txt";
  std::ifstream file(filep);
  if (file.good())
  {
  }
  else
  {
    ERRPRINT("We didn't find instrumentation.txt, please check the shell script!");
  }

  std::string fileflagp = DPFuzztmp + "/flag.txt";
  std::ifstream fileflag(fileflagp);
  int BBindex;
  if (fileflag.good())
  {
    fileflag >> BBindex;
    fileflag.close();
  }
  else
  {
    ERRPRINT("We didn't find flag.txt, please check the shell script!");
    return false;
  }

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
  IntegerType *LargestType = Int64Ty;
  ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
  IntegerType *LargestType = Int32Ty;
  ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
  ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
  ConstantInt *One = ConstantInt::get(LargestType, 1);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET"))
  {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");
  }
  else
    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str)
  {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */
  int inst_blocks = 0;
  for (auto &F : M)
  {
    int bbnum = 0;
    if (!isBlacklisted(&F))
    {
      for (auto &BB : F)
      {
        bbnum++;
      }
    }
    int funcBBindx = 0;
    for (auto &BB : F)
    {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio)
        continue;

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      // DPFuzz ins = start =
      if (BBindex < (NEW_MAP_SIZE - 1))
      {
        ConstantInt *MapLoopInstLoc = ConstantInt::get(LargestType, MAP_SIZE + BBindex);
        if (bbnum != 0 && bbnum <= (FRONT_INS + BACK_INS))
        {
          getBBInf(BB, F, funcBBindx);
          Value *MapLoopInstPtr = IRB.CreateBitCast(IRB.CreateGEP(MapPtr, MapLoopInstLoc), LargestType->getPointerTo());
          LoadInst *MapLoopInst = IRB.CreateLoad(MapLoopInstPtr);
          MapLoopInst->setMetadata(M.getMDKindID("nonsanitize"), MDNode::get(C, None));
          Value *IncrLoopInst = IRB.CreateAdd(MapLoopInst, ConstantInt::get(Int8Ty, 1));
          IRB.CreateStore(IncrLoopInst, MapLoopInstPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          BBindex++;
        }
        else if (bbnum != 0 && bbnum > (FRONT_INS + BACK_INS))
        {
          // 函数前插桩
          if (funcBBindx < FRONT_INS)
          {
            getBBInf(BB, F, funcBBindx);
            Value *MapLoopInstPtr = IRB.CreateBitCast(IRB.CreateGEP(MapPtr, MapLoopInstLoc), LargestType->getPointerTo());
            LoadInst *MapLoopInst = IRB.CreateLoad(MapLoopInstPtr);
            MapLoopInst->setMetadata(M.getMDKindID("nonsanitize"), MDNode::get(C, None));
            Value *IncrLoopInst = IRB.CreateAdd(MapLoopInst, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(IncrLoopInst, MapLoopInstPtr)
                ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            BBindex++;
          }
          else if (funcBBindx >= (bbnum - BACK_INS))
          {
            getBBInf(BB, F, funcBBindx);
            Value *MapLoopInstPtr = IRB.CreateBitCast(IRB.CreateGEP(MapPtr, MapLoopInstLoc), LargestType->getPointerTo());
            LoadInst *MapLoopInst = IRB.CreateLoad(MapLoopInstPtr);
            MapLoopInst->setMetadata(M.getMDKindID("nonsanitize"), MDNode::get(C, None));
            Value *IncrLoopInst = IRB.CreateAdd(MapLoopInst, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(IncrLoopInst, MapLoopInstPtr)
                ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            BBindex++;
          }
        }
        // DPFuzz ins =  end  =
      }
      else
      {
        ERRPRINT("The extended bitmap is full!");
      }
      funcBBindx++;
      inst_blocks++;
    }
  }
  std::ofstream outfile(fileflagp);
  outfile << BBindex << std::endl;
  outfile.close();
  NICEPRINT("BBindex is " + std::to_string(BBindex));
  /* Say something nice. */

  if (!be_quiet)
  {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).",
          inst_blocks, getenv("AFL_HARDEN") ? "hardened" : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ? "ASAN/MSAN" : "non-hardened"), inst_ratio);
  }

  return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM)
{

  PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
