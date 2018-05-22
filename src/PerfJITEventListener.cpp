/*
 * An interface to notify object emission in 
 */
 
#include "llvm/ADT/Twine.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/SymbolSize.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"

#include "locks.h"

#include <sys/mman.h>  // mmap()
#include <sys/types.h> // getpid()
#include <time.h>      // clock_gettime(), time(), localtime_r() 
#include <unistd.h>    // for getpid(), read(), close()

using namespace llvm;
using namespace llvm::object;

typedef DILineInfoSpecifier::FileLineInfoKind FileLineInfoKind;

namespace {

//From llvm review D44890
// language identifier (XXX: should we generate something better from debug
// info?)
#define JIT_LANG "llvm-IR"
#define LLVM_PERF_JIT_MAGIC                                                    \
  ((uint32_t)'J' << 24 | (uint32_t)'i' << 16 | (uint32_t)'T' << 8 |            \
   (uint32_t)'D')
#define LLVM_PERF_JIT_VERSION 1

// bit 0: set if the jitdump file is using an architecture-specific timestamp
// clock source
#define JITDUMP_FLAGS_ARCH_TIMESTAMP (1ULL << 0)

struct LLVMPerfJitHeader;

class PerfJITEventListener : public JITEventListener {
    
public:
    PerfJITEventListener();
    ~PerfJITEventListener()  {
        if(MarkerAddr)
            CloseMarker();
    }

    void NotifyObjectEmitted( const ObjectFile &Obj, const RuntimeDyld::LoadedObjectInfo &L) override;
    void NotifyFreeingObject(const ObjectFile &Obj) override;

private:
    bool InitDebuggingDir();
    bool OpenMarker();
    void CloseMarker();
    static bool FillMachine(LLVMPerfJitHeader &hdr);

    void NotifyCode(Expected<llvm::StringRef> &Symbol, uint64_t CodeAddr,
                    uint64_t CodeSize);
    void NotifyDebug(uint64_t CodeAddr, DILineInfoTable Lines);

    // cache lookups
    pid_t Pid;

    // base directory for output data
    std::string JitPath;

    // output data stream, closed via Dumpstream
    int DumpFd = -1;

    // output data stream
    std::unique_ptr<raw_fd_ostream> Dumpstream;

    // perf mmap marker
    void *MarkerAddr = NULL;

    // perf support ready
    bool SuccessfullyInitialized = false;

    // identifier for functions, primarily to identify when moving them around
    uint64_t CodeGeneration = 1;
};

// The following are POD struct definitions from the perf jit specification

enum LLVMPerfJitRecordType {
    JIT_CODE_LOAD = 0,
    JIT_CODE_MOVE = 1, // not emitted, code isn't moved
    JIT_CODE_DEBUG_INFO = 2,
    JIT_CODE_CLOSE = 3,          // not emitted, unnecessary
    JIT_CODE_UNWINDING_INFO = 4, // not emitted

    JIT_CODE_MAX
};

struct LLVMPerfJitHeader {
    uint32_t Magic;     // characters "JiTD"
    uint32_t Version;   // header version
    uint32_t TotalSize; // total size of header
    uint32_t ElfMach;   // elf mach target
    uint32_t Pad1;      // reserved
    uint32_t Pid;
    uint64_t Timestamp; // timestamp
    uint64_t Flags;     // flags
};

// record prefix (mandatory in each record)
struct LLVMPerfJitRecordPrefix {
    uint32_t Id; // record type identifier
    uint32_t TotalSize;
    uint64_t Timestamp;
};

struct LLVMPerfJitRecordCodeLoad {
    LLVMPerfJitRecordPrefix Prefix;

    uint32_t Pid;
    uint32_t Tid;
    uint64_t Vma;
    uint64_t CodeAddr;
    uint64_t CodeSize;
    uint64_t CodeIndex;
};

struct LLVMPerfJitDebugEntry {
    uint64_t Addr;
    int Lineno;  // source line number starting at 1
    int Discrim; // column discriminator, 0 is default
    // followed by null terminated filename, \xff\0 if same as previous entry
};

struct LLVMPerfJitRecordDebugInfo {
    LLVMPerfJitRecordPrefix Prefix;

    uint64_t CodeAddr;
    uint64_t NrEntry;
    // followed by NrEntry LLVMPerfJitDebugEntry records
};

static inline uint64_t timespec_to_ns(const struct timespec *ts) {
    const uint64_t NanoSecPerSec = 1000000000;
    return ((uint64_t)ts->tv_sec * NanoSecPerSec) + ts->tv_nsec;
}

static inline uint64_t perf_get_timestamp(void) {
    struct timespec ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret)
    return 0;

    return timespec_to_ns(&ts);
}

PerfJITEventListener::PerfJITEventListener() : Pid(::getpid()) {
    if(!perf_get_timestamp()) {
        errs() << "kernel does not support CLOCK_MONOTONIC\n";
        return;
    }

    if(!InitDebuggingDir()) {
        errs() << "could not initialize debugging directory\n";
        return;
    }

    std::string Filename;
    raw_string_ostream FilenameBuf(Filename);
    FilenameBuf << JitPath << "jit-" << Pid << ".dump" ;
    
    // Need to open ourselves, because we need to hand the FD to OpenMarker() and
    // raw_fd_ostream doesn't expose the FD.
    using sys::fs::openFileForWrite;
    if (auto EC =
            openFileForWrite(FilenameBuf.str(), DumpFd, sys::fs::F_RW, 0666)) {
      errs() << "could not open JIT dump file " << FilenameBuf.str() << ": "
             << EC.message() << "\n";
      return;
    }
}

void PerfJITEventListener::NotifyObjectEmitted(const ObjectFile &Obj, const RuntimeDyld::LoadedObjectInfo &L) {
    
    if(!SuccessfullyInitialized)
        return;

    OwningBinary<ObjectFile> DebugObjOwner = L.getObjectForDebug(Obj);
    const ObjectFile &DebugObj = *DebugObjOwner.getBinary();

      // Get the address of the object image for use as a unique identifier
    std::unique_ptr<DIContext> Context = DWARFContext::create(DebugObj);

    // Use symbol info to iterate over functions in the object.
    for (const std::pair<SymbolRef, uint64_t> &P : computeSymbolSizes(DebugObj)) {
    SymbolRef Sym = P.first;
    std::string SourceFileName;

    Expected<SymbolRef::Type> SymTypeOrErr = Sym.getType();
    if (!SymTypeOrErr) {
      // There's not much we can with errors here
      consumeError(SymTypeOrErr.takeError());
      continue;
    }
    SymbolRef::Type SymType = *SymTypeOrErr;
    if (SymType != SymbolRef::ST_Function)
      continue;

    Expected<StringRef> Name = Sym.getName();
    if (!Name) {
      consumeError(Name.takeError());
      continue;
    }

    Expected<uint64_t> AddrOrErr = Sym.getAddress();
    if (!AddrOrErr) {
      consumeError(AddrOrErr.takeError());
      continue;
    }
    uint64_t Addr = *AddrOrErr;
    uint64_t Size = P.second;

    // According to spec debugging info has to come before loading the
    // corresonding code load.
    DILineInfoTable Lines = Context->getLineInfoForAddressRange(
        Addr, Size, FileLineInfoKind::AbsoluteFilePath);

    NotifyDebug(Addr, Lines);
    NotifyCode(Name, Addr, Size);
    }

    Dumpstream->flush();
}

void PerfJITEventListener::NotifyFreeingObject(const ObjectFile &Obj) {
    // TODO Well it seems that perf does not have an interface for object
    // unloading. The LLVM patch seems to achieve this by munmap()ing the
    // code section.
}

bool PerfJITEventListener::InitDebuggingDir() {
    time_t t = std::time(0);
    std::tm* now = std::localtime(&t);
    char TimeBuffer[sizeof("YYYYMMDD")];
    SmallString<64> Path;

    // search for location to dump data to
    if (const char *BaseDir = getenv("JITDUMPDIR"))
        Path.append(BaseDir);
    else if (!sys::path::home_directory(Path))
        Path = ".";

    // create debug directory
    Path += "/.debug/jit/";
    if (auto EC = sys::fs::create_directories(Path)) {
        errs() << "could not create jit cache directory " << Path << ": "
             << EC.message() << "\n";
        return false;
    }

    // create unique directory for dump data related to this process

    strftime(TimeBuffer, sizeof(TimeBuffer), "%Y%m%d", now);
    Path += JIT_LANG "-jit-";
    Path += TimeBuffer;

    SmallString<128> UniqueDebugDir;

    using sys::fs::createUniqueDirectory;
    if (auto EC = createUniqueDirectory(Path, UniqueDebugDir)) {
        errs() << "could not create unique jit cache directory " << UniqueDebugDir
             << ": " << EC.message() << "\n";
        return false;
    }

    JitPath = UniqueDebugDir.str();

    return true;
}
bool PerfJITEventListener::OpenMarker() {
	// We mmap the jitdump to create an MMAP RECORD in perf.data file.  The mmap
	// is captured either live (perf record running when we mmap) or in deferred
	// mode, via /proc/PID/maps. The MMAP record is used as a marker of a jitdump
	// file for more meta data info about the jitted code. Perf report/annotate
	// detect this special filename and process the jitdump file.
	//
	// Mapping must be PROT_EXEC to ensure it is captured by perf record
	// even when not using -d option.
	MarkerAddr = ::mmap(NULL, sys::Process::getPageSize(), PROT_READ | PROT_EXEC,
						MAP_PRIVATE, DumpFd, 0);

	if (MarkerAddr == MAP_FAILED) {
	  errs() << "could not mmap JIT marker\n";
	  return false;
	}
	return true;
}

void PerfJITEventListener::CloseMarker() {
	if (!MarkerAddr)
	  return;

	munmap(MarkerAddr, sys::Process::getPageSize());
	MarkerAddr = nullptr;
}

bool PerfJITEventListener::FillMachine(LLVMPerfJitHeader &hdr) {
    ssize_t sret;
    char id[16];
    int SelfFD;
    
	struct {
		uint16_t e_type;
        uint16_t e_machine;
    } info;
    
    using sys::fs::openFileForRead;
    if (auto EC = openFileForRead("/proc/self/exe", SelfFD)) {
    	errs() << "could not open /proc/self/exe: " << EC.message() << "\n";
        return false;   
	}

    sret = ::read(SelfFD, id, sizeof(id));
    if (sret != sizeof(id)) {
    	errs() << "could not read elf signature from /proc/self/exe\n";
    	::close(SelfFD);
        return false;
     }
    
	// check ELF signature
    if (id[0] != 0x7f || id[1] != 'E' || id[2] != 'L' || id[3] != 'F') {
        errs() << "Elf object signature is not valid\n";
		::close(SelfFD);
		return false;
	}	

	sret = ::read(SelfFD, &info, sizeof(info));
    if (sret != sizeof(info)) {
		errs() << "Could not read machine identification\n";
		::close(SelfFD);
		return false;
    }

    hdr.ElfMach = info.e_machine;
	::close(SelfFD);
	return true;
}


void PerfJITEventListener::NotifyCode(Expected<llvm::StringRef> &Symbol,
                                      uint64_t CodeAddr, uint64_t CodeSize) {

    // 0 length functions can't have samples.
    if (CodeSize == 0)
      return;

    LLVMPerfJitRecordCodeLoad rec;
    rec.Prefix.Id = JIT_CODE_LOAD;
    rec.Prefix.TotalSize = sizeof(rec) +        // debug record itself
                           Symbol->size() + 1 + // symbol name
                           CodeSize;            // and code
    rec.Prefix.Timestamp = perf_get_timestamp();

    rec.CodeSize = CodeSize;
    rec.Vma = 0;
    rec.CodeAddr = CodeAddr;
    rec.Pid = Pid;
    rec.Tid = get_threadid();

    rec.CodeIndex = CodeGeneration++; // under lock!

    Dumpstream->write(reinterpret_cast<const char *>(&rec), sizeof(rec));
    Dumpstream->write(Symbol->data(), Symbol->size() + 1);
    Dumpstream->write(reinterpret_cast<const char *>(CodeAddr), CodeSize);

}

void PerfJITEventListener::NotifyDebug(uint64_t CodeAddr,
									 DILineInfoTable Lines) {
	assert(SuccessfullyInitialized);

	// Didn't get useful debug info.
	if (Lines.empty())
	  return;

	LLVMPerfJitRecordDebugInfo rec;
	rec.Prefix.Id = JIT_CODE_DEBUG_INFO;
	rec.Prefix.TotalSize = sizeof(rec); // will be increased further
	rec.Prefix.Timestamp = perf_get_timestamp();
	rec.CodeAddr = CodeAddr;
	rec.NrEntry = Lines.size();

	// compute total size size of record (variable due to filenames)
	DILineInfoTable::iterator Begin = Lines.begin();
	DILineInfoTable::iterator End = Lines.end();
	for (DILineInfoTable::iterator It = Begin; It != End; ++It) {
		DILineInfo &line = It->second;
		rec.Prefix.TotalSize += sizeof(LLVMPerfJitDebugEntry);
		rec.Prefix.TotalSize += line.FileName.size() + 1;
	}

	// The debug_entry describes the source line information. It is defined as
	// follows in order:
	// * uint64_t code_addr: address of function for which the debug information
	// is generated
	// * uint32_t line     : source file line number (starting at 1)
	// * uint32_t discrim  : column discriminator, 0 is default
	// * char name[n]      : source file name in ASCII, including null termination


	Dumpstream->write(reinterpret_cast<const char *>(&rec), sizeof(rec));

	for (DILineInfoTable::iterator It = Begin; It != End; ++It) {
		LLVMPerfJitDebugEntry LineInfo;
		DILineInfo &Line = It->second;

		LineInfo.Addr = It->first;
		// The function re-created by perf is preceded by a elf
		// header. Need to adjust for that, otherwise the results are
		// wrong.
		LineInfo.Addr += 0x40;
		LineInfo.Lineno = Line.Line;
		LineInfo.Discrim = Line.Discriminator;
		
		Dumpstream->write(reinterpret_cast<const char *>(&LineInfo),
						sizeof(LineInfo));
		Dumpstream->write(Line.FileName.c_str(), Line.FileName.size() + 1);
	}
}

// llvm::ManagedStatic<PerfJITEventListener> PerfEventListener;

// JITEventListener PerfJITEventListener::createPerfJITEventListener() {
//     return &*PerfEventListener;
// }

JITEventListener *CreatePerfJITEventListener() {
    return new PerfJITEventListener();
}

} // end anonymous namespace

// LLVMJITEventListenerRef LLVMCreatePerfJITEventListener(void) {
//     return wrap(JITEventListener::createPerfJITEventListener());
// }
