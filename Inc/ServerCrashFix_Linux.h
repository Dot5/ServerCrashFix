/*=============================================================================
	ServerCrashFix_Linux.h

	Revision history:
		* Created by AnthraX
=============================================================================*/

/*-----------------------------------------------------------------------------
	Thread Locking
-----------------------------------------------------------------------------*/
#define LOCKTYPE	pthread_mutex_t

//
// Create a normal mutex
//
#define DEFINE_LOCK(LockName)\
	pthread_mutex_t LockName;

// Definition
#define INIT_LOCK(LockName)\
	pthread_mutex_init(&LockName, NULL);

//
// Locking and unlocking
// 
#define LOCK(pLockName)\
	pthread_mutex_lock(pLockName);
#define UNLOCK(pLockName)\
	pthread_mutex_unlock(pLockName);

/*-----------------------------------------------------------------------------
	Platform specific functions
-----------------------------------------------------------------------------*/
//
// Signal constant to string
//
const char* getTextualSig(DWORD dwSignal) {
    const char* result = "UNKNOWN";

#define DEF_SIGNAL(a) case a:\
    result = #a;\
    break;\

    switch(dwSignal) {
        DEF_SIGNAL(SIGALRM)
        DEF_SIGNAL(SIGHUP)
        DEF_SIGNAL(SIGINT)
        DEF_SIGNAL(SIGKILL)
        DEF_SIGNAL(SIGPIPE)
        DEF_SIGNAL(SIGPOLL)
        DEF_SIGNAL(SIGPROF)
        DEF_SIGNAL(SIGTERM)
        DEF_SIGNAL(SIGUSR1)
        DEF_SIGNAL(SIGUSR2)
        DEF_SIGNAL(SIGVTALRM)
//        DEF_SIGNAL(STKFLT) - Undefined on linux
        DEF_SIGNAL(SIGPWR)
        DEF_SIGNAL(SIGWINCH)
        DEF_SIGNAL(SIGCHLD)
        DEF_SIGNAL(SIGURG)
        DEF_SIGNAL(SIGTSTP)
        DEF_SIGNAL(SIGTTIN)
        DEF_SIGNAL(SIGTTOU)
        DEF_SIGNAL(SIGSTOP)
        DEF_SIGNAL(SIGCONT)
        DEF_SIGNAL(SIGABRT)
        DEF_SIGNAL(SIGFPE)
        DEF_SIGNAL(SIGILL)
        DEF_SIGNAL(SIGQUIT)
        DEF_SIGNAL(SIGSEGV)
        DEF_SIGNAL(SIGTRAP)
        DEF_SIGNAL(SIGSYS)
//        DEF_SIGNAL(SIGEMT) - Undefined on linux
        DEF_SIGNAL(SIGBUS)
        DEF_SIGNAL(SIGXCPU)
        DEF_SIGNAL(SIGXFSZ)
    }

    return result;
}

const char* getTextualCode(int sig, int code) {
    const char* result = "UNKNOWN";

    code = code & ~(SI_KERNEL | SI_USER);
    if (sig == SIGILL) {
		switch (code) {
			DEF_SIGNAL(ILL_ILLOPC)
			DEF_SIGNAL(ILL_ILLOPN)
			DEF_SIGNAL(ILL_ILLADR)
			DEF_SIGNAL(ILL_ILLTRP)
			DEF_SIGNAL(ILL_PRVOPC)
			DEF_SIGNAL(ILL_PRVREG)
			DEF_SIGNAL(ILL_COPROC)
			DEF_SIGNAL(ILL_BADSTK)
		}
    }
    if (sig == SIGFPE) {
		switch (code) {
			DEF_SIGNAL(FPE_INTDIV)
			DEF_SIGNAL(FPE_INTOVF)
			DEF_SIGNAL(FPE_FLTDIV)
			DEF_SIGNAL(FPE_FLTOVF)
			DEF_SIGNAL(FPE_FLTUND)
			DEF_SIGNAL(FPE_FLTRES)
			DEF_SIGNAL(FPE_FLTINV)
			DEF_SIGNAL(FPE_FLTSUB)
		}
    }
    if (sig == SIGSEGV) {
		switch (code) {
			DEF_SIGNAL(SEGV_MAPERR)
			DEF_SIGNAL(SEGV_ACCERR)
		}
    }
    if (sig == SIGBUS) {
		switch (code) {
			DEF_SIGNAL(BUS_ADRALN)
			DEF_SIGNAL(BUS_ADRERR)
			DEF_SIGNAL(BUS_OBJERR)
		}
    }
    if (sig == SIGTRAP) {
		switch (code) {
			DEF_SIGNAL(TRAP_BRKPT)
			DEF_SIGNAL(TRAP_TRACE)
		}
    }

    return result;
}


static void context_backtrace (ucontext_t *context) {
#define REG(r) context->uc_mcontext.gregs[r]
	GLog->Logf(TEXT("[SCF]     eax %08x  ebx %08x  ecx %08x  edx %08x"), REG(REG_EAX), REG(REG_EBX), REG(REG_ECX), REG(REG_EDX));
	GLog->Logf(TEXT("[SCF]     esi %08x  edi %08x  xgs %08x  xss %08x"), REG(REG_ESI), REG(REG_EDI), REG(REG_GS), REG(REG_SS));
	GLog->Logf(TEXT("[SCF]     xcs %08x  xds %08x  xes %08x  xfs %08x"), REG(REG_CS), REG(REG_DS), REG(REG_ES), REG(REG_FS));
	GLog->Logf(TEXT("[SCF]     eip %08x  ebp %08x  esp %08x  flags %08x"), REG(REG_EIP), REG(REG_EBP), REG(REG_ESP), REG(REG_EFL));
	GLog->Logf(TEXT("[SCF]     err %08x  uesp %08x  trapno %08x"), REG(REG_ERR), REG(REG_UESP), REG(REG_TRAPNO));
	GLog->Logf(TEXT("[SCF] backtrace:"));

    unsigned frame_number = 0;

    void *ip = NULL;
    void **bp = NULL;

#if defined(REG_RIP)
    ip = (void*) context->uc_mcontext.gregs[REG_RIP];
    bp = (void**) context->uc_mcontext.gregs[REG_RBP];
#elif defined(REG_EIP)
    ip = (void*) context->uc_mcontext.gregs[REG_EIP];
    bp = (void**) context->uc_mcontext.gregs[REG_EBP];
#endif

    while (bp && ip) {
        Dl_info dlinfo;
        if (!dladdr (ip, &dlinfo))
            break;

        const char *symbol = dlinfo.dli_sname;

        GLog->Logf(TEXT("[SCF]     % 2d: %p <%s+0x%lx> (%s)"),
                 ++frame_number,
                 ip,
                 symbol ? symbol : "(?)",
                 (unsigned int) ip - (unsigned int) dlinfo.dli_saddr,
                 dlinfo.dli_fname);

        if (dlinfo.dli_sname && strcmp (dlinfo.dli_sname, "main") == 0)
            break;

        ip = bp[1];
        bp = (void**) bp[0];
    }
}

/*-----------------------------------------------------------------------------
	SCF Exception handler
-----------------------------------------------------------------------------*/
static void SCFExceptionHandler(int sig, siginfo_t *siginfo, void *context) {
    static INT IsError = 0;

    if (!IsError) {
        IsError = 1;
        int j, nptrs;
        void *buffer[1000];
        char **strings;

        nptrs = backtrace(buffer, 1000);

        GLog->Logf(TEXT("[SCF] Exception Handler for pid %d"), getpid());
        GLog->Logf(TEXT("[SCF] Signal Received: %s"), ANSI_TO_TCHAR(getTextualSig(sig)));
        GLog->Logf(TEXT("[SCF] signal %d (%s), code %d (%s), errno %d, fault addr %08x"), siginfo->si_signo,
        	ANSI_TO_TCHAR(getTextualSig(siginfo->si_signo)),
        	siginfo->si_code, ANSI_TO_TCHAR(getTextualCode(siginfo->si_signo, siginfo->si_code)),
			siginfo->si_errno, siginfo->si_addr);

        if (siginfo->si_code == SI_USER) {
        	GLog->Logf(TEXT("[SCF] kill from %d %d"), siginfo->si_pid, siginfo->si_uid);
        }

        if (!context) {
        	GLog->Logf(TEXT("[SCF] NULL context"));
        } else {
        	context_backtrace ((ucontext_t*) context);
        }

        strings = backtrace_symbols(buffer, nptrs);
        if (strings == NULL) {
            GLog->Logf(TEXT("[SCF] Backtrace failed"));
            exit(EXIT_FAILURE);
        }    
    
        GLog->Logf(TEXT("[SCF] current backtrace (%d):"), nptrs);
        for (j = 0; j < nptrs; j++)
            GLog->Logf(TEXT("[SCF] %03d: %s"), j, ANSI_TO_TCHAR(strings[j]));

        GLog->Logf(TEXT("[SCF] Memory Map:"));
    
        char procname[100];
        char buf[65536];
        int pos = 0;
        sprintf(procname, "cat /proc/%d/maps", getpid());
        FILE* fp = popen(procname, "r");

        while (true) {
            int read = fread(buf + pos, 1, 1024, fp);
     	    pos += read;

            if (read < 1024 || feof(fp) || pos+1024 > 65536)
                break;            
        }

        pclose(fp);

        buf[pos] = '\0';
        char* tok = NULL;
        tok = strtok(buf, "\n");
        while (tok != NULL) {
             GLog->Logf(TEXT("[SCF] %s"), ANSI_TO_TCHAR(tok));
             tok = strtok(NULL, "\n");
        }
      
        // Check if this build supports unwind...
        /*void* corehandle = dlopen("Core.so", RTLD_NOW);
        jmp_buf* pEnv    = (jmp_buf*)dlsym(corehandle, "_9__Context.Env");
        if (dlerror() == NULL) {
             GLog->Logf(TEXT("ACE: __Context::Env found. Trying to unwind..."));
             sync();
             longjmp(*pEnv, 1);
        }*/

        appPreExit();
        appExit();        
    }
    
    exit(0);
}

//
// Platform: 1 = windows, 2 = linux 
//
DWORD FORCEINLINE appGetPlatform() {
	return 2;
}

// 
// Request highest possible resolution (usually 1ms)
// -> return 0 on linux or on error
//
DWORD appRequestTimer() {
	return 0;
}

//
// Change appSecondsSlow from GetTickCount to timeGetTime
//
UBOOL appHookAppSeconds() {
	GTimestamp = 0;
	return 1;
}

//
// Install custom signal handlers for crash reporting
//	-> Not on windows
//
UBOOL appInstallHandlers() {
	static INT Initialized = 0;

	if (Initialized == 0) {
		Initialized = 1;
		
		struct sigaction termaction;
		termaction.sa_sigaction = &SCFExceptionHandler;
		termaction.sa_flags = SA_SIGINFO;

		sigaction(SIGILL , &termaction, NULL);
		sigaction(SIGSEGV, &termaction, NULL);
		sigaction(SIGIOT , &termaction, NULL);
		sigaction(SIGBUS , &termaction, NULL);
		sigaction(SIGFPE , &termaction, NULL);
	}

	return 1;
}

// 
// Force CPU Core affinity
//
INT appSetAffinity(INT CPUCore) {
	static INT CPUSet = 0;

	if (CPUSet != 0)
		return CPUSet;
	
	int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
	if (CPUCore > numCPU-1) {
		GLog->Logf(TEXT("[SCF] appSetAffinity ERROR"));
		GLog->Logf(TEXT("[SCF] CPUCore (user-defined): %d"), CPUCore);
		GLog->Logf(TEXT("[SCF] numCPU (sysconf): %d"), numCPU);
		return 0;
	}

	unsigned long mask = 0x00000001 << CPUCore;
	unsigned int len = sizeof(mask);
	CPUSet = sched_setaffinity(0, len, (cpu_set_t*)&mask);

	return (CPUSet >= 0 ? CPUCore : -1);
}
