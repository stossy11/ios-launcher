// Based on: https://blog.xpnsec.com/restoring-dyld-memory-loading
// https://github.com/xpn/DyldDeNeuralyzer/blob/main/DyldDeNeuralyzer/DyldPatch/dyldpatch.m

#import "src/components/LogUtils.h"
#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "utils.h"

extern void EKJITLessHook(void* _target, void* _replacement, void** orig);

#define ASM(...) __asm__(#__VA_ARGS__)

// Signatures to search for
static char mmapSig[] = { 0xB0, 0x18, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4 };
static char fcntlSig[] = { 0x90, 0x0B, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4 };

extern void* __mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset);
extern int __fcntl(int fildes, int cmd, void* param);

typedef int (*fcntl_p)(int fildes, int cmd, void* param);
typedef void* (*mmap_p)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);

static bool redirectFunction(char *name, void *patchAddr, void *target, void **orig) {
	EKJITLessHook(patchAddr, target, orig);

	AppLog(@"[TXM] hook %s succeed!", name);
	return TRUE;
}

static bool searchAndPatch(char* name, char* base, char* signature, int length, void* target, void **orig) {
	char* patchAddr = NULL;

	AppLog(@"[TXM] searching for %s...", name, patchAddr);
	// TODO: maybe add a condition for if the user really has dopamine, considering that I may need to look further into the address space
	// but it crashes if I have it too big!? wacky
	// for(int i=0; i < 0x100000; i++) {
	for (int i = 0; i < 0x80000; i++) { // i+=4
		if (base[i] == signature[0] && memcmp(base + i, signature, length) == 0) {
			patchAddr = base + i;
			break;
		}
	}

	if (patchAddr == NULL) {
		AppLog(@"[TXM] hook %s fails line %d", name, __LINE__);
		return FALSE;
	}

	AppLog(@"[TXM] found %s at %p", name, patchAddr);
	return redirectFunction(name, patchAddr, target, orig);
}

static struct dyld_all_image_infos* _alt_dyld_get_all_image_infos() {
	static struct dyld_all_image_infos* result;
	if (result) {
		return result;
	}
	struct task_dyld_info dyld_info;
	mach_vm_address_t image_infos;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	kern_return_t ret;
	ret = task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
	if (ret != KERN_SUCCESS) {
		return NULL;
	}
	image_infos = dyld_info.all_image_info_addr;
	result = (struct dyld_all_image_infos*)image_infos;
	return result;
}

static void* getDyldBase(void) { return (void*)_alt_dyld_get_all_image_infos()->dyldImageLoadAddress; }
/*
static void BreakMarkJITMapping(uint64_t addr, size_t bytes) {
    asm volatile (
        "mov x0, %0\n"
        "mov x1, %1\n"
        "brk #0x69"
        :
        : "r" (addr), "r" (bytes)
        : "x0", "x1"
    );
}
*/

__attribute__((noinline,optnone,naked))
void* JIT26PrepareRegion(void *addr, size_t len) {
    asm("mov x16, #1 \n"
        "brk #0xf00d \n"
        "ret");
}

static void* common_hooked_mmap(mmap_p orig, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    void *map = orig(addr, len, prot, flags, fd, offset);
    if (map == MAP_FAILED && fd && (prot & PROT_EXEC)) {
        
        map = __mmap(addr, len, prot, flags | MAP_PRIVATE | MAP_ANON, 0, 0);
        
        JIT26PrepareRegion(map, len);
        
        void *memoryLoadedFile = __mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, offset);
        // mirror `addr` (rx, JIT applied) to `mirrored` (rw)
        vm_address_t mirrored = 0;
        vm_prot_t cur_prot, max_prot;
        kern_return_t ret = vm_remap(mach_task_self(), &mirrored, len, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)map, false, &cur_prot, &max_prot, VM_INHERIT_SHARE);
        if(ret == KERN_SUCCESS) {
            vm_protect(mach_task_self(), mirrored, len, NO,
                    VM_PROT_READ | VM_PROT_WRITE);
            memcpy((void*)mirrored, memoryLoadedFile, len);
            vm_deallocate(mach_task_self(), mirrored, len);
        }
        munmap(memoryLoadedFile, len);
    }
    return map;
}
static void* hooked_dyld_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    return common_hooked_mmap(__mmap, addr, len, prot, flags, fd, offset);
}

static int common_hooked_fcntl(fcntl_p orig, int fildes, int cmd, void *param) {
	if (cmd == F_ADDFILESIGS_RETURN) {
		char filePath[PATH_MAX];
		bzero(filePath, PATH_MAX);
		if (orig(fildes, F_GETPATH, filePath) != -1) {
			fsignatures_t *fsig = (fsignatures_t*)param;
			// called to check that cert covers file.. so we'll make it cover everything ;)
			fsig->fs_file_start = 0xFFFFFFFF;
			return 0;
		}
	}
	// Signature sanity check by dyld
	else if (cmd == F_CHECK_LV) {
		orig(fildes, cmd, param);
		// Just say everything is fine
		return 0;
	}
	return orig(fildes, cmd, param);
}

static int hooked_dyld_fcntl(int fildes, int cmd, void *param) {
    return common_hooked_fcntl(__fcntl, fildes, cmd, param);
}

#include <dirent.h>

BOOL has_txm() {
	if ([[NSUserDefaults standardUserDefaults] boolForKey:@"FORCE_TXM"]) return YES;
	if (@available(iOS 26.0, *)) return YES;
	if (access("/System/Volumes/Preboot/boot/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4", F_OK) == 0) return YES;
	DIR *d = opendir("/private/preboot");
    if(!d) return NO;
    struct dirent *dir;
	char txmPath[PATH_MAX];
    while ((dir = readdir(d)) != NULL) {
        if(strlen(dir->d_name) == 96) {
            snprintf(txmPath, sizeof(txmPath), "/private/preboot/%s/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4", dir->d_name);
            break;
        }
    }
    closedir(d);
    return access(txmPath, F_OK) == 0;
}

void init_bypassDyldLibValidation() {
	static BOOL bypassed;
	if (bypassed)
		return;
	bypassed = YES;

    if (!has_txm()) {
        init_bypassDyldLibValidationNonTXM();
        return;
    }
	AppLog(@"init (TXM)");
    // ty https://github.com/LiveContainer/LiveContainer/tree/jitless
    char* dyldBase = getDyldBase();
    // so what is the point of orig if youre not going to use it!? i mean okay you do use it but why in params!?
    searchAndPatch("dyld_mmap", dyldBase, mmapSig, sizeof(mmapSig), hooked_dyld_mmap, NULL);
    searchAndPatch("dyld_fcntl", dyldBase, fcntlSig, sizeof(fcntlSig), hooked_dyld_fcntl, NULL);
}
