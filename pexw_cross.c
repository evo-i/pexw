#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// PE structures (platform-independent)
#pragma pack(push, 1)

typedef struct {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
} DOS_HEADER;

typedef struct {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
} FILE_HEADER;

typedef struct {
  uint32_t VirtualAddress;
  uint32_t Size;
} DATA_DIRECTORY;

#define NUM_DATA_DIRECTORIES 16

typedef struct {
  uint16_t       Magic;
  uint8_t        MajorLinkerVersion;
  uint8_t        MinorLinkerVersion;
  uint32_t       SizeOfCode;
  uint32_t       SizeOfInitializedData;
  uint32_t       SizeOfUninitializedData;
  uint32_t       AddressOfEntryPoint;
  uint32_t       BaseOfCode;
  uint64_t       ImageBase;
  uint32_t       SectionAlignment;
  uint32_t       FileAlignment;
  uint16_t       MajorOperatingSystemVersion;
  uint16_t       MinorOperatingSystemVersion;
  uint16_t       MajorImageVersion;
  uint16_t       MinorImageVersion;
  uint16_t       MajorSubsystemVersion;
  uint16_t       MinorSubsystemVersion;
  uint32_t       Win32VersionValue;
  uint32_t       SizeOfImage;
  uint32_t       SizeOfHeaders;
  uint32_t       CheckSum;
  uint16_t       Subsystem;
  uint16_t       DllCharacteristics;
  uint64_t       SizeOfStackReserve;
  uint64_t       SizeOfStackCommit;
  uint64_t       SizeOfHeapReserve;
  uint64_t       SizeOfHeapCommit;
  uint32_t       LoaderFlags;
  uint32_t       NumberOfRvaAndSizes;
  DATA_DIRECTORY DataDirectory[NUM_DATA_DIRECTORIES];
} OPTIONAL_HEADER64;

typedef struct {
  uint32_t          Signature;
  FILE_HEADER       FileHeader;
  OPTIONAL_HEADER64 OptionalHeader;
} NT_HEADERS64;

typedef struct {
  uint8_t  Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} SECTION_HEADER;

#pragma pack(pop)

#define DOS_SIGNATURE 0x5A4D
#define NT_SIGNATURE 0x00004550
#define OPT_HDR64_MAGIC 0x20B
#define MACHINE_AMD64 0x8664

// Cross-platform structures
typedef struct {
  char     name[9];
  uint64_t virtualAddress;
  uint64_t virtualSize;
  uint64_t rawAddress;
  uint32_t rawSize;
  uint8_t* data;
} Section;

typedef struct {
  char     dataName[32];
  char     encryptedString[512];
  char     decryptedString[512];
  uint64_t rdataRVA;
  uint64_t stringRVA;
  int      found;
} DataEntry;

typedef struct {
#ifdef _WIN32
  HANDLE hFile;
  HANDLE hMapping;
#else
  int fd;
#endif
  uint8_t* pView;
  size_t   fileSize;
} MappedFile;

Section    textSection       = {0};
Section    rdataSection      = {0};
uint64_t   imageBase         = 0;
DataEntry* dataEntries       = NULL;
int        dataEntryCount    = 0;
int        dataEntryCapacity = 0;

void
decryptString(const char* encrypted, char* decrypted, int maxLen) {
  int len = strlen(encrypted);
  if (len > maxLen)
    len = maxLen;

  for (int i = 0; i < len; i++) {
    decrypted[i] = encrypted[i] ^ 0x05;
  }
  decrypted[len] = '\0';
}

void
addDataEntry(const char* name, uint64_t rdataRVA) {
  if (dataEntryCount >= dataEntryCapacity) {
    dataEntryCapacity     = dataEntryCapacity == 0 ? 100 : dataEntryCapacity * 2;
    DataEntry* newEntries = (DataEntry*)realloc(dataEntries, dataEntryCapacity * sizeof(DataEntry));
    if (newEntries) {
      dataEntries = newEntries;
      // Zero out new entries
      for (int i = dataEntryCount; i < dataEntryCapacity; i++) {
        memset(&dataEntries[i], 0, sizeof(DataEntry));
      }
    }
  }

  memset(&dataEntries[dataEntryCount], 0, sizeof(DataEntry));
  strncpy(dataEntries[dataEntryCount].dataName, name, 31);
  dataEntries[dataEntryCount].dataName[31] = '\0';
  dataEntries[dataEntryCount].rdataRVA     = rdataRVA;
  dataEntries[dataEntryCount].found        = 0;
  dataEntryCount++;
}

int
mapPEFile(const char* filename, MappedFile* mf) {
#ifdef _WIN32
  mf->hFile    = INVALID_HANDLE_VALUE;
  mf->hMapping = NULL;
  mf->pView    = NULL;
  mf->fileSize = 0;

  mf->hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
  if (mf->hFile == INVALID_HANDLE_VALUE) {
    printf("Error: Cannot open file\n");
    return 0;
  }

  mf->fileSize = GetFileSize(mf->hFile, NULL);
  if (mf->fileSize == INVALID_FILE_SIZE || mf->fileSize == 0) {
    printf("Error: Invalid file size\n");
    CloseHandle(mf->hFile);
    return 0;
  }

  mf->hMapping = CreateFileMappingA(mf->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (mf->hMapping == NULL) {
    printf("Error: Cannot create file mapping\n");
    CloseHandle(mf->hFile);
    return 0;
  }

  mf->pView = (uint8_t*)MapViewOfFile(mf->hMapping, FILE_MAP_READ, 0, 0, 0);
  if (mf->pView == NULL) {
    printf("Error: Cannot map view of file\n");
    CloseHandle(mf->hMapping);
    CloseHandle(mf->hFile);
    return 0;
  }
#else
  mf->fd       = -1;
  mf->pView    = NULL;
  mf->fileSize = 0;

  mf->fd = open(filename, O_RDONLY);
  if (mf->fd < 0) {
    printf("Error: Cannot open file\n");
    return 0;
  }

  struct stat st;
  if (fstat(mf->fd, &st) < 0) {
    printf("Error: Cannot get file size\n");
    close(mf->fd);
    return 0;
  }

  mf->fileSize = st.st_size;
  if (mf->fileSize == 0) {
    printf("Error: File is empty\n");
    close(mf->fd);
    return 0;
  }

  mf->pView = (uint8_t*)mmap(NULL, mf->fileSize, PROT_READ, MAP_PRIVATE, mf->fd, 0);
  if (mf->pView == MAP_FAILED) {
    printf("Error: Cannot map file\n");
    close(mf->fd);
    return 0;
  }
#endif

  return 1;
}

void
unmapPEFile(MappedFile* mf) {
#ifdef _WIN32
  if (mf->pView != NULL) {
    UnmapViewOfFile(mf->pView);
    mf->pView = NULL;
  }
  if (mf->hMapping != NULL) {
    CloseHandle(mf->hMapping);
    mf->hMapping = NULL;
  }
  if (mf->hFile != INVALID_HANDLE_VALUE) {
    CloseHandle(mf->hFile);
    mf->hFile = INVALID_HANDLE_VALUE;
  }
#else
  if (mf->pView != NULL && mf->pView != MAP_FAILED) {
    munmap(mf->pView, mf->fileSize);
    mf->pView = NULL;
  }
  if (mf->fd >= 0) {
    close(mf->fd);
    mf->fd = -1;
  }
#endif
}

uint64_t
rvaToFileOffset(uint64_t rva, SECTION_HEADER* sections, int numSections) {
  for (int i = 0; i < numSections; i++) {
    if (rva >= sections[i].VirtualAddress &&
        rva < sections[i].VirtualAddress + sections[i].VirtualSize) {
      return sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
    }
  }
  return 0;
}

int
parsePEHeaders(uint8_t* peData, size_t fileSize, SECTION_HEADER** outSections,
               int* outNumSections) {
  if (fileSize < sizeof(DOS_HEADER)) {
    printf("Error: File too small\n");
    return 0;
  }

  DOS_HEADER* dosHeader = (DOS_HEADER*)peData;
  if (dosHeader->e_magic != DOS_SIGNATURE) {
    printf("Error: Invalid DOS signature\n");
    return 0;
  }

  printf("[+] DOS Header: 0x%X\n", dosHeader->e_lfanew);

  uint32_t* peSignature = (uint32_t*)(peData + dosHeader->e_lfanew);
  if (*peSignature != NT_SIGNATURE) {
    printf("Error: Invalid PE signature\n");
    return 0;
  }

  printf("[+] PE Signature found\n");

  FILE_HEADER* fileHeader = (FILE_HEADER*)(peData + dosHeader->e_lfanew + 4);

  printf("[+] Machine: 0x%X\n", fileHeader->Machine);
  printf("[+] Sections: %d\n", fileHeader->NumberOfSections);

  if (fileHeader->Machine != MACHINE_AMD64) {
    printf("Error: Only x64 supported\n");
    return 0;
  }

  NT_HEADERS64* ntHeaders = (NT_HEADERS64*)(peData + dosHeader->e_lfanew);

  if (ntHeaders->OptionalHeader.Magic != OPT_HDR64_MAGIC) {
    printf("Error: Invalid Optional Header\n");
    return 0;
  }

  imageBase = ntHeaders->OptionalHeader.ImageBase;
  printf("[+] Image Base: 0x%llX\n", (unsigned long long)imageBase);

  *outSections =
      (SECTION_HEADER*)((uint8_t*)&ntHeaders->OptionalHeader + fileHeader->SizeOfOptionalHeader);
  *outNumSections = fileHeader->NumberOfSections;

  return 1;
}

int
loadSections(uint8_t* peData, size_t fileSize, SECTION_HEADER* sections, int numSections) {
  printf("\n[*] Loading sections:\n");

  for (int i = 0; i < numSections; i++) {
    char sectionName[9] = {0};
    memcpy(sectionName, sections[i].Name, 8);

    printf("[+] %s VA=0x%X Size=0x%X\n", sectionName, sections[i].VirtualAddress,
           sections[i].VirtualSize);

    if (strcmp(sectionName, ".text") == 0) {
      strncpy(textSection.name, sectionName, 8);
      textSection.virtualAddress = sections[i].VirtualAddress;
      textSection.virtualSize    = sections[i].VirtualSize;
      textSection.rawAddress     = sections[i].PointerToRawData;
      textSection.rawSize        = sections[i].SizeOfRawData;
      textSection.data           = peData + sections[i].PointerToRawData;
    }

    if (strcmp(sectionName, ".rdata") == 0) {
      strncpy(rdataSection.name, sectionName, 8);
      rdataSection.virtualAddress = sections[i].VirtualAddress;
      rdataSection.virtualSize    = sections[i].VirtualSize;
      rdataSection.rawAddress     = sections[i].PointerToRawData;
      rdataSection.rawSize        = sections[i].SizeOfRawData;
      rdataSection.data           = peData + sections[i].PointerToRawData;
    }
  }

  if (!textSection.data || !rdataSection.data) {
    printf("Error: Required sections not found\n");
    return 0;
  }

  return 1;
}

int
findDataMarkers() {
  printf("\n[*] Scanning for dataXX markers...\n");

  for (uint32_t i = 0; i < rdataSection.rawSize - 7; i++) {
    uint8_t* ptr = rdataSection.data + i;

    if (ptr[0] == 'd' && ptr[1] == 'a' && ptr[2] == 't' && ptr[3] == 'a') {
      if ((ptr[4] >= '0' && ptr[4] <= '9') && (ptr[5] >= '0' && ptr[5] <= '9')) {

        char name[32] = {0};
        int  j        = 0;
        while (j < 31 && ptr[j] != '\0' && (j < 4 || (ptr[j] >= '0' && ptr[j] <= '9'))) {
          name[j] = ptr[j];
          j++;
        }
        name[j] = '\0';

        uint64_t rva = rdataSection.virtualAddress + i;
        addDataEntry(name, rva);

        printf("[+] %s at 0x%llX\n", name, (unsigned long long)rva);
      }
    }
  }

  printf("[+] Total: %d\n", dataEntryCount);
  return dataEntryCount;
}

int
extractStringsUsingCapstone(uint8_t* peData, SECTION_HEADER* sections, int numSections,
                            size_t fileSize) {
  printf("\n[*] Using Capstone for disassembly...\n");

  csh      handle;
  cs_insn* insn;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    printf("Error: Failed to initialize Capstone\n");
    return 0;
  }

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

  size_t count = cs_disasm(handle, textSection.data, textSection.rawSize,
                           textSection.virtualAddress, 0, &insn);

  if (count == 0) {
    printf("Error: Failed to disassemble\n");
    cs_close(&handle);
    return 0;
  }

  printf("[+] Disassembled %zu instructions\n", count);

  uint64_t rdataStart = imageBase + rdataSection.virtualAddress;
  uint64_t rdataEnd   = rdataStart + rdataSection.virtualSize;

  uint64_t markerFunctionRVA = 0;

  // Find marker function
  for (size_t i = 0; i < count - 100; i++) {
    // Look for function prologue
    if (!(insn[i].size == 4 && insn[i].bytes[0] == 0x48 && insn[i].bytes[1] == 0x83 &&
          insn[i].bytes[2] == 0xEC))
      continue;

    int markerCount    = 0;
    int nonMarkerCount = 0;

    for (size_t j = i; j < i + 200 && j < count; j++) {
      if (strcmp(insn[j].mnemonic, "lea") == 0 && insn[j].detail) {
        cs_x86* x86 = &insn[j].detail->x86;
        if (x86->op_count == 2 && x86->operands[1].type == X86_OP_MEM) {
          if (x86->operands[1].mem.base == X86_REG_RIP) {
            int64_t  disp     = x86->operands[1].mem.disp;
            uint64_t targetVA = imageBase + insn[j].address + insn[j].size + disp;

            if (targetVA >= rdataStart && targetVA < rdataEnd) {
              uint64_t targetRVA = targetVA - imageBase;
              int      isMarker  = 0;
              for (int k = 0; k < dataEntryCount; k++) {
                if (targetRVA == dataEntries[k].rdataRVA) {
                  isMarker = 1;
                  break;
                }
              }
              if (isMarker)
                markerCount++;
              else
                nonMarkerCount++;
            }
          }
        }
      }

      if (strcmp(insn[j].mnemonic, "ret") == 0)
        break;
    }

    if (markerCount >= 15 && nonMarkerCount == 0) {
      markerFunctionRVA = insn[i].address;
      printf("[+] Marker function at 0x%llX (%d markers)\n", (unsigned long long)markerFunctionRVA,
             markerCount);
      break;
    }
  }

  if (markerFunctionRVA == 0) {
    printf("[-] Marker function not found\n");
    cs_free(insn, count);
    cs_close(&handle);
    return 0;
  }

  // Find string function after marker function
  printf("[*] Searching for string function after 0x%llX...\n",
         (unsigned long long)markerFunctionRVA);

  for (size_t i = 0; i < count - 100; i++) {
    if (insn[i].address <= markerFunctionRVA + 100)
      continue;
    if (insn[i].address > markerFunctionRVA + 10000)
      break;

    // More flexible prologue detection
    int isPrologue = 0;
    if (insn[i].size >= 3 && insn[i].bytes[0] == 0x48 && insn[i].bytes[1] == 0x83 &&
        insn[i].bytes[2] == 0xEC) {
      isPrologue = 1;
    } else if (strcmp(insn[i].mnemonic, "push") == 0 && insn[i].detail) {
      cs_x86* x86 = &insn[i].detail->x86;
      if (x86->op_count == 1 && x86->operands[0].type == X86_OP_REG &&
          x86->operands[0].reg == X86_REG_RBP) {
        isPrologue = 1;
      }
    }

    if (!isPrologue)
      continue;

    char     strings[50][512] = {0};
    uint64_t stringRVAs[50]   = {0};
    int      stringCount      = 0;

    for (size_t j = i; j < i + 200 && j < count; j++) {
      if (strcmp(insn[j].mnemonic, "lea") == 0 && insn[j].detail) {
        cs_x86* x86 = &insn[j].detail->x86;
        if (x86->op_count == 2 && x86->operands[1].type == X86_OP_MEM) {
          if (x86->operands[1].mem.base == X86_REG_RIP) {
            int64_t  disp     = x86->operands[1].mem.disp;
            uint64_t targetVA = imageBase + insn[j].address + insn[j].size + disp;

            if (targetVA >= rdataStart && targetVA < rdataEnd) {
              uint64_t targetRVA = targetVA - imageBase;
              int      isMarker  = 0;
              for (int k = 0; k < dataEntryCount; k++) {
                if (targetRVA == dataEntries[k].rdataRVA) {
                  isMarker = 1;
                  break;
                }
              }

              if (!isMarker) {
                uint64_t strFileOff = rvaToFileOffset(targetRVA, sections, numSections);
                if (strFileOff > 0 && strFileOff < fileSize - 500) {
                  char* str = (char*)(peData + strFileOff);
                  int   len = 0;
                  while (len < 500 && str[len] != '\0')
                    len++;

                  if (len > 0 && len < 500 && stringCount < 50) {
                    strncpy(strings[stringCount], str, 511);
                    strings[stringCount][511] = '\0';
                    stringRVAs[stringCount]   = targetRVA;
                    stringCount++;
                  }
                }
              }
            }
          }
        }
      }

      if (strcmp(insn[j].mnemonic, "ret") == 0)
        break;
    }

    if (stringCount >= 15) {
      printf("[+] String function at 0x%llX (%d strings)\n", (unsigned long long)insn[i].address,
             stringCount);
      printf("\n[*] Mapping (reverse order):\n");

      int mapped   = 0;
      int minCount = (dataEntryCount < stringCount) ? dataEntryCount : stringCount;

      for (int k = 0; k < minCount; k++) {
        int stringIndex = stringCount - 1 - k;

        strncpy(dataEntries[k].encryptedString, strings[stringIndex], 511);
        dataEntries[k].encryptedString[511] = '\0';
        dataEntries[k].stringRVA            = stringRVAs[stringIndex];
        dataEntries[k].found                = 1;

        decryptString(dataEntries[k].encryptedString, dataEntries[k].decryptedString, 511);

        printf("    [%02d] %s <- \"%s\"\n", k, dataEntries[k].dataName,
               dataEntries[k].encryptedString);
        printf("                    -> \"%s\"\n", dataEntries[k].decryptedString);

        mapped++;
      }

      printf("\n[+] Mapped: %d\n", mapped);
      cs_free(insn, count);
      cs_close(&handle);
      return mapped;
    }
  }

  cs_free(insn, count);
  cs_close(&handle);

  printf("[-] String function not found\n");
  return 0;
}

void
printDictionary() {
  printf("\n");
  printf("================================================================================\n");
  printf("                          DICTIONARY\n");
  printf("================================================================================\n");
  printf("Marker       | Encrypted                                | Decrypted\n");
  printf("-------------|------------------------------------------|----------------------------\n");

  for (int i = 0; i < dataEntryCount; i++) {
    if (dataEntries[i].found && dataEntries[i].encryptedString[0] != '\0') {
      char enc[41] = {0};
      char dec[41] = {0};
      strncpy(enc, dataEntries[i].encryptedString, 40);
      strncpy(dec, dataEntries[i].decryptedString, 40);

      printf("%-12s | %-40s | %s\n", dataEntries[i].dataName, enc, dec);
    }
  }

  printf("================================================================================\n");
}

void
exportToJSON(const char* filename) {
  FILE* f = fopen(filename, "w");
  if (!f)
    return;

  fprintf(f, "{\n");
  fprintf(f, "  \"image_base\": \"0x%llX\",\n", (unsigned long long)imageBase);
  fprintf(f, "  \"decryption_key\": \"0x05\",\n");
  fprintf(f, "  \"data_entries\": [\n");

  int first = 1;
  for (int i = 0; i < dataEntryCount; i++) {
    if (dataEntries[i].found && dataEntries[i].encryptedString[0] != '\0') {
      if (!first)
        fprintf(f, ",\n");
      first = 0;

      fprintf(f, "    {\n");
      fprintf(f, "      \"marker\": \"%s\",\n", dataEntries[i].dataName);
      fprintf(f, "      \"encrypted\": \"%s\",\n", dataEntries[i].encryptedString);
      fprintf(f, "      \"decrypted\": \"%s\",\n", dataEntries[i].decryptedString);
      fprintf(f, "      \"rdata_rva\": \"0x%llX\",\n", (unsigned long long)dataEntries[i].rdataRVA);
      fprintf(f, "      \"string_rva\": \"0x%llX\"\n",
              (unsigned long long)dataEntries[i].stringRVA);
      fprintf(f, "    }");
    }
  }

  fprintf(f, "\n  ]\n}\n");
  fclose(f);

  printf("\n[+] Exported: %s\n", filename);
}

void
exportToCSV(const char* filename) {
  FILE* f = fopen(filename, "w");
  if (!f)
    return;

  fprintf(f, "Marker,Encrypted,Decrypted,RDATA_RVA,STRING_RVA\n");

  for (int i = 0; i < dataEntryCount; i++) {
    if (dataEntries[i].found && dataEntries[i].encryptedString[0] != '\0') {
      fprintf(f, "\"%s\",\"%s\",\"%s\",0x%llX,0x%llX\n", dataEntries[i].dataName,
              dataEntries[i].encryptedString, dataEntries[i].decryptedString,
              (unsigned long long)dataEntries[i].rdataRVA,
              (unsigned long long)dataEntries[i].stringRVA);
    }
  }

  fclose(f);
  printf("[+] Exported: %s\n", filename);
}

int
main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("pexw - Cross-Platform PE String Extractor\n");
    printf("Usage: %s <PE_file> [output.json] [output.csv]\n", argv[0]);
    return 1;
  }

  const char* inputFile  = argv[1];
  const char* jsonOutput = argc > 2 ? argv[2] : "dictionary.json";
  const char* csvOutput  = argc > 3 ? argv[3] : "strings.csv";

  printf("================================================================================\n");
  printf("                            pexw v2.0\n");
  printf("                    (Cross-Platform + Capstone)\n");
  printf("================================================================================\n\n");

  printf("[*] Target: %s\n", inputFile);

  MappedFile mf;
  if (!mapPEFile(inputFile, &mf)) {
    return 1;
  }

  printf("[+] Size: %zu bytes\n", mf.fileSize);
  printf("[+] Mapped at: %p\n", (void*)mf.pView);

  SECTION_HEADER* sections    = NULL;
  int             numSections = 0;

  if (!parsePEHeaders(mf.pView, mf.fileSize, &sections, &numSections)) {
    unmapPEFile(&mf);
    return 1;
  }

  if (!loadSections(mf.pView, mf.fileSize, sections, numSections)) {
    unmapPEFile(&mf);
    return 1;
  }

  if (!findDataMarkers()) {
    unmapPEFile(&mf);
    return 1;
  }

  extractStringsUsingCapstone(mf.pView, sections, numSections, mf.fileSize);

  printDictionary();
  exportToJSON(jsonOutput);
  exportToCSV(csvOutput);

  if (dataEntries)
    free(dataEntries);

  unmapPEFile(&mf);

  printf("\n[+] Complete\n");
  printf("================================================================================\n");

  return 0;
}
