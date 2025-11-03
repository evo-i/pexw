#include <windows.h>

#pragma pack(push, 1)

typedef struct {
  WORD  e_magic;
  WORD  e_cblp;
  WORD  e_cp;
  WORD  e_crlc;
  WORD  e_cparhdr;
  WORD  e_minalloc;
  WORD  e_maxalloc;
  WORD  e_ss;
  WORD  e_sp;
  WORD  e_csum;
  WORD  e_ip;
  WORD  e_cs;
  WORD  e_lfarlc;
  WORD  e_ovno;
  WORD  e_res[4];
  WORD  e_oemid;
  WORD  e_oeminfo;
  WORD  e_res2[10];
  DWORD e_lfanew;
} DOS_HEADER;

typedef struct {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} FILE_HEADER;

typedef struct {
  DWORD VirtualAddress;
  DWORD Size;
} DATA_DIRECTORY;

#define NUM_DATA_DIRECTORIES 16

typedef struct {
  WORD           Magic;
  BYTE           MajorLinkerVersion;
  BYTE           MinorLinkerVersion;
  DWORD          SizeOfCode;
  DWORD          SizeOfInitializedData;
  DWORD          SizeOfUninitializedData;
  DWORD          AddressOfEntryPoint;
  DWORD          BaseOfCode;
  UINT64         ImageBase;
  DWORD          SectionAlignment;
  DWORD          FileAlignment;
  WORD           MajorOperatingSystemVersion;
  WORD           MinorOperatingSystemVersion;
  WORD           MajorImageVersion;
  WORD           MinorImageVersion;
  WORD           MajorSubsystemVersion;
  WORD           MinorSubsystemVersion;
  DWORD          Win32VersionValue;
  DWORD          SizeOfImage;
  DWORD          SizeOfHeaders;
  DWORD          CheckSum;
  WORD           Subsystem;
  WORD           DllCharacteristics;
  UINT64         SizeOfStackReserve;
  UINT64         SizeOfStackCommit;
  UINT64         SizeOfHeapReserve;
  UINT64         SizeOfHeapCommit;
  DWORD          LoaderFlags;
  DWORD          NumberOfRvaAndSizes;
  DATA_DIRECTORY DataDirectory[NUM_DATA_DIRECTORIES];
} OPTIONAL_HEADER64;

typedef struct {
  DWORD             Signature;
  FILE_HEADER       FileHeader;
  OPTIONAL_HEADER64 OptionalHeader;
} NT_HEADERS64;

typedef struct {
  BYTE  Name[8];
  DWORD VirtualSize;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} SECTION_HEADER;

#pragma pack(pop)

#define DOS_SIGNATURE 0x5A4D
#define NT_SIGNATURE 0x00004550
#define OPT_HDR64_MAGIC 0x20B
#define MACHINE_AMD64 0x8664

typedef struct {
  char   name[9];
  UINT64 virtualAddress;
  UINT64 virtualSize;
  UINT64 rawAddress;
  DWORD  rawSize;
  BYTE*  data;
} Section;

typedef struct {
  char   dataName[32];
  char   encryptedString[512];
  char   decryptedString[512];
  UINT64 rdataRVA;
  UINT64 stringRVA;
  int    found;
} DataEntry;

typedef struct {
  HANDLE hFile;
  HANDLE hMapping;
  BYTE*  pView;
  DWORD  fileSize;
} MappedFile;

Section    textSection       = {0};
Section    rdataSection      = {0};
UINT64     imageBase         = 0;
DataEntry* dataEntries       = NULL;
int        dataEntryCount    = 0;
int        dataEntryCapacity = 0;
HANDLE     hConsole          = NULL;

void
myMemSet(void* dest, int val, SIZE_T count) {
  BYTE* p = (BYTE*)dest;
  for (SIZE_T i = 0; i < count; i++) {
    p[i] = (BYTE)val;
  }
}

void
myMemCpy(void* dest, const void* src, SIZE_T count) {
  BYTE*       d = (BYTE*)dest;
  const BYTE* s = (const BYTE*)src;
  for (SIZE_T i = 0; i < count; i++) {
    d[i] = s[i];
  }
}

int
myStrLen(const char* str) {
  int len = 0;
  while (str[len] != '\0')
    len++;
  return len;
}

void
myStrCpy(char* dest, const char* src, int maxLen) {
  int i = 0;
  while (i < maxLen - 1 && src[i] != '\0') {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

int
myStrCmp(const char* s1, const char* s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(unsigned char*)s1 - *(unsigned char*)s2;
}

void
myPrint(const char* str) {
  DWORD written;
  WriteConsoleA(hConsole, str, myStrLen(str), &written, NULL);
}

void
myPrintNum(UINT64 num, int isHex) {
  char buffer[32];
  int  i = 0;

  if (num == 0) {
    buffer[i++] = '0';
  } else {
    char temp[32];
    int  j = 0;

    while (num > 0) {
      int digit = num % (isHex ? 16 : 10);
      temp[j++] = (digit < 10) ? ('0' + digit) : ('A' + digit - 10);
      num /= (isHex ? 16 : 10);
    }

    while (j > 0) {
      buffer[i++] = temp[--j];
    }
  }

  buffer[i] = '\0';
  myPrint(buffer);
}

void
decryptString(const char* encrypted, char* decrypted, int maxLen) {
  int len = myStrLen(encrypted);
  if (len > maxLen)
    len = maxLen;

  for (int i = 0; i < len; i++) {
    decrypted[i] = encrypted[i] ^ 0x05;
  }
  decrypted[len] = '\0';
}

void
addDataEntry(const char* name, UINT64 rdataRVA) {
  if (dataEntryCount >= dataEntryCapacity) {
    dataEntryCapacity     = dataEntryCapacity == 0 ? 100 : dataEntryCapacity * 2;
    DataEntry* newEntries = (DataEntry*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataEntries,
                                                    dataEntryCapacity * sizeof(DataEntry));
    if (!newEntries) {
      if (!dataEntries) {
        dataEntries = (DataEntry*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                            dataEntryCapacity * sizeof(DataEntry));
      }
    } else {
      dataEntries = newEntries;
    }
  }

  myMemSet(&dataEntries[dataEntryCount], 0, sizeof(DataEntry));
  myStrCpy(dataEntries[dataEntryCount].dataName, name, 31);
  dataEntries[dataEntryCount].rdataRVA = rdataRVA;
  dataEntries[dataEntryCount].found    = 0;
  dataEntryCount++;
}

int
mapPEFile(const char* filename, MappedFile* mf) {
  mf->hFile    = INVALID_HANDLE_VALUE;
  mf->hMapping = NULL;
  mf->pView    = NULL;
  mf->fileSize = 0;

  mf->hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
  if (mf->hFile == INVALID_HANDLE_VALUE) {
    myPrint("Error: Cannot open file\r\n");
    return 0;
  }

  mf->fileSize = GetFileSize(mf->hFile, NULL);
  if (mf->fileSize == INVALID_FILE_SIZE || mf->fileSize == 0) {
    myPrint("Error: Invalid file size\r\n");
    CloseHandle(mf->hFile);
    return 0;
  }

  mf->hMapping = CreateFileMappingA(mf->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (mf->hMapping == NULL) {
    myPrint("Error: Cannot create file mapping\r\n");
    CloseHandle(mf->hFile);
    return 0;
  }

  mf->pView = (BYTE*)MapViewOfFile(mf->hMapping, FILE_MAP_READ, 0, 0, 0);
  if (mf->pView == NULL) {
    myPrint("Error: Cannot map view of file\r\n");
    CloseHandle(mf->hMapping);
    CloseHandle(mf->hFile);
    return 0;
  }

  return 1;
}

void
unmapPEFile(MappedFile* mf) {
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
}

UINT64
rvaToFileOffset(UINT64 rva, SECTION_HEADER* sections, int numSections) {
  for (int i = 0; i < numSections; i++) {
    if (rva >= sections[i].VirtualAddress &&
        rva < sections[i].VirtualAddress + sections[i].VirtualSize) {
      return sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
    }
  }
  return 0;
}

int
parsePEHeaders(BYTE* peData, DWORD fileSize, SECTION_HEADER** outSections, int* outNumSections) {
  if (fileSize < sizeof(DOS_HEADER)) {
    myPrint("Error: File too small\r\n");
    return 0;
  }

  DOS_HEADER* dosHeader = (DOS_HEADER*)peData;
  if (dosHeader->e_magic != DOS_SIGNATURE) {
    myPrint("Error: Invalid DOS signature\r\n");
    return 0;
  }

  myPrint("[+] DOS Header: 0x");
  myPrintNum(dosHeader->e_lfanew, 1);
  myPrint("\r\n");

  DWORD* peSignature = (DWORD*)(peData + dosHeader->e_lfanew);
  if (*peSignature != NT_SIGNATURE) {
    myPrint("Error: Invalid PE signature\r\n");
    return 0;
  }

  myPrint("[+] PE Signature found\r\n");

  FILE_HEADER* fileHeader = (FILE_HEADER*)(peData + dosHeader->e_lfanew + 4);

  myPrint("[+] Machine: 0x");
  myPrintNum(fileHeader->Machine, 1);
  myPrint("\r\n[+] Sections: ");
  myPrintNum(fileHeader->NumberOfSections, 0);
  myPrint("\r\n");

  if (fileHeader->Machine != MACHINE_AMD64) {
    myPrint("Error: Only x64 supported\r\n");
    return 0;
  }

  NT_HEADERS64* ntHeaders = (NT_HEADERS64*)(peData + dosHeader->e_lfanew);

  if (ntHeaders->OptionalHeader.Magic != OPT_HDR64_MAGIC) {
    myPrint("Error: Invalid Optional Header\r\n");
    return 0;
  }

  imageBase = ntHeaders->OptionalHeader.ImageBase;
  myPrint("[+] Image Base: 0x");
  myPrintNum(imageBase, 1);
  myPrint("\r\n");

  *outSections =
      (SECTION_HEADER*)((BYTE*)&ntHeaders->OptionalHeader + fileHeader->SizeOfOptionalHeader);
  *outNumSections = fileHeader->NumberOfSections;

  return 1;
}

int
loadSections(BYTE* peData, DWORD fileSize, SECTION_HEADER* sections, int numSections) {
  myPrint("\r\n[*] Loading sections:\r\n");

  for (int i = 0; i < numSections; i++) {
    char sectionName[9] = {0};
    myMemCpy(sectionName, sections[i].Name, 8);

    myPrint("[+] ");
    myPrint(sectionName);
    myPrint(" VA=0x");
    myPrintNum(sections[i].VirtualAddress, 1);
    myPrint(" Size=0x");
    myPrintNum(sections[i].VirtualSize, 1);
    myPrint("\r\n");

    if (myStrCmp(sectionName, ".text") == 0) {
      myStrCpy(textSection.name, sectionName, 8);
      textSection.virtualAddress = sections[i].VirtualAddress;
      textSection.virtualSize    = sections[i].VirtualSize;
      textSection.rawAddress     = sections[i].PointerToRawData;
      textSection.rawSize        = sections[i].SizeOfRawData;
      textSection.data           = peData + sections[i].PointerToRawData;
    }

    if (myStrCmp(sectionName, ".rdata") == 0) {
      myStrCpy(rdataSection.name, sectionName, 8);
      rdataSection.virtualAddress = sections[i].VirtualAddress;
      rdataSection.virtualSize    = sections[i].VirtualSize;
      rdataSection.rawAddress     = sections[i].PointerToRawData;
      rdataSection.rawSize        = sections[i].SizeOfRawData;
      rdataSection.data           = peData + sections[i].PointerToRawData;
    }
  }

  if (!textSection.data || !rdataSection.data) {
    myPrint("Error: Required sections not found\r\n");
    return 0;
  }

  return 1;
}

int
findDataMarkers() {
  myPrint("\r\n[*] Scanning for dataXX markers...\r\n");

  for (DWORD i = 0; i < rdataSection.rawSize - 7; i++) {
    BYTE* ptr = rdataSection.data + i;

    if (ptr[0] == 'd' && ptr[1] == 'a' && ptr[2] == 't' && ptr[3] == 'a') {
      if ((ptr[4] >= '0' && ptr[4] <= '9') && (ptr[5] >= '0' && ptr[5] <= '9')) {

        char name[32] = {0};
        int  j        = 0;
        while (j < 31 && ptr[j] != '\0' && (j < 4 || (ptr[j] >= '0' && ptr[j] <= '9'))) {
          name[j] = ptr[j];
          j++;
        }
        name[j] = '\0';

        UINT64 rva = rdataSection.virtualAddress + i;
        addDataEntry(name, rva);

        myPrint("[+] ");
        myPrint(name);
        myPrint(" at 0x");
        myPrintNum(rva, 1);
        myPrint("\r\n");
      }
    }
  }

  myPrint("[+] Total: ");
  myPrintNum(dataEntryCount, 0);
  myPrint("\r\n");
  return dataEntryCount;
}

int
extractStringsFromPairedFunctions(BYTE* peData, SECTION_HEADER* sections, int numSections) {
  myPrint("\r\n[*] Searching for initializer functions...\r\n");

  UINT64 rdataStart = imageBase + rdataSection.virtualAddress;
  UINT64 rdataEnd   = rdataStart + rdataSection.virtualSize;

  UINT64 markerFunctionRVA = 0;

  for (DWORD i = 0; i < textSection.rawSize - 2000; i++) {
    BYTE* code = textSection.data + i;

    if (!(code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xEC && code[3] == 0x38)) {
      continue;
    }

    int markerCount    = 0;
    int nonMarkerCount = 0;

    for (DWORD j = i; j < i + 2000 && j < textSection.rawSize - 7; j++) {
      BYTE* instr = textSection.data + j;

      if (instr[0] == 0x48 && instr[1] == 0x8D && instr[2] == 0x15) {
        INT32  disp     = *(INT32*)(instr + 3);
        UINT64 instrRVA = textSection.virtualAddress + j;
        UINT64 targetVA = imageBase + instrRVA + 7 + disp;

        if (targetVA >= rdataStart && targetVA < rdataEnd) {
          UINT64 targetRVA = targetVA - imageBase;

          int isMarker = 0;
          for (int k = 0; k < dataEntryCount; k++) {
            if (targetRVA == dataEntries[k].rdataRVA) {
              isMarker = 1;
              break;
            }
          }

          if (isMarker) {
            markerCount++;
          } else {
            nonMarkerCount++;
          }
        }
      }

      if (instr[0] == 0xC3)
        break;
    }

    if (markerCount >= 15 && nonMarkerCount == 0) {
      markerFunctionRVA = textSection.virtualAddress + i;
      myPrint("[+] Marker function at 0x");
      myPrintNum(markerFunctionRVA, 1);
      myPrint(" (");
      myPrintNum(markerCount, 0);
      myPrint(" markers)\r\n");
      break;
    }
  }

  if (markerFunctionRVA == 0) {
    myPrint("[-] Marker function not found\r\n");
    return 0;
  }

  UINT64 searchStart = markerFunctionRVA - textSection.virtualAddress;

  for (DWORD i = searchStart + 100; i < searchStart + 5000 && i < textSection.rawSize - 2000; i++) {
    BYTE* code = textSection.data + i;

    if (!(code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xEC && code[3] == 0x38)) {
      continue;
    }

    UINT64 stringFunctionRVA = textSection.virtualAddress + i;

    char   strings[50][512] = {0};
    UINT64 stringRVAs[50]   = {0};
    int    stringCount      = 0;

    for (DWORD j = i; j < i + 2000 && j < textSection.rawSize - 7; j++) {
      BYTE* instr = textSection.data + j;

      if (instr[0] == 0x48 && instr[1] == 0x8D && instr[2] == 0x15) {
        INT32  disp     = *(INT32*)(instr + 3);
        UINT64 instrRVA = textSection.virtualAddress + j;
        UINT64 targetVA = imageBase + instrRVA + 7 + disp;

        if (targetVA >= rdataStart && targetVA < rdataEnd) {
          UINT64 targetRVA = targetVA - imageBase;

          int isMarker = 0;
          for (int k = 0; k < dataEntryCount; k++) {
            if (targetRVA == dataEntries[k].rdataRVA) {
              isMarker = 1;
              break;
            }
          }

          if (!isMarker) {
            UINT64 strFileOff = rvaToFileOffset(targetRVA, sections, numSections);
            if (strFileOff > 0) {
              char* str = (char*)(peData + strFileOff);
              int   len = 0;
              while (len < 500 && str[len] != '\0')
                len++;

              if (len > 0 && len < 500 && stringCount < 50) {
                myStrCpy(strings[stringCount], str, 511);
                stringRVAs[stringCount] = targetRVA;
                stringCount++;
              }
            }
          }
        }
      }

      if (instr[0] == 0xC3)
        break;
    }

    if (stringCount >= 15) {
      myPrint("[+] String function at 0x");
      myPrintNum(stringFunctionRVA, 1);
      myPrint(" (");
      myPrintNum(stringCount, 0);
      myPrint(" strings)\r\n");

      myPrint("\r\n[*] Mapping (reverse order):\r\n");

      int mapped   = 0;
      int minCount = (dataEntryCount < stringCount) ? dataEntryCount : stringCount;

      for (int k = 0; k < minCount; k++) {
        int stringIndex = stringCount - 1 - k;

        myStrCpy(dataEntries[k].encryptedString, strings[stringIndex], 511);
        dataEntries[k].stringRVA = stringRVAs[stringIndex];
        dataEntries[k].found     = 1;

        decryptString(dataEntries[k].encryptedString, dataEntries[k].decryptedString, 511);

        myPrint("    [");
        if (k < 10)
          myPrint("0");
        myPrintNum(k, 0);
        myPrint("] ");
        myPrint(dataEntries[k].dataName);
        myPrint(" <- \"");
        myPrint(dataEntries[k].encryptedString);
        myPrint("\"\r\n");
        myPrint("                    -> \"");
        myPrint(dataEntries[k].decryptedString);
        myPrint("\"\r\n");

        mapped++;
      }

      myPrint("\r\n[+] Mapped: ");
      myPrintNum(mapped, 0);
      myPrint("\r\n");
      return mapped;
    }
  }

  myPrint("[-] String function not found\r\n");
  return 0;
}

void
printDictionary() {
  myPrint("\r\n");
  myPrint("================================================================================\r\n");
  myPrint("                          DICTIONARY\r\n");
  myPrint("================================================================================\r\n");
  myPrint("Marker       | Encrypted                                | Decrypted\r\n");
  myPrint("-------------|------------------------------------------|-------------------------------"
          "-----------\r\n");

  for (int i = 0; i < dataEntryCount; i++) {
    if (dataEntries[i].found && dataEntries[i].encryptedString[0] != '\0') {
      char enc[41] = {0};
      char dec[41] = {0};
      myStrCpy(enc, dataEntries[i].encryptedString, 40);
      myStrCpy(dec, dataEntries[i].decryptedString, 40);

      myPrint(dataEntries[i].dataName);
      int padding = 12 - myStrLen(dataEntries[i].dataName);
      for (int p = 0; p < padding; p++)
        myPrint(" ");
      myPrint(" | ");
      myPrint(enc);
      padding = 40 - myStrLen(enc);
      for (int p = 0; p < padding; p++)
        myPrint(" ");
      myPrint(" | ");
      myPrint(dec);
      myPrint("\r\n");
    }
  }

  myPrint("================================================================================\r\n");
}

void
exportToJSON(const char* filename) {
  HANDLE hFile =
      CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return;

  DWORD written;

  WriteFile(hFile, "{\r\n", 3, &written, NULL);
  WriteFile(hFile, "  \"image_base\": \"0x", 19, &written, NULL);

  char numBuf[32];
  wsprintfA(numBuf, "%llX", imageBase);
  WriteFile(hFile, numBuf, lstrlenA(numBuf), &written, NULL);

  WriteFile(hFile, "\",\r\n", 4, &written, NULL);
  WriteFile(hFile, "  \"decryption_key\": \"0x05\",\r\n", 31, &written, NULL);
  WriteFile(hFile, "  \"data_entries\": [\r\n", 23, &written, NULL);

  int first = 1;
  for (int i = 0; i < dataEntryCount; i++) {
    if (dataEntries[i].found && dataEntries[i].encryptedString[0] != '\0') {
      if (!first)
        WriteFile(hFile, ",\r\n", 3, &written, NULL);
      first = 0;

      WriteFile(hFile, "    {\r\n", 7, &written, NULL);
      WriteFile(hFile, "      \"marker\": \"", 18, &written, NULL);
      WriteFile(hFile, dataEntries[i].dataName, myStrLen(dataEntries[i].dataName), &written, NULL);
      WriteFile(hFile, "\",\r\n", 4, &written, NULL);

      WriteFile(hFile, "      \"encrypted\": \"", 21, &written, NULL);
      WriteFile(hFile, dataEntries[i].encryptedString, myStrLen(dataEntries[i].encryptedString),
                &written, NULL);
      WriteFile(hFile, "\",\r\n", 4, &written, NULL);

      WriteFile(hFile, "      \"decrypted\": \"", 21, &written, NULL);
      WriteFile(hFile, dataEntries[i].decryptedString, myStrLen(dataEntries[i].decryptedString),
                &written, NULL);
      WriteFile(hFile, "\",\r\n", 4, &written, NULL);

      WriteFile(hFile, "      \"rdata_rva\": \"0x", 23, &written, NULL);
      wsprintfA(numBuf, "%llX", dataEntries[i].rdataRVA);
      WriteFile(hFile, numBuf, lstrlenA(numBuf), &written, NULL);
      WriteFile(hFile, "\",\r\n", 4, &written, NULL);

      WriteFile(hFile, "      \"string_rva\": \"0x", 24, &written, NULL);
      wsprintfA(numBuf, "%llX", dataEntries[i].stringRVA);
      WriteFile(hFile, numBuf, lstrlenA(numBuf), &written, NULL);
      WriteFile(hFile, "\"\r\n", 3, &written, NULL);

      WriteFile(hFile, "    }", 5, &written, NULL);
    }
  }

  WriteFile(hFile, "\r\n  ]\r\n}\r\n", 10, &written, NULL);
  CloseHandle(hFile);

  myPrint("\r\n[+] Exported: ");
  myPrint(filename);
  myPrint("\r\n");
}

void
exportToCSV(const char* filename) {
  HANDLE hFile =
      CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return;

  DWORD written;
  WriteFile(hFile, "Marker,Encrypted,Decrypted,RDATA_RVA,STRING_RVA\r\n", 49, &written, NULL);

  for (int i = 0; i < dataEntryCount; i++) {
    if (dataEntries[i].found && dataEntries[i].encryptedString[0] != '\0') {
      char line[2048];
      wsprintfA(line, "\"%s\",\"%s\",\"%s\",0x%llX,0x%llX\r\n", dataEntries[i].dataName,
                dataEntries[i].encryptedString, dataEntries[i].decryptedString,
                dataEntries[i].rdataRVA, dataEntries[i].stringRVA);
      WriteFile(hFile, line, lstrlenA(line), &written, NULL);
    }
  }

  CloseHandle(hFile);

  myPrint("[+] Exported: ");
  myPrint(filename);
  myPrint("\r\n");
}

int
main(int argc, char* argv[]) {
  hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

  if (argc < 2) {
    myPrint("pexw - PE String Extractor\r\n");
    myPrint("Usage: pexw.exe <PE_file> [output.json] [output.csv]\r\n");
    return 1;
  }

  const char* inputFile  = argv[1];
  const char* jsonOutput = argc > 2 ? argv[2] : "dictionary.json";
  const char* csvOutput  = argc > 3 ? argv[3] : "strings.csv";

  myPrint("================================================================================\r\n");
  myPrint("                            pexw v1.0\r\n");
  myPrint(
      "================================================================================\r\n\r\n");

  myPrint("[*] Target: ");
  myPrint(inputFile);
  myPrint("\r\n");

  MappedFile mf;
  if (!mapPEFile(inputFile, &mf)) {
    return 1;
  }

  myPrint("[+] Size: ");
  myPrintNum(mf.fileSize, 0);
  myPrint(" bytes\r\n");
  myPrint("[+] Mapped at: 0x");
  myPrintNum((UINT64)mf.pView, 1);
  myPrint("\r\n");

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

  extractStringsFromPairedFunctions(mf.pView, sections, numSections);

  printDictionary();
  exportToJSON(jsonOutput);
  exportToCSV(csvOutput);

  if (dataEntries)
    HeapFree(GetProcessHeap(), 0, dataEntries);

  unmapPEFile(&mf);

  myPrint("\r\n[+] Complete\r\n");
  myPrint("================================================================================\r\n");

  return 0;
}
