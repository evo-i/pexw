#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <threads.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  #define ATOMIC_VAR_INIT(x) {x}
  typedef struct { volatile uint64_t val; } atomic_uint_fast64_t;
  static inline uint64_t atomic_load(atomic_uint_fast64_t *obj) {
    return InterlockedOr64((volatile LONG64*)&obj->val, 0);
  }
  static inline bool atomic_compare_exchange_strong(atomic_uint_fast64_t *obj, uint64_t *expected, uint64_t desired) {
    uint64_t old = InterlockedCompareExchange64((volatile LONG64*)&obj->val, desired, *expected);
    if (old == *expected) return true;
    *expected = old;
    return false;
  }
  typedef struct {
    LARGE_INTEGER start;
    LARGE_INTEGER freq;
  } high_res_timer_t;
  static inline void timer_start(high_res_timer_t *t) {
    QueryPerformanceFrequency(&t->freq);
    QueryPerformanceCounter(&t->start);
  }
  static inline double timer_get_elapsed(high_res_timer_t *t) {
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - t->start.QuadPart) / (double)t->freq.QuadPart;
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #include <sys/types.h>
  #include <sys/sysctl.h>
  #include <stdatomic.h>
  #include <time.h>
  typedef struct {
    struct timespec start;
  } high_res_timer_t;
  static inline void timer_start(high_res_timer_t *t) {
    clock_gettime(CLOCK_MONOTONIC, &t->start);
  }
  static inline double timer_get_elapsed(high_res_timer_t *t) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - t->start.tv_sec) + (end.tv_nsec - t->start.tv_nsec) / 1e9;
  }
#else
  #include <unistd.h>
  #include <stdatomic.h>
  #include <time.h>
  typedef struct {
    struct timespec start;
  } high_res_timer_t;
  static inline void timer_start(high_res_timer_t *t) {
    clock_gettime(CLOCK_MONOTONIC, &t->start);
  }
  static inline double timer_get_elapsed(high_res_timer_t *t) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - t->start.tv_sec) + (end.tv_nsec - t->start.tv_nsec) / 1e9;
  }
#endif

#define DOS_SIGNATURE       0x5A4D
#define PE_SIGNATURE        0x00004550
#define OPT_MAGIC64         0x20B
#define MACHINE_AMD64       0x8664
#define XOR_KEY             0x05

#define MAX_MARKER_NAME_LEN 32
#define MAX_STRING_LEN      512
#define MAX_STRINGS_ARRAY   128
#define INITIAL_ARRAY_CAP   128
#define SCAN_DEPTH          2000
#define LEA_INSTR_SIZE      7
#define FUNC_MIN_SIZE       16
#define MIN_MARKERS_COUNT   15
#define MARGIN_BYTES        8
#define DATA_DIR_COUNT      16
#define SECTION_NAME_LEN    8
#define DEFAULT_CPU_COUNT   4

#define OPCODE_SUB_RSP_38_0 0x48
#define OPCODE_SUB_RSP_38_1 0x83
#define OPCODE_SUB_RSP_38_2 0xEC
#define OPCODE_SUB_RSP_38_3 0x38
#define OPCODE_LEA_RDX_0    0x48
#define OPCODE_LEA_RDX_1    0x8D
#define OPCODE_LEA_RDX_2    0x15
#define OPCODE_RET          0xC3

#define MARKER_SIGNATURE    0x61746164
#define MARKER_PREFIX_LEN   4
#define MARGIN_CHECK_BYTES  6
#define DISP_OFFSET         3
#define LEA_FULL_SIZE       7
#define DIGIT_MIN           0x30
#define DIGIT_MAX           0x39

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
} dos_header_t;

typedef struct {
  uint16_t machine;
  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_header;
  uint16_t characteristics;
} file_header_t;

typedef struct {
  uint32_t virtual_address;
  uint32_t size;
} data_directory_entry_t;

typedef struct {
  uint16_t magic;
  uint8_t major_linker_version;
  uint8_t minor_linker_version;
  uint32_t size_of_code;
  uint32_t size_of_initialized_data;
  uint32_t size_of_uninitialized_data;
  uint32_t address_of_entry_point;
  uint32_t base_of_code;
  uint64_t image_base;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint16_t major_operating_system_version;
  uint16_t minor_operating_system_version;
  uint16_t major_image_version;
  uint16_t minor_image_version;
  uint16_t major_subsystem_version;
  uint16_t minor_subsystem_version;
  uint32_t win32_version_value;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t check_sum;
  uint16_t subsystem;
  uint16_t dll_characteristics;
  uint64_t size_of_stack_reserve;
  uint64_t size_of_stack_commit;
  uint64_t size_of_heap_reserve;
  uint64_t size_of_heap_commit;
  uint32_t loader_flags;
  uint32_t number_of_rva_and_sizes;
  data_directory_entry_t data_directory[DATA_DIR_COUNT];
} optional_header64_t;

typedef struct {
  uint32_t signature;
  file_header_t file_header;
  optional_header64_t optional_header;
} nt_headers64_t;

typedef struct {
  uint8_t name[SECTION_NAME_LEN];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t size_of_raw_data;
  uint32_t pointer_to_raw_data;
  uint32_t pointer_to_relocations;
  uint32_t pointer_to_linenumbers;
  uint16_t number_of_relocations;
  uint16_t number_of_linenumbers;
  uint32_t characteristics;
} section_header_t;

#pragma pack(pop)

typedef struct {
  char data_name[MAX_MARKER_NAME_LEN];
  char decrypted_string[MAX_STRING_LEN];
  uint64_t rdata_rva;
  uint64_t string_rva;
  bool found;
} data_entry_t;

static uint8_t *pe_data = NULL;
static size_t pe_size = 0;
static section_header_t *sections = NULL;
static int32_t num_sections = 0;
static uint64_t image_base = 0;
static section_header_t *text_sec = NULL;
static section_header_t *rdata_sec = NULL;

static data_entry_t *data_entries = NULL;
static size_t data_entry_count = 0;
static size_t data_entry_cap = 0;
static mtx_t entries_mtx;

static atomic_uint_fast64_t marker_function_rva_atomic = ATOMIC_VAR_INIT(0);

static int32_t get_cpu_count(void) {
#if defined(_WIN32) || defined(_WIN64)
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  return (int32_t)sysinfo.dwNumberOfProcessors;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  int32_t count;
  size_t count_len = sizeof(count);
  if (sysctlbyname("hw.ncpu", &count, &count_len, NULL, 0) == 0) {
    return count;
  }
  return DEFAULT_CPU_COUNT;
#elif defined(_SC_NPROCESSORS_ONLN)
  long procs = sysconf(_SC_NPROCESSORS_ONLN);
  return (procs > 0) ? (int32_t)procs : DEFAULT_CPU_COUNT;
#else
  return DEFAULT_CPU_COUNT;
#endif
}

static void xor05_decrypt_inplace(char *s) {
  for (size_t i = 0; s[i]; ++i) {
    s[i] = (char)(s[i] ^ XOR_KEY);
  }
}

static void add_data_entry_ts(const char *name, uint64_t rdata_rva) {
  mtx_lock(&entries_mtx);
  {
    if (data_entry_count >= data_entry_cap) {
      size_t newcap = data_entry_cap == 0 ? INITIAL_ARRAY_CAP : data_entry_cap * 2;
      data_entry_t *p = realloc(data_entries, newcap * sizeof(data_entry_t));
      if (!p) {
        perror("realloc");
        exit(1);
      }
      data_entries = p;
      data_entry_cap = newcap;
    }
    data_entry_t *e = &data_entries[data_entry_count++];
    memset(e, 0, sizeof(data_entry_t));
    size_t name_len = strlen(name);
    if (name_len >= MAX_MARKER_NAME_LEN) {
      name_len = MAX_MARKER_NAME_LEN - 1;
    }
    memcpy(e->data_name, name, name_len);
    e->data_name[name_len] = '\0';
    e->rdata_rva = rdata_rva;
    e->found = false;
  }
  mtx_unlock(&entries_mtx);
}

typedef struct {
  uint32_t start_off, end_off;
} rdata_arg_t;

typedef struct {
  uint32_t start_off, end_off;
} text_arg_t;

typedef struct {
  uint32_t start_off, end_off;
  size_t mapped;
} string_arg_t;

static int rdata_worker(void *arg) {
  rdata_arg_t a = *(rdata_arg_t*)arg;
  uint32_t *base = (uint32_t*)(pe_data + rdata_sec->pointer_to_raw_data);
  uint32_t raw_size = rdata_sec->size_of_raw_data;
  
  uint32_t start_word = a.start_off / 4;
  uint32_t end_word = (a.end_off + MARGIN_BYTES) / 4;
  uint32_t size_words = raw_size / 4;
  
  if (end_word > size_words) {
    end_word = size_words;
  }

  for (uint32_t i = start_word; i < end_word; ++i) {
    if (base[i] == MARKER_SIGNATURE) {
      uint8_t *ptr = (uint8_t*)&base[i];
      if (ptr[4] >= DIGIT_MIN && ptr[4] <= DIGIT_MAX &&
          ptr[5] >= DIGIT_MIN && ptr[5] <= DIGIT_MAX) {
        char name[MAX_MARKER_NAME_LEN];
        int32_t j = 0;
        uint32_t byte_off = i * 4;
        while (j < MAX_MARKER_NAME_LEN - 1 && byte_off + j < raw_size && 
               pe_data[rdata_sec->pointer_to_raw_data + byte_off + j] != 0 &&
               (j < MARKER_PREFIX_LEN || 
                (pe_data[rdata_sec->pointer_to_raw_data + byte_off + j] >= DIGIT_MIN && 
                 pe_data[rdata_sec->pointer_to_raw_data + byte_off + j] <= DIGIT_MAX))) {
          name[j] = (char)pe_data[rdata_sec->pointer_to_raw_data + byte_off + j];
          j++;
        }
        name[j] = 0;
        uint64_t rva = (uint64_t)rdata_sec->virtual_address + byte_off;
        add_data_entry_ts(name, rva);
      }
    }
  }
  return 0;
}

static int marker_worker(void *arg) {
  text_arg_t a = *(text_arg_t*)arg;
  uint8_t *base = pe_data + text_sec->pointer_to_raw_data;
  uint32_t raw_size = text_sec->size_of_raw_data;
  uint64_t rdata_start = image_base + rdata_sec->virtual_address;
  uint64_t rdata_end = rdata_start + rdata_sec->virtual_size;

  if (a.start_off >= raw_size) {
    return 0;
  }
  if (a.end_off > raw_size) {
    a.end_off = raw_size;
  }

  for (uint32_t i = a.start_off; i + FUNC_MIN_SIZE < a.end_off; ++i) {
    if (atomic_load(&marker_function_rva_atomic) != 0) {
      break;
    }
    uint8_t *code = base + i;
    if (!(code[0] == OPCODE_SUB_RSP_38_0 && code[1] == OPCODE_SUB_RSP_38_1 &&
          code[2] == OPCODE_SUB_RSP_38_2 && code[3] == OPCODE_SUB_RSP_38_3)) {
      continue;
    }
    size_t marker_count = 0, non_marker_count = 0;
    for (uint32_t j = i; j < i + SCAN_DEPTH && j + LEA_INSTR_SIZE < raw_size; ++j) {
      uint8_t *instr = base + j;
      if (instr[0] == OPCODE_LEA_RDX_0 && instr[1] == OPCODE_LEA_RDX_1 && 
          instr[2] == OPCODE_LEA_RDX_2) {
        int32_t disp = *(int32_t*)(instr + DISP_OFFSET);
        uint64_t instr_rva = (uint64_t)text_sec->virtual_address + j;
        uint64_t target_va = image_base + instr_rva + LEA_FULL_SIZE + (uint64_t)disp;
        if (target_va >= rdata_start && target_va < rdata_end) {
          uint64_t target_rva = target_va - image_base;
          bool is_marker = false;
          mtx_lock(&entries_mtx);
          {
            for (size_t k = 0; k < data_entry_count; k++) {
              if (data_entries[k].rdata_rva == target_rva) {
                is_marker = true;
                break;
              }
            }
          }
          mtx_unlock(&entries_mtx);
          if (is_marker) {
            marker_count++;
          } else {
            non_marker_count++;
          }
        }
      }
      if (instr[0] == OPCODE_RET) {
        break;
      }
    }
    if (marker_count >= MIN_MARKERS_COUNT && non_marker_count == 0) {
      uint64_t candidate = (uint64_t)text_sec->virtual_address + i;
      uint64_t expected = 0;
      atomic_compare_exchange_strong(&marker_function_rva_atomic, &expected, candidate);
      break;
    }
  }
  return 0;
}

static int string_worker(void *arg) {
  string_arg_t *a = (string_arg_t*)arg;
  uint8_t *base = pe_data + text_sec->pointer_to_raw_data;
  uint32_t raw_size = text_sec->size_of_raw_data;
  uint64_t rdata_start = image_base + rdata_sec->virtual_address;
  uint64_t rdata_end = rdata_start + rdata_sec->virtual_size;

  if (a->start_off >= raw_size) {
    return 0;
  }
  if (a->end_off > raw_size) {
    a->end_off = raw_size;
  }

  for (uint32_t i = a->start_off; i + FUNC_MIN_SIZE < a->end_off; ++i) {
    uint8_t *code = base + i;
    if (!(code[0] == OPCODE_SUB_RSP_38_0 && code[1] == OPCODE_SUB_RSP_38_1 &&
          code[2] == OPCODE_SUB_RSP_38_2 && code[3] == OPCODE_SUB_RSP_38_3)) {
      continue;
    }

    char strings[MAX_STRINGS_ARRAY][MAX_STRING_LEN];
    uint64_t string_rvas[MAX_STRINGS_ARRAY];
    size_t scount = 0;

    for (uint32_t j = i; j < i + SCAN_DEPTH && j + LEA_INSTR_SIZE < raw_size; ++j) {
      uint8_t *instr = base + j;
      if (instr[0] == OPCODE_LEA_RDX_0 && instr[1] == OPCODE_LEA_RDX_1 && 
          instr[2] == OPCODE_LEA_RDX_2) {
        int32_t disp = *(int32_t*)(instr + DISP_OFFSET);
        uint64_t instr_rva = (uint64_t)text_sec->virtual_address + j;
        uint64_t target_va = image_base + instr_rva + LEA_FULL_SIZE + (uint64_t)disp;
        if (target_va >= rdata_start && target_va < rdata_end) {
          uint64_t target_rva = target_va - image_base;
          bool is_marker = false;
          mtx_lock(&entries_mtx);
          {
            for (size_t k = 0; k < data_entry_count; k++) {
              if (data_entries[k].rdata_rva == target_rva) {
                is_marker = true;
                break;
              }
            }
          }
          mtx_unlock(&entries_mtx);
          if (!is_marker) {
            uint64_t off = (uint64_t)rdata_sec->pointer_to_raw_data +
                           (target_rva - rdata_sec->virtual_address);
            if (off < pe_size) {
              size_t len = 0;
              while (len < MAX_STRING_LEN - 1 && off + len < pe_size && 
                     pe_data[off + len]) {
                ++len;
              }
              if (len > 0) {
                if (scount < MAX_STRINGS_ARRAY) {
                  memset(strings[scount], 0, MAX_STRING_LEN);
                  memcpy(strings[scount], pe_data + off, len);
                  string_rvas[scount] = target_rva;
                  scount++;
                } else {
                  break;
                }
              }
            }
          }
        }
      }
      if (instr[0] == OPCODE_RET) {
        break;
      }
    }

    if (scount >= MIN_MARKERS_COUNT) {
      mtx_lock(&entries_mtx);
      {
        size_t minc = data_entry_count < scount ? data_entry_count : scount;
        for (size_t k = 0; k < minc; ++k) {
          size_t si = scount - 1 - k;
          if (!data_entries[k].found) {
            size_t str_len = strlen(strings[si]);
            if (str_len >= MAX_STRING_LEN) {
              str_len = MAX_STRING_LEN - 1;
            }
            memcpy(data_entries[k].decrypted_string, strings[si], str_len);
            data_entries[k].decrypted_string[str_len] = '\0';
            data_entries[k].string_rva = string_rvas[si];
            xor05_decrypt_inplace(data_entries[k].decrypted_string);
            data_entries[k].found = true;
            a->mapped++;
          }
        }
      }
      mtx_unlock(&entries_mtx);
      break;
    }
  }
  return 0;
}

static int cmp_entries_by_rva(const void *pa, const void *pb) {
  const data_entry_t *a = pa;
  const data_entry_t *b = pb;
  if (a->rdata_rva < b->rdata_rva) {
    return -1;
  }
  if (a->rdata_rva > b->rdata_rva) {
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <PEfile> [threads]\n", argv[0]);
    return 1;
  }
  int32_t nthreads = 0;
  if (argc >= 3) {
    nthreads = atoi(argv[2]);
  }
  if (nthreads <= 0) {
    nthreads = get_cpu_count();
  }

  const char *fname = argv[1];
  struct stat st;
  if (stat(fname, &st) != 0) {
    perror("stat");
    return 1;
  }
  pe_size = (size_t)st.st_size;
  pe_data = malloc(pe_size);
  if (!pe_data) {
    perror("malloc");
    return 1;
  }
  FILE *f = fopen(fname, "rb");
  if (!f) {
    perror("fopen");
    free(pe_data);
    return 1;
  }
  if (fread(pe_data, 1, pe_size, f) != pe_size) {
    perror("fread");
    fclose(f);
    free(pe_data);
    return 1;
  }
  fclose(f);

  if (pe_size < sizeof(dos_header_t)) {
    fprintf(stderr, "file too small\n");
    free(pe_data);
    return 1;
  }
  dos_header_t *dh = (dos_header_t*)pe_data;
  if (dh->e_magic != DOS_SIGNATURE) {
    fprintf(stderr, "invalid DOS\n");
    free(pe_data);
    return 1;
  }
  uint32_t peoff = dh->e_lfanew;
  if (peoff + sizeof(uint32_t) + sizeof(file_header_t) > pe_size) {
    fprintf(stderr, "truncated\n");
    free(pe_data);
    return 1;
  }
  uint32_t sig = *(uint32_t*)(pe_data + peoff);
  if (sig != PE_SIGNATURE) {
    fprintf(stderr, "invalid PE\n");
    free(pe_data);
    return 1;
  }
  file_header_t *fh = (file_header_t*)(pe_data + peoff + sizeof(uint32_t));
  nt_headers64_t *nth = (nt_headers64_t*)(pe_data + peoff);
  if (fh->machine != MACHINE_AMD64) {
    fprintf(stderr, "only x64 supported\n");
    free(pe_data);
    return 1;
  }
  if (nth->optional_header.magic != OPT_MAGIC64) {
    fprintf(stderr, "invalid optional header\n");
    free(pe_data);
    return 1;
  }
  image_base = nth->optional_header.image_base;
  sections = (section_header_t*)((uint8_t*)&nth->optional_header +
                                 fh->size_of_optional_header);
  num_sections = fh->number_of_sections;
  for (int32_t i = 0; i < num_sections; i++) {
    char name[SECTION_NAME_LEN + 1];
    memcpy(name, sections[i].name, SECTION_NAME_LEN);
    name[SECTION_NAME_LEN] = 0;
    if (strcmp(name, ".text") == 0) {
      text_sec = &sections[i];
    }
    if (strcmp(name, ".rdata") == 0) {
      rdata_sec = &sections[i];
    }
  }
  if (!text_sec || !rdata_sec) {
    fprintf(stderr, ".text or .rdata not found\n");
    free(pe_data);
    return 1;
  }

  high_res_timer_t timer;
  timer_start(&timer);

  mtx_init(&entries_mtx, mtx_plain);

  thrd_t *tids = calloc((size_t)nthreads, sizeof(thrd_t));
  rdata_arg_t *rargs = calloc((size_t)nthreads, sizeof(rdata_arg_t));
  uint32_t raw_size = rdata_sec->size_of_raw_data;
  uint32_t chunk = (raw_size + (uint32_t)nthreads - 1) / (uint32_t)nthreads;
  for (int32_t i = 0; i < nthreads; i++) {
    rargs[i].start_off = (uint32_t)i * chunk;
    rargs[i].end_off = (uint32_t)(i + 1) * chunk;
    thrd_create(&tids[i], rdata_worker, &rargs[i]);
  }
  for (int32_t i = 0; i < nthreads; i++) {
    thrd_join(tids[i], NULL);
  }
  free(rargs);

  mtx_lock(&entries_mtx);
  {
    if (data_entry_count > 1) {
      qsort(data_entries, data_entry_count, sizeof(data_entry_t), cmp_entries_by_rva);
    }
  }
  mtx_unlock(&entries_mtx);

  text_arg_t *targs = calloc((size_t)nthreads, sizeof(text_arg_t));
  uint32_t text_raw = text_sec->size_of_raw_data;
  uint32_t tchunk = (text_raw + (uint32_t)nthreads - 1) / (uint32_t)nthreads;
  for (int32_t i = 0; i < nthreads; i++) {
    targs[i].start_off = (uint32_t)i * tchunk;
    targs[i].end_off = (uint32_t)(i + 1) * tchunk;
    thrd_create(&tids[i], marker_worker, &targs[i]);
  }
  for (int32_t i = 0; i < nthreads; i++) {
    thrd_join(tids[i], NULL);
  }
  free(targs);

  string_arg_t *sargs = calloc((size_t)nthreads, sizeof(string_arg_t));
  for (int32_t i = 0; i < nthreads; i++) {
    sargs[i].start_off = (uint32_t)i * tchunk;
    sargs[i].end_off = (uint32_t)(i + 1) * tchunk;
    sargs[i].mapped = 0;
    thrd_create(&tids[i], string_worker, &sargs[i]);
  }
  for (int32_t i = 0; i < nthreads; i++) {
    thrd_join(tids[i], NULL);
  }

  double elapsed = timer_get_elapsed(&timer);
  fprintf(stderr, "Elapsed: %.4f s (threads=%" PRId32 ")\n", elapsed, nthreads);

  for (size_t i = 0; i < data_entry_count; i++) {
    if (data_entries[i].found) {
      printf("%s: %s\n", data_entries[i].data_name, data_entries[i].decrypted_string);
    }
  }

  free(tids);
  free(sargs);
  if (data_entries) {
    free(data_entries);
  }
  if (pe_data) {
    free(pe_data);
  }
  mtx_destroy(&entries_mtx);
  return 0;
}
