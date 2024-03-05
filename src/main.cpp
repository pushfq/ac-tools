/**
 * A small program designed to make analysis of osu!auth and osu!ac a little easier.
 * - Locates detours.
 * - Remaps and unprotects osu!ac's regions.
 * - Dumps a PE image representing the mapped osu!ac.
 */

#include <Windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <print>
#include <span>
#include <string_view>
#include <vector>

// clang-format off

extern "C" {

// NOLINTNEXTLINE
NTSYSCALLAPI NTSTATUS NtCreateSection(
  [out]          PHANDLE            SectionHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
  [in, optional] PLARGE_INTEGER     MaximumSize,
  [in]           ULONG              SectionPageProtection,
  [in]           ULONG              AllocationAttributes,
  [in, optional] HANDLE             FileHandle
);

// NOLINTNEXTLINE
NTSYSAPI NTSTATUS ZwMapViewOfSection(
  [in]                HANDLE         SectionHandle,
  [in]                HANDLE         ProcessHandle,
  [in, out]           PVOID          *BaseAddress,
  [in]                ULONG_PTR      ZeroBits,
  [in]                SIZE_T         CommitSize,
  [in, out, optional] PLARGE_INTEGER SectionOffset,
  [in, out]           PSIZE_T        ViewSize,
  [in]                DWORD          InheritDisposition,
  [in]                ULONG          AllocationType,
  [in]                ULONG          Win32Protect
);

// NOLINTNEXTLINE
NTSYSAPI NTSTATUS ZwUnmapViewOfSection(
  [in]           HANDLE ProcessHandle,
  [in, optional] PVOID  BaseAddress
);

// NOLINTNEXTLINE
NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(
  [in] HANDLE ProcessHandle
);

// NOLINTNEXTLINE
NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(
  [in] HANDLE ProcessHandle
);

}

// clang-format on

namespace {

HANDLE open_process(std::wstring_view process_name) {
  constexpr auto initial_buffer_length = 1024UZ;
  constexpr auto info_length_mismatch = static_cast<NTSTATUS>(0xc0000004);

  auto system_info_buffer = std::make_unique<char[]>(initial_buffer_length);
  auto system_info_buffer_size = initial_buffer_length;

  while (true) {
    auto length = static_cast<ULONG>(system_info_buffer_size);

    if (NtQuerySystemInformation(SystemProcessInformation, system_info_buffer.get(), system_info_buffer_size, &length) != info_length_mismatch) {
      break;
    }

    system_info_buffer_size = length;
    system_info_buffer = std::make_unique<char[]>(static_cast<size_t>(length));
  }

  const auto* process = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(system_info_buffer.get());

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvoid-pointer-to-int-cast"

  while (process->NextEntryOffset != 0) {
    if (process->ImageName.Buffer != nullptr) {
      std::wstring_view name(process->ImageName.Buffer, process->ImageName.Length / 2);

      if (process_name == name)
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, reinterpret_cast<DWORD>(process->UniqueProcessId));
    }

    process = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<uintptr_t>(process) + process->NextEntryOffset);
  }

#pragma clang diagnostic pop

  return INVALID_HANDLE_VALUE;
}

std::vector<MEMORY_BASIC_INFORMATION> find_ac_regions(HANDLE process) {
  std::vector<MEMORY_BASIC_INFORMATION> result;

  result.reserve(5);

  uintptr_t lo_region = 0;
  uintptr_t hi_region = 0;

  MEMORY_BASIC_INFORMATION inf;
  for (uintptr_t i = 0; VirtualQueryEx(process, reinterpret_cast<LPVOID>(i), &inf, sizeof(inf)) != 0; i += inf.RegionSize) {
    if (inf.Type != MEM_MAPPED)
      continue;

    if (inf.Protect == PAGE_EXECUTE || inf.Protect == PAGE_EXECUTE_READWRITE) {
      result.push_back(inf);
      if (lo_region == 0) {
        lo_region = i;
      } else {
        hi_region = std::max(hi_region, i + static_cast<size_t>(inf.RegionSize));
      }
    }
  }

  std::println("Found osu!ac at {:#x}", lo_region);

  return result;
}

bool remap_ac_regions(HANDLE process, std::span<const MEMORY_BASIC_INFORMATION> regions) {
  if (!NT_SUCCESS(NtSuspendProcess(process)))
    return false;

  for (const auto& region : regions) {
    LARGE_INTEGER section_size{.QuadPart = static_cast<LONGLONG>(region.RegionSize)};

    auto* section_handle = INVALID_HANDLE_VALUE;
    auto* base_address = region.AllocationBase;
    auto section_data = std::make_unique<char[]>(region.RegionSize);
    auto bytes_read = 0UZ;

    if (!ReadProcessMemory(process, base_address, section_data.get(), region.RegionSize, nullptr)) {
      NtResumeProcess(process);
      return false;
    }

    if (!NT_SUCCESS(NtCreateSection(&section_handle, SECTION_ALL_ACCESS, 0, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0))) {
      NtResumeProcess(process);
      return false;
    }

    if (!NT_SUCCESS(ZwUnmapViewOfSection(process, base_address))) {
      NtClose(section_handle);
      NtResumeProcess(process);
      return false;
    }

    if (!NT_SUCCESS(ZwMapViewOfSection(section_handle, process, &base_address, 0, 0, 0, &bytes_read, 2, 0, PAGE_EXECUTE_READWRITE))) {
      NtClose(section_handle);
      NtResumeProcess(process);
      return false;
    }

    if (!WriteProcessMemory(process, base_address, section_data.get(), region.RegionSize, &bytes_read)) {
      NtClose(section_handle);
      NtResumeProcess(process);
      return false;
    }

    NtClose(section_handle);
  }

  return NT_SUCCESS(NtResumeProcess(process));
}

bool dump_ac_module(const std::filesystem::path& output, HANDLE process, std::span<const MEMORY_BASIC_INFORMATION> regions) {
  const auto& last_region = regions.back();
  const auto& first_region = regions.front();

  const auto image_base = reinterpret_cast<uintptr_t>(first_region.AllocationBase);
  const auto mapped_size = reinterpret_cast<uintptr_t>(last_region.AllocationBase) + last_region.RegionSize - image_base;

  auto module_buffer = std::make_unique<char[]>(mapped_size);
  if (!ReadProcessMemory(process, reinterpret_cast<LPVOID>(image_base), module_buffer.get(), mapped_size, nullptr))
    return false;

  std::ofstream fs(output, std::ios::binary);

  if (!fs.is_open())
    return false;

  IMAGE_DOS_HEADER dos_header = {};
  IMAGE_NT_HEADERS32 nt_headers = {};

  dos_header.e_magic = IMAGE_DOS_SIGNATURE;
  dos_header.e_lfanew = sizeof(IMAGE_DOS_HEADER);

  nt_headers.Signature = IMAGE_NT_SIGNATURE;
  nt_headers.FileHeader.Characteristics = IMAGE_FILE_DLL;
  nt_headers.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt_headers.FileHeader.SizeOfOptionalHeader = sizeof(nt_headers.OptionalHeader);
  nt_headers.FileHeader.NumberOfSections = static_cast<WORD>(regions.size());
  nt_headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt_headers.OptionalHeader.ImageBase = static_cast<DWORD>(image_base);
  nt_headers.OptionalHeader.SizeOfImage = mapped_size;

  fs.write(reinterpret_cast<const char*>(&dos_header), sizeof(dos_header));
  fs.seekp(dos_header.e_lfanew);
  fs.write(reinterpret_cast<const char*>(&nt_headers), sizeof(nt_headers));

  const auto section_data_start = static_cast<uintptr_t>(fs.tellp()) + regions.size() * sizeof(IMAGE_SECTION_HEADER);

  for (size_t i = 0; i < regions.size(); ++i) {
    const auto& region = regions[i];
    const auto name = std::format("pushfq{}", i);
    const auto base = reinterpret_cast<uintptr_t>(region.AllocationBase);

    IMAGE_SECTION_HEADER header = {};

    std::memcpy(header.Name, name.data(), name.size());

    switch (region.Protect) {
      case PAGE_EXECUTE:
        header.Characteristics = IMAGE_SCN_MEM_EXECUTE;
        break;
      case PAGE_EXECUTE_READWRITE:
        header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        break;
      default:
        break;
    }

    header.VirtualAddress = base - image_base;
    header.PointerToRawData = section_data_start + base - image_base;
    header.SizeOfRawData = region.RegionSize;
    header.Misc.VirtualSize = header.SizeOfRawData;

    fs.write(reinterpret_cast<const char*>(&header), sizeof(header));

    const auto next_header = fs.tellp();

    fs.seekp(header.PointerToRawData);
    fs.write(module_buffer.get() + base - image_base, static_cast<std::streamsize>(region.RegionSize));
    fs.seekp(next_header);
  }

  return true;
}

void discover_detours(HANDLE process) {
  constexpr uint32_t detours_signature = 'Rrtd';

  MEMORY_BASIC_INFORMATION inf;
  for (uintptr_t i = 0; VirtualQueryEx(process, reinterpret_cast<LPVOID>(i), &inf, sizeof(inf)) != 0; i += inf.RegionSize) {
    if (inf.Protect != PAGE_EXECUTE_READ)
      continue;

    uint32_t signature;

    if (!ReadProcessMemory(process, reinterpret_cast<LPVOID>(i), &signature, sizeof(signature), nullptr))
      continue;

    if (signature != detours_signature)
      continue;

    /**
     * \todo (@pushfq) Find and log trampoline addresses instead.
     */

    std::println("Found detours region at: {:#x}", i);
  }
}

}  // namespace

int main(int argc, const char* argv[]) {
  if (argc != 2) {
    std::println(stderr, "{} <output>", argv[0]);
    return EXIT_FAILURE;
  }

  auto* handle = open_process(L"osu!.exe");

  if (handle == INVALID_HANDLE_VALUE) {
    std::println(stderr, "Failed to attach to osu!");
    return EXIT_FAILURE;
  }

  discover_detours(handle);

  const auto regions = find_ac_regions(handle);

  if (!dump_ac_module(argv[1], handle, regions)) {
    std::println(stderr, "Failed to dump osu!ac!");
    CloseHandle(handle);
    return EXIT_FAILURE;
  }

  std::println("Wrote osu!ac to disk.");

  if (!remap_ac_regions(handle, regions)) {
    std::println(stderr, "Failed to remap osu!ac!");
    CloseHandle(handle);
    return EXIT_FAILURE;
  }

  std::println("Remapped protected regions.");

  CloseHandle(handle);
  return EXIT_SUCCESS;
}
