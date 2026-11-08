#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <unordered_map>

#include "hook_detector/core/types.h"
#include "hook_detector/core/process_target.h"

namespace hook_detector::core {

class PeImage {
public:
    PeImage(const ProcessTarget& process, uintptr_t base_address);

    bool parse();
    bool is_valid() const;

    uintptr_t get_base_address() const;
    const IMAGE_DOS_HEADER& get_dos_header() const;
    const IMAGE_NT_HEADERS64& get_nt_headers() const;
    const std::vector<IMAGE_SECTION_HEADER>& get_sections() const;

    uintptr_t rva_to_va(uint32_t rva) const;
    bool get_data_directory(uint32_t entry_index, uintptr_t& out_va, size_t& out_size) const;
    bool get_export_directory(uintptr_t& out_va, size_t& out_size) const;
    bool get_import_directory(uintptr_t& out_va, size_t& out_size) const;

    bool get_section_bounds(const std::string& section_name, uintptr_t& out_start, size_t& out_size) const;
    bool is_address_in_section(uintptr_t addr, const std::string& section_name) const;
    bool is_address_executable(uintptr_t addr) const;

private:
    const ProcessTarget& m_process;
    uintptr_t m_base_address;
    bool m_valid;
    IMAGE_DOS_HEADER m_dos_header;
    IMAGE_NT_HEADERS64 m_nt_headers;
    std::vector<IMAGE_SECTION_HEADER> m_sections;
};

using pe_image = PeImage;

class DiskPeImage {
public:
    DiskPeImage();
    ~DiskPeImage();

    DiskPeImage(const DiskPeImage&) = delete;
    DiskPeImage& operator=(const DiskPeImage&) = delete;

    DiskPeImage(DiskPeImage&& other) noexcept;
    DiskPeImage& operator=(DiskPeImage&& other) noexcept;

    bool open(const std::wstring& file_path);
    void close();
    bool is_valid() const;

    std::vector<uint8_t> read_original_bytes(uint32_t rva, size_t size) const;

private:
    HANDLE m_file_handle;
    HANDLE m_mapping_handle;
    const uint8_t* m_mapped_view;
    size_t m_file_size;
    bool m_valid;
    IMAGE_DOS_HEADER m_dos_header;
    IMAGE_NT_HEADERS64 m_nt_headers;
    std::vector<IMAGE_SECTION_HEADER> m_sections;
};

using disk_pe_image = DiskPeImage;

class DiskImageProvider {
public:
    DiskImageProvider() = default;
    ~DiskImageProvider() = default;

    DiskImageProvider(const DiskImageProvider&) = delete;
    DiskImageProvider& operator=(const DiskImageProvider&) = delete;

    std::shared_ptr<DiskPeImage> get_image(const std::wstring& file_path);
    std::vector<uint8_t> get_original_bytes(const ModuleInfo& mod, uintptr_t address, size_t size = 16);

private:
    std::unordered_map<std::wstring, std::shared_ptr<DiskPeImage>> m_cache;
};

using disk_image_provider = DiskImageProvider;

}
