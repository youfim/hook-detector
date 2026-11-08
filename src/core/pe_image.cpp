#include <cstring>
#include <algorithm>
#include <utility>

#include "hook_detector/core/pe_image.h"

namespace hook_detector::core {

PeImage::PeImage(const ProcessTarget& process, uintptr_t base_address)
    : m_process(process),
      m_base_address(base_address),
      m_valid(false),
      m_dos_header{},
      m_nt_headers{} {}

bool PeImage::parse() {
    m_valid = false;
    m_sections.clear();

    if (m_base_address == 0 || !m_process.is_attached()) {
        return false;
    }

    size_t bytes_read = 0;
    if (!m_process.read_memory(m_base_address, &m_dos_header, sizeof(m_dos_header), &bytes_read) ||
        bytes_read != sizeof(m_dos_header)) {
        return false;
    }

    if (m_dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (m_dos_header.e_lfanew <= 0 || m_dos_header.e_lfanew > 0x10000) {
        return false;
    }

    uintptr_t nt_headers_addr = m_base_address + static_cast<uintptr_t>(m_dos_header.e_lfanew);
    if (!m_process.read_memory(nt_headers_addr, &m_nt_headers, sizeof(m_nt_headers), &bytes_read) ||
        bytes_read != sizeof(m_nt_headers)) {
        return false;
    }

    if (m_nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    if (m_nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return false;
    }

    if (m_nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    WORD num_sections = m_nt_headers.FileHeader.NumberOfSections;
    if (num_sections == 0 || num_sections > 96) {
        return false;
    }

    uintptr_t section_headers_addr = nt_headers_addr +
                                     offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                     m_nt_headers.FileHeader.SizeOfOptionalHeader;

    m_sections.resize(num_sections);
    size_t sections_total_size = num_sections * sizeof(IMAGE_SECTION_HEADER);
    if (!m_process.read_memory(section_headers_addr, m_sections.data(), sections_total_size, &bytes_read) ||
        bytes_read != sections_total_size) {
        m_sections.clear();
        return false;
    }

    m_valid = true;
    return true;
}

bool PeImage::is_valid() const {
    return m_valid;
}

uintptr_t PeImage::get_base_address() const {
    return m_base_address;
}

const IMAGE_DOS_HEADER& PeImage::get_dos_header() const {
    return m_dos_header;
}

const IMAGE_NT_HEADERS64& PeImage::get_nt_headers() const {
    return m_nt_headers;
}

const std::vector<IMAGE_SECTION_HEADER>& PeImage::get_sections() const {
    return m_sections;
}

uintptr_t PeImage::rva_to_va(uint32_t rva) const {
    return m_base_address + static_cast<uintptr_t>(rva);
}

bool PeImage::get_data_directory(uint32_t entry_index, uintptr_t& out_va, size_t& out_size) const {
    out_va = 0;
    out_size = 0;

    if (!m_valid || entry_index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return false;
    }

    const auto& dir = m_nt_headers.OptionalHeader.DataDirectory[entry_index];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return false;
    }

    out_va = rva_to_va(dir.VirtualAddress);
    out_size = static_cast<size_t>(dir.Size);
    return true;
}

bool PeImage::get_export_directory(uintptr_t& out_va, size_t& out_size) const {
    return get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT, out_va, out_size);
}

bool PeImage::get_import_directory(uintptr_t& out_va, size_t& out_size) const {
    return get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT, out_va, out_size);
}

bool PeImage::get_section_bounds(const std::string& section_name, uintptr_t& out_start, size_t& out_size) const {
    out_start = 0;
    out_size = 0;

    if (!m_valid) {
        return false;
    }

    for (const auto& sec : m_sections) {
        char name_buf[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        std::memcpy(name_buf, sec.Name, IMAGE_SIZEOF_SHORT_NAME);
        std::string current_name(name_buf);

        if (_stricmp(current_name.c_str(), section_name.c_str()) == 0) {
            out_start = rva_to_va(sec.VirtualAddress);
            out_size = sec.Misc.VirtualSize != 0 ? static_cast<size_t>(sec.Misc.VirtualSize)
                                                 : static_cast<size_t>(sec.SizeOfRawData);
            return true;
        }
    }

    return false;
}

bool PeImage::is_address_in_section(uintptr_t addr, const std::string& section_name) const {
    uintptr_t start = 0;
    size_t size = 0;
    if (!get_section_bounds(section_name, start, size)) {
        return false;
    }

    return addr >= start && addr < (start + size);
}

bool PeImage::is_address_executable(uintptr_t addr) const {
    if (!m_valid) {
        return false;
    }

    for (const auto& sec : m_sections) {
        if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            uintptr_t start = rva_to_va(sec.VirtualAddress);
            size_t size = sec.Misc.VirtualSize != 0 ? static_cast<size_t>(sec.Misc.VirtualSize)
                                                   : static_cast<size_t>(sec.SizeOfRawData);
            if (addr >= start && addr < (start + size)) {
                return true;
            }
        }
    }

    return false;
}

DiskPeImage::DiskPeImage()
    : m_file_handle(INVALID_HANDLE_VALUE),
      m_mapping_handle(nullptr),
      m_mapped_view(nullptr),
      m_file_size(0),
      m_valid(false),
      m_dos_header{},
      m_nt_headers{} {}

DiskPeImage::~DiskPeImage() {
    close();
}

DiskPeImage::DiskPeImage(DiskPeImage&& other) noexcept
    : m_file_handle(other.m_file_handle),
      m_mapping_handle(other.m_mapping_handle),
      m_mapped_view(other.m_mapped_view),
      m_file_size(other.m_file_size),
      m_valid(other.m_valid),
      m_dos_header(other.m_dos_header),
      m_nt_headers(other.m_nt_headers),
      m_sections(std::move(other.m_sections)) {
    other.m_file_handle = INVALID_HANDLE_VALUE;
    other.m_mapping_handle = nullptr;
    other.m_mapped_view = nullptr;
    other.m_file_size = 0;
    other.m_valid = false;
}

DiskPeImage& DiskPeImage::operator=(DiskPeImage&& other) noexcept {
    if (this != &other) {
        close();
        m_file_handle = other.m_file_handle;
        m_mapping_handle = other.m_mapping_handle;
        m_mapped_view = other.m_mapped_view;
        m_file_size = other.m_file_size;
        m_valid = other.m_valid;
        m_dos_header = other.m_dos_header;
        m_nt_headers = other.m_nt_headers;
        m_sections = std::move(other.m_sections);

        other.m_file_handle = INVALID_HANDLE_VALUE;
        other.m_mapping_handle = nullptr;
        other.m_mapped_view = nullptr;
        other.m_file_size = 0;
        other.m_valid = false;
    }
    return *this;
}

bool DiskPeImage::open(const std::wstring& file_path) {
    close();

    if (file_path.empty()) {
        return false;
    }

    m_file_handle = CreateFileW(
        file_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_file_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(m_file_handle, &li) || li.QuadPart <= 0) {
        close();
        return false;
    }
    m_file_size = static_cast<size_t>(li.QuadPart);

    m_mapping_handle = CreateFileMappingW(
        m_file_handle,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );

    if (m_mapping_handle == nullptr) {
        close();
        return false;
    }

    m_mapped_view = static_cast<const uint8_t*>(MapViewOfFile(
        m_mapping_handle,
        FILE_MAP_READ,
        0,
        0,
        0
    ));

    if (m_mapped_view == nullptr) {
        close();
        return false;
    }

    if (m_file_size < sizeof(IMAGE_DOS_HEADER)) {
        close();
        return false;
    }

    std::memcpy(&m_dos_header, m_mapped_view, sizeof(IMAGE_DOS_HEADER));
    if (m_dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
        m_dos_header.e_lfanew <= 0 ||
        static_cast<size_t>(m_dos_header.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > m_file_size) {
        close();
        return false;
    }

    std::memcpy(&m_nt_headers, m_mapped_view + m_dos_header.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
    if (m_nt_headers.Signature != IMAGE_NT_SIGNATURE ||
        m_nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        m_nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        close();
        return false;
    }

    WORD num_sections = m_nt_headers.FileHeader.NumberOfSections;
    size_t section_headers_offset = static_cast<size_t>(m_dos_header.e_lfanew) +
                                    offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                                    m_nt_headers.FileHeader.SizeOfOptionalHeader;

    if (section_headers_offset + num_sections * sizeof(IMAGE_SECTION_HEADER) > m_file_size) {
        close();
        return false;
    }

    m_sections.resize(num_sections);
    std::memcpy(
        m_sections.data(),
        m_mapped_view + section_headers_offset,
        num_sections * sizeof(IMAGE_SECTION_HEADER)
    );

    m_valid = true;
    return true;
}

void DiskPeImage::close() {
    if (m_mapped_view != nullptr) {
        UnmapViewOfFile(m_mapped_view);
        m_mapped_view = nullptr;
    }

    if (m_mapping_handle != nullptr) {
        CloseHandle(m_mapping_handle);
        m_mapping_handle = nullptr;
    }

    if (m_file_handle != INVALID_HANDLE_VALUE && m_file_handle != nullptr) {
        CloseHandle(m_file_handle);
        m_file_handle = INVALID_HANDLE_VALUE;
    }

    m_file_size = 0;
    m_valid = false;
    m_sections.clear();
}

bool DiskPeImage::is_valid() const {
    return m_valid;
}

std::vector<uint8_t> DiskPeImage::read_original_bytes(uint32_t rva, size_t size) const {
    std::vector<uint8_t> result;
    if (!m_valid || m_mapped_view == nullptr || size == 0) {
        return result;
    }

    for (const auto& sec : m_sections) {
        uint32_t sec_va = sec.VirtualAddress;
        uint32_t sec_size = sec.Misc.VirtualSize != 0 ? sec.Misc.VirtualSize : sec.SizeOfRawData;

        if (rva >= sec_va && rva < sec_va + sec_size) {
            uint32_t sec_offset = rva - sec_va;
            if (sec_offset >= sec.SizeOfRawData) {
                return result;
            }

            uint32_t file_offset = sec.PointerToRawData + sec_offset;
            size_t available_bytes = sec.SizeOfRawData > sec_offset ? (sec.SizeOfRawData - sec_offset) : 0;
            size_t bytes_to_copy = std::min(size, available_bytes);

            if (file_offset + bytes_to_copy > m_file_size) {
                bytes_to_copy = m_file_size > file_offset ? (m_file_size - file_offset) : 0;
            }

            if (bytes_to_copy > 0) {
                result.resize(bytes_to_copy);
                std::memcpy(result.data(), m_mapped_view + file_offset, bytes_to_copy);
            }
            return result;
        }
    }

    return result;
}

std::shared_ptr<DiskPeImage> DiskImageProvider::get_image(const std::wstring& file_path) {
    if (file_path.empty()) {
        return nullptr;
    }

    auto it = m_cache.find(file_path);
    if (it != m_cache.end()) {
        return it->second;
    }

    auto img = std::make_shared<DiskPeImage>();
    if (img->open(file_path)) {
        m_cache[file_path] = img;
        return img;
    }

    m_cache[file_path] = nullptr;
    return nullptr;
}

std::vector<uint8_t> DiskImageProvider::get_original_bytes(const ModuleInfo& mod, uintptr_t address, size_t size) {
    if (!mod.contains_address(address) || mod.full_path.empty() || size == 0) {
        return {};
    }

    auto img = get_image(mod.full_path);
    if (!img || !img->is_valid()) {
        return {};
    }

    uint32_t rva = static_cast<uint32_t>(address - mod.base_address);
    return img->read_original_bytes(rva, size);
}

}
