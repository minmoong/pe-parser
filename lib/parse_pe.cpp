#include <iostream>
#include <iomanip>
#include "../include/parse_pe.h"

const int kColumnWidth = 30;

PEParser::PEParser(std::FILE *file) {

  p_file = file;

  /* 아키텍쳐를 추출하는 작업입니다. */
  DWORD e_lfanew;
  fseek(p_file, sizeof(IMAGE_DOS_HEADER) - 4, SEEK_SET);
  fread(&e_lfanew, 4, 1, p_file);

  WORD magic;
  fseek(p_file, e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), SEEK_SET);
  fread(&magic, 2, 1, p_file);

  arch = magic == 0x10b ? "x32" : "x64";

  ParseHeaders();

}

void PEParser::ParseHeaders() {

  ParseDOSHeader();
  ParseNTHeader();
  ParseSECTIONHeader();

}

void PEParser::PrintHeaders() {

  PrintDOSHeader();
  PrintNTHeader();
  PrintSECTIONHeader();

}


/* 파싱 함수들 */
void PEParser::ParseDOSHeader() {

  fseek(p_file, 0, SEEK_SET);
  fread(&DOS_header, sizeof(IMAGE_DOS_HEADER), 1, p_file);

}

void PEParser::ParseNTHeader() {

  if (arch == "x32") {

    fseek(p_file, DOS_header.e_lfanew, SEEK_SET);
    fread(&NT_headers32, sizeof(IMAGE_NT_HEADERS32), 1, p_file);

  } else if (arch == "x64") {

    fseek(p_file, DOS_header.e_lfanew, SEEK_SET);
    fread(&NT_headers64, sizeof(IMAGE_NT_HEADERS64), 1, p_file);

  }

}

void PEParser::ParseSECTIONHeader() {

  ULONGLONG offset {DOS_header.e_lfanew + (arch == "x32" ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64))};
  number_of_sections = arch == "x32" ? NT_headers32.FileHeader.NumberOfSections
                                          : NT_headers64.FileHeader.NumberOfSections;

  p_SECTION_headers = new IMAGE_SECTION_HEADER[number_of_sections];

  for (int i {}; i < number_of_sections; ++i) {
    fseek(p_file, offset + sizeof(IMAGE_SECTION_HEADER)*i, SEEK_SET);
    fread(&p_SECTION_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, p_file);
  }

}


/* 프린트 함수들 */
void PEParser::PrintDOSHeader() {
  
  std::cout << "\033[1;34m" << "[IMAGE_DOS_HEADER]" << "\033[0m" << std::endl;
  std::cout << std::left;
  std::cout << std::uppercase << std::hex;
  std::cout << std::setw(kColumnWidth) << "e_magic" << "0x" << DOS_header.e_magic << std::endl;
  std::cout << std::setw(kColumnWidth) << "e_lfanew" << "0x" << DOS_header.e_lfanew << std::endl;
  std::cout << std::endl << std::endl;

}

void PEParser::PrintNTHeader() {
  
  if (arch == "x32") {

    std::cout << "\033[1;34m" << "[IMAGE_NT_HEADERS]" << "\033[0m" << std::endl;
    std::cout << std::left;
    std::cout << std::uppercase << std::hex;
    std::cout << std::setw(kColumnWidth) << "Signature" << "0x" << NT_headers32.Signature << std::endl;
    std::cout << std::endl << std::endl;
    
    std::cout << "\033[1;34m" << "[IMAGE_NT_HEADERS - IMAGE_FILE_HEADER]" << "\033[0m" << std::endl;
    std::cout << std::setw(kColumnWidth) << "Machine" << "0x" << NT_headers32.FileHeader.Machine << std::endl;
    std::cout << std::setw(kColumnWidth) << "NumberOfSections" << "0x" << NT_headers32.FileHeader.NumberOfSections << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfOptionalHeader" << "0x" << NT_headers32.FileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << std::setw(kColumnWidth) << "Characteristics" << "0x" << NT_headers32.FileHeader.Characteristics << std::endl;
    std::cout << std::endl << std::endl;

    std::cout << "\033[1;34m" << "[IMAGE_NT_HEADERS - IMAGE_OPTIONAL_HEADER32]" << "\033[0m" << std::endl;
    std::cout << std::setw(kColumnWidth) << "Magic" << "0x" << NT_headers32.OptionalHeader.Magic << std::endl;
    std::cout << std::setw(kColumnWidth) << "AddressOfEntryPoint" << "0x" << NT_headers32.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << std::setw(kColumnWidth) << "ImageBase" << "0x" << NT_headers32.OptionalHeader.ImageBase << std::endl;
    std::cout << std::setw(kColumnWidth) << "SectionAlignment" << "0x" << NT_headers32.OptionalHeader.SectionAlignment << std::endl;
    std::cout << std::setw(kColumnWidth) << "FileAlignment" << "0x" << NT_headers32.OptionalHeader.FileAlignment << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfImage" << "0x" << NT_headers32.OptionalHeader.SizeOfImage << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfHeaders" << "0x" << NT_headers32.OptionalHeader.SizeOfHeaders << std::endl;
    std::cout << std::setw(kColumnWidth) << "Subsystem" << "0x" << NT_headers32.OptionalHeader.Subsystem << std::endl;
    std::cout << std::setw(kColumnWidth) << "NumberOfRvaAndSizes" << "0x" << NT_headers32.OptionalHeader.NumberOfRvaAndSizes << std::endl;
    std::cout << std::setw(kColumnWidth) << "RVA of IMPORT Directory" << "0x" << NT_headers32.OptionalHeader.DataDirectory[1].VirtualAddress << std::endl;
    std::cout << std::setw(kColumnWidth) << "size of IMPORT Directory" << "0x" << NT_headers32.OptionalHeader.DataDirectory[1].Size << std::endl;
    std::cout << std::endl << std::endl;
  
  } else if (arch == "x64") {

    std::cout << "\033[1;34m" << "[IMAGE_NT_HEADERS]" << "\033[0m" << std::endl;
    std::cout << std::left;
    std::cout << std::uppercase << std::hex;
    std::cout << std::setw(kColumnWidth) << "Signature" << "0x" << NT_headers64.Signature << std::endl;
    std::cout << std::endl << std::endl;
    
    std::cout << "\033[1;34m" << "[IMAGE_NT_HEADERS - IMAGE_FILE_HEADER]" << "\033[0m" << std::endl;
    std::cout << std::setw(kColumnWidth) << "Machine" << "0x" << NT_headers64.FileHeader.Machine << std::endl;
    std::cout << std::setw(kColumnWidth) << "NumberOfSections" << "0x" << NT_headers64.FileHeader.NumberOfSections << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfOptionalHeader" << "0x" << NT_headers64.FileHeader.SizeOfOptionalHeader << std::endl;
    std::cout << std::setw(kColumnWidth) << "Characteristics" << "0x" << NT_headers64.FileHeader.Characteristics << std::endl;
    std::cout << std::endl << std::endl;

    std::cout << "\033[1;34m" << "[IMAGE_NT_HEADERS - IMAGE_OPTIONAL_HEADER64]" << "\033[0m" << std::endl;
    std::cout << std::setw(kColumnWidth) << "Magic" << "0x" << NT_headers64.OptionalHeader.Magic << std::endl;
    std::cout << std::setw(kColumnWidth) << "AddressOfEntryPoint" << "0x" << NT_headers64.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << std::setw(kColumnWidth) << "ImageBase" << "0x" << NT_headers64.OptionalHeader.ImageBase << std::endl;
    std::cout << std::setw(kColumnWidth) << "SectionAlignment" << "0x" << NT_headers64.OptionalHeader.SectionAlignment << std::endl;
    std::cout << std::setw(kColumnWidth) << "FileAlignment" << "0x" << NT_headers64.OptionalHeader.FileAlignment << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfImage" << "0x" << NT_headers64.OptionalHeader.SizeOfImage << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfHeaders" << "0x" << NT_headers64.OptionalHeader.SizeOfHeaders << std::endl;
    std::cout << std::setw(kColumnWidth) << "Subsystem" << "0x" << NT_headers64.OptionalHeader.Subsystem << std::endl;
    std::cout << std::setw(kColumnWidth) << "NumberOfRvaAndSizes" << "0x" << NT_headers64.OptionalHeader.NumberOfRvaAndSizes << std::endl;
    std::cout << std::setw(kColumnWidth) << "RVA of IMPORT Directory" << "0x" << NT_headers64.OptionalHeader.DataDirectory[1].VirtualAddress << std::endl;
    std::cout << std::setw(kColumnWidth) << "size of IMPORT Directory" << "0x" << NT_headers64.OptionalHeader.DataDirectory[1].Size << std::endl;
    std::cout << std::endl << std::endl;

  }

}

void PEParser::PrintSECTIONHeader() {

  std::cout << "\033[1;34m" << "[IMAGE_SECTION_HEADER]" << "\033[0m" << std::endl;
  std::cout << std::left;
  std::cout << std::uppercase << std::hex;
  
  for (int i {}; i < number_of_sections; ++i) {
    
    std::cout << std::setw(kColumnWidth) << "Name" << p_SECTION_headers[i].Name << std::endl;
    std::cout << std::setw(kColumnWidth) << "VirtualSize" << "0x" << p_SECTION_headers[i].Misc.VirtualSize << std::endl;
    std::cout << std::setw(kColumnWidth) << "VirtualAddress" << "0x" << p_SECTION_headers[i].VirtualAddress << std::endl;
    std::cout << std::setw(kColumnWidth) << "SizeOfRawData" << "0x" << p_SECTION_headers[i].SizeOfRawData << std::endl;
    std::cout << std::setw(kColumnWidth) << "PointerToRawData" << "0x" << p_SECTION_headers[i].PointerToRawData << std::endl;
    std::cout << std::setw(kColumnWidth) << "Characteristics" << "0x" << p_SECTION_headers[i].Characteristics << std::endl;
    std::cout << std::endl;

  }

}