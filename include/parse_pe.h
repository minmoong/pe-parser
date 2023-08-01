#ifndef PARSE_PE_H
#define PARSE_PE_H

#include "../include/winntdef.h"

class PEParser {
  public:
    PEParser(std::FILE *file);

    void PrintHeaders();

  private:
    std::FILE*                p_file;
    std::string               arch;
    IMAGE_DOS_HEADER          DOS_header       {0, };
    IMAGE_NT_HEADERS32        NT_headers32     {0, };
    IMAGE_NT_HEADERS64        NT_headers64     {0, };

    void ParseHeaders();
    
    void ParseDOSHeader();
    void ParseNTHeader();

    void PrintDOSHeader();
    void PrintNTHeader();
};

#endif