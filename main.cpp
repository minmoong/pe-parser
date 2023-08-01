#include <iostream>
#include "include/utils.h"
#include "include/parse_pe.h"

int main(int argc, char *argv[]) {

  /* 파일 매개변수가 주어지지 않았다면 종료합니다. */
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " [path to file]" << std::endl;
    exit(EXIT_FAILURE);
  }

  std::FILE *p_file;
  fopen_s(&p_file, argv[1], "rb");

  /* 파일 오픈에 실패하면 종료합니다. */
  if (p_file == NULL) {
    std::cerr << "Unable to open file: " << argv[1] << std::endl;
    exit(EXIT_FAILURE);
  }

  PrintTitle();
  
  PEParser pe_parser(p_file);

  pe_parser.PrintHeaders();

  return 0;

}