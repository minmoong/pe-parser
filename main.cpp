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

  const int VIEW_ALL_CHOICE       = 1,
            DOS_HEADER_CHOICE     = 2,
            NT_HEADER_CHOICE      = 3,
            SECTION_HEADER_CHOICE = 4,
            QUIT_CHOICE           = 5;

  int choice;

  std::cout << "---------- MENU ----------" << std::endl;
  std::cout << "1. View all" << std::endl;
  std::cout << "2. View DOS header" << std::endl;
  std::cout << "3. View NT headers" << std::endl;
  std::cout << "4. View SECTION headers" << std::endl;
  std::cout << "5. Quit" << std::endl;
  std::cout << "> ";
  std::cin >> choice;
  std::cout << std::endl;

  switch (choice)
  {
    case VIEW_ALL_CHOICE:
      pe_parser.PrintHeaders();
      break;

    case DOS_HEADER_CHOICE:
      pe_parser.PrintDOSHeader();
      break;
    
    case NT_HEADER_CHOICE:
      pe_parser.PrintNTHeader();
      break;
    
    case SECTION_HEADER_CHOICE:
      pe_parser.PrintSECTIONHeader();
      break;
    
    case QUIT_CHOICE:
      std::cout << "Bye bye!" << std::endl;
      exit(EXIT_SUCCESS);
      break;
    
    default:
      std::cout << "Menu not found" << std::endl;
      break;
  }

  return 0;

}