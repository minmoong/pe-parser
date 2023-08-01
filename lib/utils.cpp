#include <iostream>

void PrintTitle() {
  
  std::string title {
    "                                                                                \n"
    "                                                                                \n"
    "       ██████  ███████     ██    ██ ██ ███████ ██     ██ ███████ ██████         \n"
    "       ██   ██ ██          ██    ██ ██ ██      ██     ██ ██      ██   ██        \n"
    "       ██████  █████       ██    ██ ██ █████   ██  █  ██ █████   ██████         \n"
    "       ██      ██           ██  ██  ██ ██      ██ ███ ██ ██      ██   ██        \n"
    "       ██      ███████       ████   ██ ███████  ███ ███  ███████ ██   ██        \n"
    "                                                                                \n"
    "                                 BY HACKSSERT                                   \n\n"
  };

  std::system("chcp 65001");
  std::system("cls");

  std::cout << title << std::endl;
  std::cout << "(주의) PE 파일의 일부 정보만 추출합니다.\n\n" << std::endl;
  
}