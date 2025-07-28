[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-2e0aaae1b6195c2367325f4f02e2d04e9abb55f0b24a779b69b11b9e10269abc.svg)](https://classroom.github.com/online_ide?assignment_repo_id=19434679&assignment_repo_type=AssignmentRepo)

In order to get this project working after checking it out of the library, several steps need to be taken:

- change the value of SIGSTKSZ to a real value in the doctest.cpp file (maybe 16385)
- do an explicit include of the repl_driver.cxx in both the pkg\cloud.cxx and pkg\agent.cxx
- install the libcrypto++ library
- change the byte namespace to CryptoPP if necessary

Make sure you're using a linux or Mac so that you can use the curses or ncurses library, as the pdcurses is not sufficient on Windows. 