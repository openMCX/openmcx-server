// The openMCX startup banner, printed by every long-running openMCX program (openMCX, no 3GPP specification).
package common

import (
	"fmt"
	"os"
)

// ------------------------------------------------------------------------------
// PrintBanner writes the openMCX banner naming the program on stderr, as the C++ programs do
// (include/mcx/banner.hpp); stdout stays free for the program's output.
func PrintBanner(program string) {
	fmt.Fprint(os.Stderr, `
                            __  __   ____ __  __
  ___   _ __    ___  _ __  |  \/  | / ___|\ \/ /
 / _ \ | '_ \  / _ \| '_ \ | |\/| || |     \  /
| (_) || |_) ||  __/| | | || |  | || |___  /  \
 \___/ | .__/  \___||_| |_||_|  |_| \____|/_/\_\
       |_|
`)
	fmt.Fprintf(os.Stderr, "  3GPP Release 19 %s - MCX Services\n\n", program)
}
