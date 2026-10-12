//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The OpenMCX startup banner, printed by every long-running OpenMCX program (OpenMCX, no 3GPP specification).
package common

import (
	"fmt"
	"os"
)

// ------------------------------------------------------------------------------
// PrintBanner writes the OpenMCX banner naming the program on stderr, as the C++ programs do
// (include/mcx/banner.hpp); stdout stays free for the program's output.
func PrintBanner(program string) {
	fmt.Fprint(os.Stderr, `
  ___                   __  __  ______  __
 / _ \ _ __   ___ _ __ |  \/  |/ ___\ \/ /
| | | | '_ \ / _ \ '_ \| |\/| | |    \  /
| |_| | |_) |  __/ | | | |  | | |___ /  \
 \___/| .__/ \___|_| |_|_|  |_|\____/_/\_\
      |_|
`)
	fmt.Fprintf(os.Stderr, "  3GPP Release 19 %s - MCX Services\n\n", program)
}
