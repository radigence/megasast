// rule: megasast/go-exec-cmd
package sample

import "os/exec"

func f() {
    _ = exec.Command("/bin/ls", "-l")
}
