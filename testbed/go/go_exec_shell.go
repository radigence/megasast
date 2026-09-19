// rule: megasast/go-exec-shell (+ megasast/go-exec-cmd)
package sample

import "os/exec"

func f() {
    _ = exec.Command("sh", "-c", cmd)
}
