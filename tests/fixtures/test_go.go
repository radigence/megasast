package main
import "os/exec"
func main() {
    cmd := exec.Command("sh", "-c", "rm -rf /")
}
