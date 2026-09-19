// rule: megasast/go-sql-sprintf
package sample

import "fmt"

func f() {
    _ = db.Query(fmt.Sprintf("select %s", x))
}
