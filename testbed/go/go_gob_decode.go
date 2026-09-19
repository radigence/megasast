// rule: megasast/go-gob-decode
package sample

import "encoding/gob"

func f() {
    _ = gob.NewDecoder(r).Decode(&v)
}
