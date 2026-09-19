// rule: megasast/go-insecure-skip-verify
package sample

import "crypto/tls"

var _ = &tls.Config{InsecureSkipVerify: true}
