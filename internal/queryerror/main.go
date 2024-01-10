package queryerror

import "errors"

var ErrBogonResource = errors.New("the referred resource is a bogon")
