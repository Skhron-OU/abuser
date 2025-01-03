package utils

import "golang.org/x/exp/constraints"

type Number interface {
	constraints.Integer | constraints.Float
}

func Sum[T Number](nums ...T) T {
	var total T = 0

	for _, num := range nums {
		total += num
	}

	return total
}
