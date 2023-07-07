package utils

func GetUnique[T comparable](slice []T) []T {
	keys := make(map[T]bool)
	list := []T{}

	for _, entry := range slice {
		if _, value := keys[entry]; value {
			continue
		}
		keys[entry] = true
		list = append(list, entry)
	}

	return list
}

func Reverse[S ~[]E, E any](s S)  {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }
}

func Index[E comparable](s []E, v E) int {
    for i, vs := range s {
        if v == vs {
            return i
        }
    }
    return -1
}

func Keys[K comparable, V any](m map[K]V) []K {
    keys := make([]K, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}
