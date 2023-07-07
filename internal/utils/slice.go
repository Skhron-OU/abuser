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
