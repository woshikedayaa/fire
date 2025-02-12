package common

func NonNil[T comparable](v ...T) []T {
	if len(v) == 0 {
		return v
	}
	var (
		zero T
		n    = len(v)
		i    int
		j    int
	)

	for j < n {
		if v[j] != zero {
			v[i] = v[j]
			i++
		}
		j++
	}
	return v[:i]
}
