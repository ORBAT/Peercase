package auth

type CA interface {
	Sign(Certificate) Certificate
}
