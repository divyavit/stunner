package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// An explicit "none" turns off STUN/TURN authentication entirely (a pure STUN server) and is set
// deliberately by downstream tooling: Validate must keep it and may default only an empty type.
// Coercing "none" to any other type breaks deployed configs.
func TestAuthConfigNoneStaysNone(t *testing.T) {
	a := AuthConfig{Type: "none"}
	assert.NoError(t, a.Validate(), "explicit none validates without credentials")
	assert.Equal(t, "none", a.Type, "explicit none is never defaulted")

	d := AuthConfig{}
	err := d.Validate()
	assert.Error(t, err, "an empty type defaults to static, which demands credentials")
	assert.Equal(t, "static", d.Type, "only an empty type is defaulted")
}
