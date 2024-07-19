package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()

	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	fmt.Println("privateKey :", privKey.Bytes())
	fmt.Println("publicKey :", privKey.Public().key)
}
