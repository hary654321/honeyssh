package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"josephlewis.net/osshit/core/vos/vostest"
)

func TestEnv(t *testing.T) {
	cases := goldenTestSuite{
		"no-arg": {[]string{"env"}},
		"help":   {[]string{"env", "--help"}},
	}

	cases.Run(t, Cat)
}

func TestEnv_contents(t *testing.T) {
	cmd := vostest.Command(Env, "env")
	cmd.VOS.Setenv("C", "charlie")
	cmd.VOS.Setenv("A", "alpha")
	cmd.VOS.Setenv("B", "bravo")

	out, err := cmd.CombinedOutput()

	assert.Equal(t, 0, cmd.ExitStatus, "exit code")
	assert.Nil(t, err)
	assert.Equal(t, "A=alpha\nB=bravo\nC=charlie\n", string(out))
}
