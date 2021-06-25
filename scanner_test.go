package sscan

import (
	"testing"
)

func TestScanner(t *testing.T) {
	//scan()
}

func TestSubnet(t *testing.T) {
	info, err := networkInfo()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NET: %+v\n", info)
}

func TestUlimit(t *testing.T) {
	limit := Ulimit()
	if limit < 0 {
		t.Fatal("ulmit unknown")
	}
	t.Logf("ulimit: %d\n", limit)
}
