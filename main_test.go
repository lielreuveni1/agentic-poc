package main

import "testing"

func TestEnvOr(t *testing.T) {
	t.Setenv("OX_TEST_VAR", "set")
	if envOr("OX_TEST_VAR", "default") != "set" {
		t.Error("set variable ignored")
	}
	t.Setenv("OX_TEST_VAR", "")
	if envOr("OX_TEST_VAR", "default") != "default" {
		t.Error("empty variable should fall back to the default")
	}
}
