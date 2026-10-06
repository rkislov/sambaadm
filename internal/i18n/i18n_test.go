package i18n

import "testing"

func TestT(t *testing.T) {
	if T(RU, "nav.users") != "Пользователи" {
		t.Fatal("ru")
	}
	if T(EN, "nav.users") != "Users" {
		t.Fatal("en")
	}
	if Normalize("en-US") != EN {
		t.Fatal("normalize")
	}
}
