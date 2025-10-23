package cmd

import (
	"log/slog"
	"os"
	"testing"

	"github.com/VITObelgium/fakes3pp/logging"
)

func initializeTestLogging() {
	logging.InitializeLogging(slog.LevelError, nil, nil)
}

// utility function to not run a test if there are no testing backends in the build environment.
func skipIfNoTestingBackends(t testing.TB) {
	if os.Getenv("NO_TESTING_BACKENDS") != "" {
		t.Skip("Skipping this test because no testing backends and that is a dependency for thist test.")
	}
}

func fixture_with_environment_values(tb testing.TB, new_env map[string]string) (tearDown func()) {
	old_env_variables := map[string]string{}

	for new_env_key, new_env_value := range new_env {
		old_value, old_value_exists := os.LookupEnv(new_env_key)
		if old_value_exists {
			old_env_variables[new_env_key] = old_value
		}
		err := os.Setenv(new_env_key, new_env_value)
		if err != nil {
			tb.Errorf("Issue environment fixture when setting %s=%s got %s", new_env_key, new_env_value, err)
			tb.FailNow()
		}
	}

	tearDown = func() {
		for new_env_key, new_env_value := range new_env {
			old_value, old_value_exists := old_env_variables[new_env_key]
			if old_value_exists {
				err := os.Setenv(new_env_key, old_value)
				if err != nil {
					tb.Errorf("Issue environment fixture when setting %s=%s got %s", new_env_key, new_env_value, err)
					tb.FailNow()
				}
			} else {
				err := os.Unsetenv(new_env_key)
				if err != nil {
					tb.Errorf("Issue environment fixture when unsetting %s=%s got %s", new_env_key, new_env_value, err)
					tb.FailNow()
				}
			}

		}
	}
	return tearDown
}
