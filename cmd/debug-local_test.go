package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/VITObelgium/fakes3pp/logging"
	"github.com/VITObelgium/fakes3pp/server"
)


//This is a dummy test that can be used to spawn a server with a local config
//Just set DEBUG_LOCAL_TEST to a directory that has a fakes3pp.env file and all the other
//required config that you reference in that env file. Then if you debug this test you have a server
//running with the debugger attached.
func TestRunLocalDebugEndpoint(t *testing.T) {
	if os.Getenv("DEBUG_LOCAL_TEST") == "" {
		t.Skip("Skipping this test because DEBUG_LOCAL_TEST is empty.")
	}
	
	testDir := os.Getenv("DEBUG_LOCAL_TEST")
	envFiles = fmt.Sprintf("%s/fakes3pp.env", testDir)
	loadEnvVarsFromDotEnv()
	initConfig()
	logging.InitializeLogging(slog.LevelDebug, nil, nil)

	server.CreateAndStartSync(buildS3Server(), getServerOptsFromViper())
	
}